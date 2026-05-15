"""GatewayGuard relay-only server.

This service is intended for a public/intermediate server. It does not run the
GatewayGuard detector, does not store a database, and does not need vehicle
network access. It only accepts Android/car-side batches and broadcasts them to
Windows/browser subscribers.

Run:
    uvicorn relay_server:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import json
import os
import time
from collections import deque
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


INGEST_API_KEY = os.getenv("GATEWAY_GUARD_INGEST_KEY", "")
MAX_RECENT_PACKETS = int(os.getenv("GATEWAY_GUARD_RELAY_PACKET_CACHE", "500"))


class MobilePacket(BaseModel):
    timestamp: float
    protocol: str
    source: str = ""
    destination: str = ""
    msg_id: str = ""
    payload_hex: str = ""
    payload_decoded: dict[str, Any] = Field(default_factory=dict)
    domain: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class MobileAlert(BaseModel):
    timestamp: float
    anomaly_type: str
    severity: str = "medium"
    confidence: float = 0.0
    protocol: str = ""
    source_node: str = ""
    target_node: str = ""
    description: str = ""
    detection_method: str = "android_remote"
    event_id: Optional[str] = None
    packet_count: int = 1
    vehicle_profile: Optional[str] = None
    evidence: list[Any] = Field(default_factory=list)


class MobileIngestRequest(BaseModel):
    device_id: str = "android-gateway"
    device_name: str = "Android Gateway"
    source: str = "android"
    sent_at: Optional[float] = None
    stats: dict[str, Any] = Field(default_factory=dict)
    packets: list[MobilePacket] = Field(default_factory=list)
    alerts: list[MobileAlert] = Field(default_factory=list)


app = FastAPI(
    title="GatewayGuard Relay",
    description="Relay-only GatewayGuard transport server",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

recent_packets: deque[dict[str, Any]] = deque(maxlen=MAX_RECENT_PACKETS)
recent_alerts: deque[dict[str, Any]] = deque(maxlen=200)
connections: set[WebSocket] = set()
relay_state: dict[str, Any] = {
    "device_id": "",
    "device_name": "",
    "received_at": None,
    "total_received": 0,
    "last_batch_packets": 0,
    "last_batch_alerts": 0,
}
protocol_counts: dict[str, int] = {"CAN": 0, "ETH": 0, "V2X": 0}


def _dump_model(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _dump_models(models: list[Any]) -> list[dict[str, Any]]:
    return [_dump_model(model) for model in models]


def _require_key(
    x_gatewayguard_key: Optional[str] = Header(None, alias="X-GatewayGuard-Key"),
    api_key: Optional[str] = Query(None),
) -> None:
    if not INGEST_API_KEY:
        return
    if (x_gatewayguard_key or api_key or "") != INGEST_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid GatewayGuard relay key")


def _packet_attack_type(payload_decoded: object, metadata: object) -> Optional[str]:
    if isinstance(payload_decoded, dict):
        attack = payload_decoded.get("attack")
        if attack:
            return str(attack)
    if isinstance(metadata, dict) and metadata.get("attack"):
        return "simulated_attack"
    return None


def _packet_stream_rows(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    latest = sorted(
        packets,
        key=lambda packet: float(packet.get("timestamp") or 0.0),
        reverse=True,
    )[:50]
    for packet in latest:
        payload_decoded = packet.get("payload_decoded") or {}
        metadata = packet.get("metadata") or {}
        attack_type = _packet_attack_type(payload_decoded, metadata)
        rows.append(
            {
                "timestamp": packet.get("timestamp"),
                "protocol": str(packet.get("protocol") or "").upper(),
                "source": packet.get("source") or "",
                "destination": packet.get("destination") or "",
                "msg_id": packet.get("msg_id") or "",
                "domain": packet.get("domain") or "",
                "payload_decoded": payload_decoded,
                "attack_type": attack_type,
                "is_attack": bool(attack_type),
            }
        )
    return rows


def _stats() -> dict[str, Any]:
    timestamps = [
        float(packet.get("timestamp") or 0.0)
        for packet in recent_packets
        if packet.get("timestamp") is not None
    ]
    ts_min = min(timestamps) if timestamps else None
    ts_max = max(timestamps) if timestamps else None
    pps = 0.0
    if ts_min is not None and ts_max is not None and ts_max > ts_min:
        pps = relay_state["total_received"] / (ts_max - ts_min)

    return {
        "total_packets": relay_state["total_received"],
        "can_count": protocol_counts.get("CAN", 0),
        "eth_count": protocol_counts.get("ETH", 0),
        "v2x_count": protocol_counts.get("V2X", 0),
        "time_range_start": ts_min,
        "time_range_end": ts_max,
        "packets_per_second": round(pps, 2),
    }


async def _broadcast(message: dict[str, Any]) -> None:
    if not connections:
        return
    payload = json.dumps(message, ensure_ascii=False, default=str)
    dead = []
    for websocket in connections:
        try:
            await websocket.send_text(payload)
        except Exception:
            dead.append(websocket)
    for websocket in dead:
        connections.discard(websocket)


@app.get("/")
async def root():
    return {
        "name": "GatewayGuard Relay",
        "mode": "relay-only",
        "version": "0.1.0",
    }


@app.get("/health/live")
async def health_live():
    return {"status": "alive", "mode": "relay-only"}


@app.get("/health/ready")
async def health_ready():
    return {
        "status": "ready",
        "mode": "relay-only",
        "active_ws": len(connections),
        **relay_state,
    }


@app.get("/api/mobile/status")
async def mobile_status():
    return dict(relay_state)


@app.post("/api/mobile/ingest")
async def ingest_mobile_data(
    payload: MobileIngestRequest,
    _: None = Depends(_require_key),
):
    return await _ingest(payload)


async def _ingest(payload: MobileIngestRequest) -> dict[str, Any]:
    packet_rows = _dump_models(payload.packets)
    alert_rows = _dump_models(payload.alerts)
    received_at = time.time()

    for packet in packet_rows:
        protocol = str(packet.get("protocol") or "").upper()
        packet["protocol"] = protocol
        packet.setdefault("metadata", {})
        packet["metadata"] = dict(packet["metadata"] or {})
        packet["metadata"]["relay_received_at"] = received_at
        packet["metadata"]["relay_device_id"] = payload.device_id
        packet["metadata"]["relay_device_name"] = payload.device_name
        recent_packets.append(packet)
        if protocol in protocol_counts:
            protocol_counts[protocol] += 1

    for alert in alert_rows:
        recent_alerts.append(alert)

    relay_state.update(
        {
            "device_id": payload.device_id,
            "device_name": payload.device_name,
            "received_at": received_at,
            "total_received": relay_state["total_received"] + len(packet_rows),
            "last_batch_packets": len(packet_rows),
            "last_batch_alerts": len(alert_rows),
        }
    )

    stats = _stats()
    await _broadcast(
        {
            "type": "traffic_update",
            "data": {
                "stats": stats,
                "device_id": payload.device_id,
                "device_name": payload.device_name,
                "received_at": received_at,
                "packet_count": len(packet_rows),
            },
        }
    )
    if packet_rows:
        await _broadcast(
            {"type": "packets_update", "data": _packet_stream_rows(packet_rows)}
        )
    await _broadcast(
        {
            "type": "stats_update",
            "data": {
                "running": True,
                "source_mode": "relay_only",
                "total_collected": stats["total_packets"],
                "total_anomalies": len(recent_alerts),
                "last_remote_packets": len(packet_rows),
                "remote_device_id": payload.device_id,
                "remote_device_name": payload.device_name,
            },
        }
    )
    if alert_rows:
        await _broadcast({"type": "alerts", "data": alert_rows})
    await _broadcast(
        {
            "type": "relay_ingest",
            "data": {
                "device_id": payload.device_id,
                "device_name": payload.device_name,
                "source": payload.source,
                "sent_at": payload.sent_at,
                "received_at": received_at,
                "stats": payload.stats,
                "packets": packet_rows,
                "alerts": alert_rows,
                "detected_alerts": [],
            },
        }
    )

    return {
        "status": "accepted",
        "mode": "relay-only",
        "received": len(packet_rows),
        "remote_alerts": len(alert_rows),
        "stats": stats,
    }


@app.get("/api/traffic/stats")
async def get_traffic_stats():
    return _stats()


@app.get("/api/traffic/packets")
async def get_packets(limit: int = Query(50, le=500), offset: int = 0):
    rows = list(reversed(recent_packets))
    return _packet_stream_rows(rows[offset : offset + limit])


@app.get("/api/traffic/collect/status")
async def collect_status():
    return {
        "running": True,
        "source_mode": "relay_only",
        "total_collected": relay_state["total_received"],
        "total_anomalies": len(recent_alerts),
        "remote_device_id": relay_state["device_id"],
        "remote_device_name": relay_state["device_name"],
    }


@app.get("/api/anomaly/status")
async def anomaly_status():
    return {
        "trained": False,
        "vehicle_profile": "relay-only",
        "min_train_packets": 0,
    }


@app.get("/api/anomaly/events")
async def anomaly_events(limit: int = Query(50, le=200), offset: int = 0):
    rows = list(reversed(recent_alerts))[offset : offset + limit]
    return {"total": len(recent_alerts), "events": rows}


@app.get("/api/system/status")
async def system_status():
    return {
        "mode": "relay-only",
        "runtime": "memory",
        "active_ws": len(connections),
        "mobile": dict(relay_state),
        "stats": _stats(),
    }


@app.websocket("/ws/realtime")
async def realtime_ws(websocket: WebSocket):
    await websocket.accept()
    connections.add(websocket)
    try:
        await websocket.send_text(
            json.dumps(
                {
                    "type": "stats_update",
                    "data": {
                        "running": True,
                        "source_mode": "relay_only",
                        "total_collected": relay_state["total_received"],
                        "total_anomalies": len(recent_alerts),
                        "remote_device_id": relay_state["device_id"],
                        "remote_device_name": relay_state["device_name"],
                    },
                },
                ensure_ascii=False,
            )
        )
        if recent_packets:
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "traffic_update",
                        "data": {"stats": _stats(), **relay_state},
                    },
                    ensure_ascii=False,
                )
            )
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "packets_update",
                        "data": _packet_stream_rows(list(recent_packets)),
                    },
                    ensure_ascii=False,
                )
            )

        while True:
            try:
                raw = await websocket.receive_text()
            except WebSocketDisconnect:
                break
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    finally:
        connections.discard(websocket)
