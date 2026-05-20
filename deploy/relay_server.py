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
from collections import Counter, deque
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
relay_collect_running = True
next_alert_id = 1
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


def _record_type_for_alert(alert: dict[str, Any]) -> str:
    return (
        "aggregated_event"
        if alert.get("detection_method") == "event_aggregation"
        else "packet_alert"
    )


def _normalize_alert(alert: dict[str, Any], received_at: float) -> dict[str, Any]:
    global next_alert_id

    row = dict(alert)
    row["id"] = next_alert_id
    next_alert_id += 1
    row["timestamp"] = float(row.get("timestamp") or received_at)
    row["anomaly_type"] = str(row.get("anomaly_type") or "relay_alert")
    row["severity"] = str(row.get("severity") or "medium")
    row["confidence"] = float(row.get("confidence") or 0.0)
    row["protocol"] = str(row.get("protocol") or "")
    row["source_node"] = str(row.get("source_node") or "")
    row["target_node"] = str(row.get("target_node") or "")
    row["description"] = str(row.get("description") or "")
    row["detection_method"] = str(row.get("detection_method") or "android_remote")
    row["status"] = str(row.get("status") or "open")
    row["packet_count"] = int(row.get("packet_count") or 1)
    evidence = row.get("evidence")
    row["evidence"] = evidence if isinstance(evidence, list) else []
    row["record_type"] = _record_type_for_alert(row)
    return row


def _filter_alerts(
    rows: list[dict[str, Any]],
    severity: Optional[str] = None,
    status: Optional[str] = None,
    record_type: Optional[str] = None,
) -> list[dict[str, Any]]:
    filtered = rows
    if severity:
        filtered = [row for row in filtered if row.get("severity") == severity]
    if status:
        filtered = [row for row in filtered if (row.get("status") or "open") == status]
    if record_type:
        filtered = [
            row
            for row in filtered
            if (row.get("record_type") or _record_type_for_alert(row)) == record_type
        ]
    return filtered


def _event_response(row: dict[str, Any], include_evidence: bool = False) -> dict[str, Any]:
    response = {
        "id": row.get("id"),
        "timestamp": row.get("timestamp"),
        "anomaly_type": row.get("anomaly_type"),
        "severity": row.get("severity"),
        "confidence": row.get("confidence"),
        "protocol": row.get("protocol"),
        "source_node": row.get("source_node"),
        "target_node": row.get("target_node"),
        "description": row.get("description"),
        "detection_method": row.get("detection_method"),
        "status": row.get("status") or "open",
        "record_type": row.get("record_type") or _record_type_for_alert(row),
        "event_id": row.get("event_id"),
        "packet_count": row.get("packet_count") or 1,
        "vehicle_profile": row.get("vehicle_profile"),
    }
    if include_evidence:
        response["evidence"] = row.get("evidence") or []
    return response


def _summary_pair_rows(
    counts: Counter,
    order: Optional[list[str]] = None,
    limit: Optional[int] = None,
) -> list[dict[str, Any]]:
    pending = {name or "unknown": int(value) for name, value in counts.items() if value}
    rows: list[dict[str, Any]] = []
    if order:
        for name in order:
            value = pending.pop(name, 0)
            if value:
                rows.append({"name": name, "value": value})

    rest = sorted(pending.items(), key=lambda item: item[1], reverse=True)
    rows.extend({"name": name, "value": value} for name, value in rest)
    if limit is not None:
        return rows[:limit]
    return rows


def _minute_start(timestamp: float) -> int:
    return int(timestamp // 60) * 60


def _format_trend_bucket(timestamp: int) -> str:
    return time.strftime("%H:%M", time.localtime(timestamp))


def _risk_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    if total <= 0:
        return {"riskLabel": "CLEAR", "riskScore": 0, "riskHint": "No anomaly events"}

    severity_counts = Counter(str(row.get("severity") or "medium") for row in rows)
    weighted_score = (
        severity_counts.get("critical", 0) * 4
        + severity_counts.get("high", 0) * 3
        + severity_counts.get("medium", 0) * 2
        + severity_counts.get("low", 0)
    )
    risk_score = round((weighted_score / (total * 4)) * 100)
    if severity_counts.get("critical", 0):
        return {"riskLabel": "CRITICAL", "riskScore": risk_score, "riskHint": "Critical risk events exist"}
    if severity_counts.get("high", 0):
        return {"riskLabel": "HIGH", "riskScore": risk_score, "riskHint": "High risk events exist"}
    if severity_counts.get("medium", 0):
        return {"riskLabel": "MEDIUM", "riskScore": risk_score, "riskHint": "Medium risk events dominate"}
    return {"riskLabel": "LOW", "riskScore": risk_score, "riskHint": "Current situation is relatively stable"}


def _rebuild_packet_state() -> None:
    protocol_counts.clear()
    protocol_counts.update({"CAN": 0, "ETH": 0, "V2X": 0})
    for packet in recent_packets:
        protocol = str(packet.get("protocol") or "").upper()
        if protocol in protocol_counts:
            protocol_counts[protocol] += 1
    relay_state["total_received"] = len(recent_packets)


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


@app.get("/api/mobile/relay/status")
async def mobile_relay_status():
    return {
        "enabled": True,
        "mode": "relay-only",
        "connected": True,
        "active_ws": len(connections),
        **relay_state,
    }


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

    alert_rows = [_normalize_alert(alert, received_at) for alert in alert_rows]
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
                "running": relay_collect_running,
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


@app.post("/api/traffic/simulate")
async def simulate_traffic(
    scenario: str = Query("normal"),
    count: int = Query(100, le=1000),
):
    base_time = time.time()
    generated = []
    attack = scenario != "normal"
    for index in range(max(count, 0)):
        protocol = "CAN"
        packet = {
            "timestamp": base_time + index * 0.01,
            "protocol": protocol,
            "source": "relay-simulator",
            "destination": "gateway",
            "msg_id": f"0x{0x100 + (index % 32):03X}",
            "payload_hex": f"{index % 256:02x}00000000000000",
            "payload_decoded": {
                "scenario": scenario,
                **({"attack": scenario} if attack else {}),
            },
            "domain": "powertrain",
            "metadata": {"source": "relay_only_simulator", "attack": attack},
        }
        recent_packets.append(packet)
        generated.append(packet)
        protocol_counts[protocol] += 1

    relay_state["total_received"] += len(generated)
    relay_state["last_batch_packets"] = len(generated)
    relay_state["received_at"] = base_time

    stats = _stats()
    await _broadcast({"type": "traffic_update", "data": {"stats": stats}})
    if generated:
        await _broadcast({"type": "packets_update", "data": _packet_stream_rows(generated)})
    return {
        "generated": len(generated),
        "attack_packets": len(generated) if attack else 0,
        "scenario": scenario,
        "mode": "relay-only",
    }


@app.post("/api/traffic/collect/start")
async def start_collect(mode: Optional[str] = Query(None)):
    global relay_collect_running
    relay_collect_running = True
    return {
        "status": "started",
        "running": True,
        "source_mode": mode or "relay_only",
        "message": "Relay-only server is listening for APK sync batches",
    }


@app.post("/api/traffic/collect/stop")
async def stop_collect():
    global relay_collect_running
    relay_collect_running = False
    return {
        "status": "stopped",
        "running": False,
        "source_mode": "relay_only",
        "message": "Relay-only collection display paused; ingest endpoint remains available",
    }


@app.get("/api/traffic/collect/status")
async def collect_status():
    return {
        "running": relay_collect_running,
        "source_mode": "relay_only",
        "total_collected": relay_state["total_received"],
        "total_anomalies": len(recent_alerts),
        "remote_device_id": relay_state["device_id"],
        "remote_device_name": relay_state["device_name"],
    }


@app.post("/api/traffic/import")
async def import_file(file_path: str = Query(...)):
    return {
        "error": "Relay-only server cannot import local capture files",
        "file": file_path,
        "imported": 0,
    }


@app.get("/api/anomaly/status")
async def anomaly_status():
    return {
        "trained": True,
        "vehicle_profile": "relay-only",
        "min_train_packets": 0,
    }


@app.post("/api/anomaly/train")
async def train_detector(limit: int = Query(2000)):
    return {
        "trained": True,
        "packet_count": min(limit, len(recent_packets)),
        "vehicle_profile": "relay-only",
        "min_train_packets": 0,
        "message": "Relay-only compatibility mode does not require local training",
    }


@app.post("/api/anomaly/detect")
async def detect_anomalies(limit: int = Query(500, le=2000)):
    rows = list(reversed(recent_packets))[:limit]
    now = time.time()
    generated_alerts = []
    for packet in rows:
        payload_decoded = packet.get("payload_decoded") or {}
        metadata = packet.get("metadata") or {}
        attack_type = _packet_attack_type(payload_decoded, metadata)
        if not attack_type:
            continue
        generated_alerts.append(
            _normalize_alert(
                {
                    "timestamp": packet.get("timestamp") or now,
                    "anomaly_type": attack_type,
                    "severity": "high",
                    "confidence": 0.8,
                    "protocol": packet.get("protocol") or "",
                    "source_node": packet.get("source") or "",
                    "target_node": packet.get("destination") or "",
                    "description": f"Relay detected simulated attack packet: {attack_type}",
                    "detection_method": "relay_compat",
                    "packet_count": 1,
                    "evidence": [{"msg_id": packet.get("msg_id")}],
                },
                now,
            )
        )

    for alert in generated_alerts:
        recent_alerts.append(alert)

    if generated_alerts:
        await _broadcast({"type": "alerts", "data": generated_alerts})

    return {
        "detected": len(generated_alerts),
        "alerts": [
            {
                "anomaly_type": alert["anomaly_type"],
                "severity": alert["severity"],
                "confidence": alert["confidence"],
                "description": alert["description"],
            }
            for alert in generated_alerts
        ],
    }


@app.get("/api/anomaly/events")
async def anomaly_events(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    record_type: Optional[str] = Query(None),
    limit: int = Query(50, le=1000),
    offset: int = 0,
    include_evidence: bool = Query(False),
):
    rows = _filter_alerts(list(reversed(recent_alerts)), severity, status, record_type)
    page = rows[offset : offset + limit]
    return {
        "total": len(rows),
        "events": [_event_response(row, include_evidence) for row in page],
    }


@app.get("/api/anomaly/summary")
async def anomaly_summary(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    record_type: Optional[str] = Query(None),
    window_minutes: int = Query(60, ge=1, le=1440),
):
    rows = _filter_alerts(list(recent_alerts), severity, status, record_type)
    severity_counts = Counter(str(row.get("severity") or "medium") for row in rows)
    protocol_counts_for_alerts = Counter(str(row.get("protocol") or "unknown") for row in rows)
    status_counts = Counter(str(row.get("status") or "open") for row in rows)
    type_counts = Counter(str(row.get("anomaly_type") or "unknown") for row in rows)

    now = time.time()
    end_minute = _minute_start(now)
    start_minute = end_minute - window_minutes * 60
    buckets = {
        minute: {
            "timestamp": minute,
            "name": _format_trend_bucket(minute),
            "total": 0,
            "highRisk": 0,
        }
        for minute in range(start_minute, end_minute + 1, 60)
    }
    for row in rows:
        timestamp = float(row.get("timestamp") or 0.0)
        if timestamp < start_minute:
            continue
        bucket = buckets.get(_minute_start(timestamp))
        if not bucket:
            continue
        bucket["total"] += 1
        if row.get("severity") in {"critical", "high"}:
            bucket["highRisk"] += 1

    return {
        "total": len(rows),
        "high_risk_count": severity_counts.get("critical", 0) + severity_counts.get("high", 0),
        "open_count": status_counts.get("open", 0) + status_counts.get("investigating", 0),
        "severity": _summary_pair_rows(severity_counts, ["critical", "high", "medium", "low"]),
        "protocol": _summary_pair_rows(protocol_counts_for_alerts, ["CAN", "ETH", "V2X"]),
        "status": _summary_pair_rows(status_counts, ["open", "investigating", "resolved"]),
        "typeTop": _summary_pair_rows(type_counts, limit=5),
        "trend": list(buckets.values()),
        **_risk_summary(rows),
    }


@app.get("/api/anomaly/events/{event_id}")
async def anomaly_event_detail(event_id: int):
    for row in recent_alerts:
        if int(row.get("id") or 0) == event_id:
            detail = _event_response(row, include_evidence=True)
            detail["raw_data"] = None
            return detail
    raise HTTPException(status_code=404, detail="Event not found")


@app.get("/api/system/status")
async def system_status():
    return {
        "mode": "relay-only",
        "runtime": "memory",
        "active_ws": len(connections),
        "mobile": dict(relay_state),
        "stats": _stats(),
    }


@app.delete("/api/system/clear-data")
async def clear_all_data():
    packet_count = len(recent_packets)
    alert_count = len(recent_alerts)
    recent_packets.clear()
    recent_alerts.clear()
    _rebuild_packet_state()
    relay_state.update(
        {
            "last_batch_packets": 0,
            "last_batch_alerts": 0,
            "received_at": None,
        }
    )
    return {
        "cleared": {
            "packets": packet_count,
            "anomaly_events": alert_count,
            "analysis_reports": 0,
            "chat_history": 0,
        },
        "message": "Relay memory data cleared",
    }


@app.delete("/api/system/clear-packets")
async def clear_packets(
    protocol: Optional[str] = Query(None),
    keep_recent: Optional[int] = Query(None),
):
    before = len(recent_packets)
    rows = list(recent_packets)
    if keep_recent and keep_recent > 0:
        rows = rows[-keep_recent:]
    elif protocol:
        rows = [
            row
            for row in rows
            if str(row.get("protocol") or "").upper() != protocol.upper()
        ]
    else:
        raise HTTPException(
            status_code=400,
            detail="Specify protocol or keep_recent",
        )

    recent_packets.clear()
    recent_packets.extend(rows)
    _rebuild_packet_state()
    return {
        "deleted": before - len(recent_packets),
        "remaining": len(recent_packets),
        "message": f"Deleted {before - len(recent_packets)} traffic records",
    }


@app.delete("/api/system/clear-anomalies")
async def clear_anomalies(
    severity: Optional[str] = Query(None),
    keep_recent: Optional[int] = Query(None),
):
    before = len(recent_alerts)
    rows = list(recent_alerts)
    if keep_recent and keep_recent > 0:
        rows = rows[-keep_recent:]
    elif severity:
        rows = [
            row
            for row in rows
            if str(row.get("severity") or "") != severity
        ]
    else:
        raise HTTPException(
            status_code=400,
            detail="Specify severity or keep_recent",
        )

    recent_alerts.clear()
    recent_alerts.extend(rows)
    return {
        "deleted": before - len(recent_alerts),
        "remaining": len(recent_alerts),
        "message": f"Deleted {before - len(recent_alerts)} anomaly events",
    }


@app.post("/api/llm/analyze")
async def analyze_event(event_id: int):
    for row in recent_alerts:
        if int(row.get("id") or 0) != event_id:
            continue
        severity = str(row.get("severity") or "medium")
        return {
            "event_id": event_id,
            "analysis": {
                "summary": row.get("description") or "Relay mirrored anomaly event",
                "risk_level": severity,
                "attack_type": row.get("anomaly_type"),
                "attack_intent": "Remote vehicle-side event synchronization",
                "attack_method": row.get("detection_method"),
                "root_cause": "Generated by the APK-side detector and relayed to this server",
                "affected_scope": [
                    value
                    for value in (row.get("source_node"), row.get("target_node"))
                    if value
                ],
                "recommendations": [
                    "Review the source vehicle gateway logs",
                    "Correlate the event with recent CAN traffic",
                    "Keep the APK sync channel online for follow-up evidence",
                ],
            },
        }
    raise HTTPException(status_code=404, detail="Event not found")


@app.post("/api/llm/report")
async def generate_report(limit: int = Query(10)):
    rows = list(reversed(recent_alerts))[:limit]
    severity_counts = Counter(str(row.get("severity") or "medium") for row in rows)
    return {
        "report": {
            "summary": f"Relay server has {len(recent_alerts)} mirrored anomaly events.",
            "risk_level": _risk_summary(rows)["riskLabel"].lower(),
            "severity_distribution": dict(severity_counts),
            "key_findings": [
                row.get("description") or row.get("anomaly_type") or "relay event"
                for row in rows[:5]
            ],
            "recommendations": [
                "Confirm APK sync status before incident review",
                "Use the full GatewayGuard backend for deep LLM analysis",
            ],
        }
    }


@app.post("/api/llm/chat")
async def chat_endpoint(message: str, session_id: Optional[str] = None):
    stats = _stats()
    return {
        "session_id": session_id or "relay",
        "response": (
            "Relay-only server is online. "
            f"Packets: {stats['total_packets']}, alerts: {len(recent_alerts)}. "
            "Deep LLM chat requires the full GatewayGuard backend."
        ),
        "tool_calls": None,
        "echo": message,
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
                        "running": relay_collect_running,
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
