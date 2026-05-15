"""Android-to-Windows realtime ingest endpoints."""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.anomaly import AnomalyEventORM
from app.models.packet import PacketORM, TrafficStats, UnifiedPacket
from app.services.ws_manager import ws_manager

router = APIRouter(prefix="/api/mobile", tags=["mobile"])

_last_ingest: dict[str, Any] = {
    "device_id": "",
    "device_name": "",
    "received_at": None,
    "packets": 0,
    "total_received": 0,
    "last_error": "",
}


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


def _require_ingest_key(
    x_gatewayguard_key: Optional[str] = Header(None, alias="X-GatewayGuard-Key"),
    api_key: Optional[str] = Query(None),
) -> None:
    expected = settings.relay.ingest_api_key
    if not expected:
        return
    supplied = x_gatewayguard_key or api_key or ""
    if supplied != expected:
        raise HTTPException(status_code=401, detail="Invalid GatewayGuard ingest key")


def _payload_bytes(payload_hex: str) -> bytes:
    if not payload_hex:
        return b""
    try:
        return bytes.fromhex(payload_hex)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid payload_hex") from exc


def _packet_attack_type(payload_decoded: object, metadata: object) -> Optional[str]:
    if isinstance(payload_decoded, dict):
        attack = payload_decoded.get("attack")
        if attack:
            return str(attack)
    if isinstance(metadata, dict) and metadata.get("attack"):
        return "simulated_attack"
    return None


def _to_unified(packet: MobilePacket, device_id: str, device_name: str) -> UnifiedPacket:
    metadata = dict(packet.metadata or {})
    metadata.update(
        {
            "remote_device_id": device_id,
            "remote_device_name": device_name,
            "ingest_source": "android",
        }
    )
    return UnifiedPacket(
        timestamp=packet.timestamp,
        protocol=packet.protocol.upper(),
        source=packet.source,
        destination=packet.destination,
        msg_id=packet.msg_id,
        payload_hex=packet.payload_hex,
        payload_decoded=packet.payload_decoded or {},
        domain=packet.domain,
        metadata=metadata,
    )


def _packet_stream_rows(packets: list[UnifiedPacket]) -> list[dict[str, Any]]:
    rows = []
    latest = sorted(packets, key=lambda packet: packet.timestamp, reverse=True)[:50]
    for packet in latest:
        attack_type = _packet_attack_type(packet.payload_decoded, packet.metadata)
        rows.append(
            {
                "timestamp": packet.timestamp,
                "protocol": packet.protocol,
                "source": packet.source,
                "destination": packet.destination,
                "msg_id": packet.msg_id,
                "domain": packet.domain,
                "payload_decoded": packet.payload_decoded,
                "attack_type": attack_type,
                "is_attack": bool(attack_type),
            }
        )
    return rows


def _dump_model(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _dump_models(models: list[Any]) -> list[dict[str, Any]]:
    return [_dump_model(model) for model in models]


async def _save_packets(
    packets: list[UnifiedPacket],
    db: AsyncSession,
) -> None:
    for packet in packets:
        db.add(
            PacketORM(
                timestamp=packet.timestamp,
                protocol=packet.protocol,
                source=packet.source,
                destination=packet.destination,
                msg_id=packet.msg_id,
                payload=_payload_bytes(packet.payload_hex),
                payload_decoded=json.dumps(packet.payload_decoded, ensure_ascii=False),
                domain=packet.domain,
                metadata_json=json.dumps(packet.metadata, ensure_ascii=False),
            )
        )
    await db.commit()


async def _save_remote_alerts(
    alerts: list[MobileAlert],
    db: AsyncSession,
    device_id: str,
) -> int:
    for alert in alerts:
        evidence = list(alert.evidence or [])
        evidence.append({"remote_device_id": device_id, "source": "android_remote"})
        db.add(
            AnomalyEventORM(
                timestamp=alert.timestamp,
                anomaly_type=alert.anomaly_type,
                severity=alert.severity,
                confidence=alert.confidence,
                protocol=alert.protocol,
                source_node=alert.source_node,
                target_node=alert.target_node,
                description=alert.description,
                detection_method=alert.detection_method,
                status="open",
                event_id=alert.event_id,
                packet_count=alert.packet_count,
                vehicle_profile=alert.vehicle_profile or settings.detector.vehicle_profile,
                evidence=json.dumps(evidence, ensure_ascii=False),
            )
        )
    if alerts:
        await db.commit()
    return len(alerts)


def _alert_message(alert: Any) -> dict[str, Any]:
    return {
        "anomaly_type": alert.anomaly_type,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "protocol": alert.protocol,
        "source_node": alert.source_node,
        "description": alert.description,
        "detection_method": alert.detection_method,
        "timestamp": alert.timestamp,
    }


async def _detect_if_trained(
    packets: list[UnifiedPacket],
    db: AsyncSession,
) -> list[dict[str, Any]]:
    if not packets:
        return []

    from app.routers.anomaly import detector

    if not detector.is_trained:
        return []

    if settings.detector.enable_event_aggregation:
        alerts, events = detector.detect_with_aggregation(packets)
    else:
        alerts = detector.detect(packets)
        events = []

    for alert in alerts:
        db.add(
            AnomalyEventORM(
                timestamp=alert.timestamp,
                anomaly_type=alert.anomaly_type,
                severity=alert.severity,
                confidence=alert.confidence,
                protocol=alert.protocol,
                source_node=alert.source_node,
                target_node=alert.target_node,
                description=alert.description,
                detection_method=alert.detection_method,
                status="open",
                event_id=alert.event_id,
                packet_count=alert.packet_count,
                vehicle_profile=settings.detector.vehicle_profile,
                evidence=json.dumps(alert.evidence, ensure_ascii=False)
                if alert.evidence
                else None,
            )
        )

    for event in events:
        db.add(
            AnomalyEventORM(
                timestamp=event.first_seen,
                anomaly_type=event.anomaly_type,
                severity=event.severity,
                confidence=event.confidence,
                protocol="CAN",
                source_node=event.involved_ids[0] if event.involved_ids else "",
                target_node=",".join(event.involved_ids),
                description=(
                    f"Aggregated {event.anomaly_type} event covering "
                    f"{event.packet_count} alerts"
                ),
                detection_method="event_aggregation",
                status="open",
                event_id=event.event_id,
                packet_count=event.packet_count,
                vehicle_profile=settings.detector.vehicle_profile,
                evidence=json.dumps(
                    {"involved_ids": event.involved_ids}, ensure_ascii=False
                ),
            )
        )

    if alerts or events:
        await db.commit()
    return [_alert_message(alert) for alert in alerts]


async def _traffic_stats(db: AsyncSession) -> TrafficStats:
    total = await db.scalar(select(func.count()).select_from(PacketORM))
    can_count = await db.scalar(
        select(func.count()).select_from(PacketORM).where(PacketORM.protocol == "CAN")
    )
    eth_count = await db.scalar(
        select(func.count()).select_from(PacketORM).where(PacketORM.protocol == "ETH")
    )
    v2x_count = await db.scalar(
        select(func.count()).select_from(PacketORM).where(PacketORM.protocol == "V2X")
    )
    ts_min = await db.scalar(select(func.min(PacketORM.timestamp)))
    ts_max = await db.scalar(select(func.max(PacketORM.timestamp)))

    packets_per_second = 0.0
    if ts_min and ts_max and ts_max > ts_min:
        packets_per_second = (total or 0) / (ts_max - ts_min)

    return TrafficStats(
        total_packets=total or 0,
        can_count=can_count or 0,
        eth_count=eth_count or 0,
        v2x_count=v2x_count or 0,
        time_range_start=ts_min,
        time_range_end=ts_max,
        packets_per_second=round(packets_per_second, 2),
    )


async def _anomaly_count(db: AsyncSession) -> int:
    return int(await db.scalar(select(func.count()).select_from(AnomalyEventORM)) or 0)


@router.get("/status")
async def mobile_status():
    return dict(_last_ingest)


@router.get("/relay/status")
async def relay_status():
    from app.services.relay_client import relay_client

    return relay_client.status


@router.post("/ingest")
async def ingest_mobile_data(
    payload: MobileIngestRequest,
    _: None = Depends(_require_ingest_key),
    db: AsyncSession = Depends(get_db),
):
    packets = [
        _to_unified(packet, payload.device_id, payload.device_name)
        for packet in payload.packets
    ]

    await _save_packets(packets, db)
    remote_alert_count = await _save_remote_alerts(
        payload.alerts, db, payload.device_id
    )
    detected_alerts = await _detect_if_trained(packets, db)

    stats = await _traffic_stats(db)
    anomaly_total = await _anomaly_count(db)
    received_at = time.time()

    _last_ingest.update(
        {
            "device_id": payload.device_id,
            "device_name": payload.device_name,
            "received_at": received_at,
            "packets": len(packets),
            "total_received": int(_last_ingest.get("total_received") or 0)
            + len(packets),
            "last_error": "",
        }
    )

    await ws_manager.broadcast(
        {
            "type": "traffic_update",
            "data": {
                "stats": _dump_model(stats),
                "device_id": payload.device_id,
                "device_name": payload.device_name,
                "received_at": received_at,
                "packet_count": len(packets),
            },
        }
    )
    if packets:
        await ws_manager.broadcast(
            {"type": "packets_update", "data": _packet_stream_rows(packets)}
        )
    if packets or payload.alerts or detected_alerts:
        await ws_manager.broadcast(
            {
                "type": "relay_ingest",
                "data": {
                    "device_id": payload.device_id,
                    "device_name": payload.device_name,
                    "source": payload.source,
                    "sent_at": payload.sent_at,
                    "received_at": received_at,
                    "stats": payload.stats,
                    "packets": _dump_models(payload.packets),
                    "alerts": _dump_models(payload.alerts),
                    "detected_alerts": detected_alerts,
                },
            }
        )
    await ws_manager.broadcast(
        {
            "type": "stats_update",
            "data": {
                "running": True,
                "source_mode": "android_remote",
                "total_collected": stats.total_packets,
                "total_anomalies": anomaly_total,
                "last_remote_packets": len(packets),
                "remote_device_id": payload.device_id,
                "remote_device_name": payload.device_name,
            },
        }
    )

    remote_alerts = [_alert_message(alert) for alert in payload.alerts]
    all_alerts = remote_alerts + detected_alerts
    if all_alerts:
        await ws_manager.broadcast({"type": "alerts", "data": all_alerts})

    return {
        "status": "accepted",
        "received": len(packets),
        "remote_alerts": remote_alert_count,
        "detected_alerts": len(detected_alerts),
        "stats": _dump_model(stats),
    }
