"""Windows-side client for subscribing to a GatewayGuard relay server."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Optional
from urllib.parse import urlparse

from sqlalchemy import func, select

from app.config import settings
from app.database import async_session
from app.models.anomaly import AnomalyEventORM
from app.models.packet import PacketORM, TrafficStats
from app.services.ws_manager import ws_manager

logger = logging.getLogger(__name__)


def _normalize_base_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"http://{value}"
    return value.rstrip("/")


def _ws_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    netloc = parsed.netloc
    path = parsed.path.rstrip("/")
    return f"{scheme}://{netloc}{path}/ws/realtime"


def _payload_bytes(payload_hex: str) -> bytes:
    if not payload_hex:
        return b""
    try:
        return bytes.fromhex(payload_hex)
    except ValueError:
        return b""


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


async def _traffic_stats() -> TrafficStats:
    async with async_session() as db:
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


async def _anomaly_count() -> int:
    async with async_session() as db:
        return int(await db.scalar(select(func.count()).select_from(AnomalyEventORM)) or 0)


def _dump_model(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


class RelayClientService:
    def __init__(self):
        cfg = settings.relay
        self._server_url = _normalize_base_url(cfg.server_url)
        self._api_key = cfg.server_api_key
        self._enabled = bool(cfg.client_enabled and self._server_url)
        self._reconnect_seconds = max(float(cfg.reconnect_seconds), 1.0)
        self._task: Optional[asyncio.Task] = None
        self._stats: dict[str, Any] = {
            "connected": False,
            "received_batches": 0,
            "received_packets": 0,
            "received_alerts": 0,
            "last_received_at": None,
            "last_error": "",
        }

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def status(self) -> dict[str, Any]:
        return {
            "enabled": self._enabled,
            "server_url": self._server_url,
            "api_key_set": bool(self._api_key),
            "running": bool(self._task and not self._task.done()),
            **self._stats,
        }

    async def start(self) -> dict[str, Any]:
        if not self._enabled:
            return self.status
        if self._task and not self._task.done():
            return self.status
        self._task = asyncio.create_task(self._run_loop())
        return self.status

    async def stop(self) -> None:
        if not self._task:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _run_loop(self) -> None:
        import websockets

        url = _ws_url(self._server_url)
        headers = {}
        if self._api_key:
            headers["X-GatewayGuard-Key"] = self._api_key

        while self._enabled:
            try:
                async with websockets.connect(
                    url,
                    extra_headers=headers or None,
                    ping_interval=30,
                    ping_timeout=20,
                ) as ws:
                    self._stats["connected"] = True
                    self._stats["last_error"] = ""
                    logger.info("Relay client connected to %s", url)
                    await self._receive_loop(ws)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._stats["connected"] = False
                self._stats["last_error"] = str(exc)
                logger.warning("Relay client disconnected: %s", exc)
                await asyncio.sleep(self._reconnect_seconds)

    async def _receive_loop(self, ws: Any) -> None:
        while self._enabled:
            raw = await ws.recv()
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if message.get("type") != "relay_ingest":
                continue

            data = message.get("data")
            if isinstance(data, dict):
                await self._handle_relay_ingest(data)

    async def _handle_relay_ingest(self, data: dict[str, Any]) -> None:
        packets = data.get("packets") or []
        alerts = data.get("alerts") or []
        detected_alerts = data.get("detected_alerts") or []
        device_id = str(data.get("device_id") or "")
        device_name = str(data.get("device_name") or "")

        if not isinstance(packets, list):
            packets = []
        if not isinstance(alerts, list):
            alerts = []
        if not isinstance(detected_alerts, list):
            detected_alerts = []

        async with async_session() as db:
            for packet in packets:
                if not isinstance(packet, dict):
                    continue
                metadata = dict(packet.get("metadata") or {})
                metadata.update(
                    {
                        "relay_source": self._server_url,
                        "remote_device_id": device_id,
                        "remote_device_name": device_name,
                    }
                )
                db.add(
                    PacketORM(
                        timestamp=float(packet.get("timestamp") or time.time()),
                        protocol=str(packet.get("protocol") or "").upper(),
                        source=str(packet.get("source") or ""),
                        destination=str(packet.get("destination") or ""),
                        msg_id=str(packet.get("msg_id") or ""),
                        payload=_payload_bytes(str(packet.get("payload_hex") or "")),
                        payload_decoded=json.dumps(
                            packet.get("payload_decoded") or {},
                            ensure_ascii=False,
                        ),
                        domain=str(packet.get("domain") or ""),
                        metadata_json=json.dumps(metadata, ensure_ascii=False),
                    )
                )

            for alert in [*alerts, *detected_alerts]:
                if not isinstance(alert, dict):
                    continue
                evidence = alert.get("evidence")
                if not isinstance(evidence, list):
                    evidence = []
                evidence.append(
                    {
                        "relay_source": self._server_url,
                        "remote_device_id": device_id,
                    }
                )
                db.add(
                    AnomalyEventORM(
                        timestamp=float(alert.get("timestamp") or time.time()),
                        anomaly_type=str(alert.get("anomaly_type") or "relay_alert"),
                        severity=str(alert.get("severity") or "medium"),
                        confidence=float(alert.get("confidence") or 0.0),
                        protocol=str(alert.get("protocol") or ""),
                        source_node=str(alert.get("source_node") or ""),
                        target_node=str(alert.get("target_node") or ""),
                        description=str(alert.get("description") or ""),
                        detection_method=str(
                            alert.get("detection_method") or "relay_server"
                        ),
                        status="open",
                        event_id=alert.get("event_id"),
                        packet_count=int(alert.get("packet_count") or 1),
                        vehicle_profile=alert.get("vehicle_profile")
                        or settings.detector.vehicle_profile,
                        evidence=json.dumps(evidence, ensure_ascii=False),
                    )
                )

            await db.commit()

        self._stats["received_batches"] += 1
        self._stats["received_packets"] += len(packets)
        self._stats["received_alerts"] += len(alerts) + len(detected_alerts)
        self._stats["last_received_at"] = time.time()

        stats = await _traffic_stats()
        anomaly_total = await _anomaly_count()
        await ws_manager.broadcast(
            {
                "type": "traffic_update",
                "data": {
                    "stats": _dump_model(stats),
                    "device_id": device_id,
                    "device_name": device_name,
                    "packet_count": len(packets),
                    "relay_server": self._server_url,
                },
            }
        )
        if packets:
            await ws_manager.broadcast(
                {"type": "packets_update", "data": _packet_stream_rows(packets)}
            )
        await ws_manager.broadcast(
            {
                "type": "stats_update",
                "data": {
                    "running": True,
                    "source_mode": "relay_server",
                    "total_collected": stats.total_packets,
                    "total_anomalies": anomaly_total,
                    "last_remote_packets": len(packets),
                    "remote_device_id": device_id,
                    "remote_device_name": device_name,
                    "relay_server": self._server_url,
                },
            }
        )

        alert_messages = [*alerts, *detected_alerts]
        if alert_messages:
            await ws_manager.broadcast({"type": "alerts", "data": alert_messages})


relay_client = RelayClientService()
