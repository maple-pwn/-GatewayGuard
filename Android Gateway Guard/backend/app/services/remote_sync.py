"""Background sender for Android-to-Windows realtime sync."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Any, Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


def _normalize_base_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"http://{value}"
    return value.rstrip("/")


def _model_to_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    return dict(value)


def _error_text(exc: Exception) -> str:
    message = str(exc).strip()
    if message:
        return message
    return exc.__class__.__name__


class RemoteSyncService:
    def __init__(self):
        cfg = settings.remote_sync
        self._target_url = _normalize_base_url(cfg.target_url)
        self._api_key = cfg.api_key
        self._enabled = bool(cfg.enabled and self._target_url)
        self._device_id = cfg.device_id
        self._device_name = cfg.device_name
        self._batch_size = max(int(cfg.batch_size), 1)
        self._flush_interval = max(float(cfg.flush_interval_ms) / 1000.0, 0.1)
        self._max_queue_size = max(int(cfg.max_queue_size), self._batch_size)
        self._timeout = float(cfg.timeout_seconds)
        self._packet_queue: deque[dict[str, Any]] = deque()
        self._alert_queue: deque[dict[str, Any]] = deque()
        self._task: Optional[asyncio.Task] = None
        self._stats: dict[str, Any] = {
            "queued_packets": 0,
            "queued_alerts": 0,
            "sent_packets": 0,
            "sent_alerts": 0,
            "dropped_packets": 0,
            "failed_batches": 0,
            "last_sent_at": None,
            "last_error": "",
        }

    @property
    def enabled(self) -> bool:
        return bool(self._enabled and self._target_url)

    @property
    def status(self) -> dict[str, Any]:
        self._stats["queued_packets"] = len(self._packet_queue)
        self._stats["queued_alerts"] = len(self._alert_queue)
        return {
            "enabled": self.enabled,
            "target_url": self._target_url,
            "api_key_set": bool(self._api_key),
            "device_id": self._device_id,
            "device_name": self._device_name,
            "running": bool(self._task and not self._task.done()),
            **self._stats,
        }

    def configure(
        self,
        target_url: str,
        enabled: bool = True,
        device_name: Optional[str] = None,
        device_id: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> dict[str, Any]:
        self._target_url = _normalize_base_url(target_url)
        self._enabled = bool(enabled and self._target_url)
        if api_key is not None:
            self._api_key = api_key
        if device_name:
            self._device_name = device_name
        if device_id:
            self._device_id = device_id
        self._stats["last_error"] = ""
        if self.enabled:
            self._ensure_task()
        return self.status

    async def enqueue_packets(
        self,
        packets: list[Any],
        source: str = "android",
    ) -> dict[str, Any]:
        if not self.enabled or not packets:
            return self.status

        for packet in packets:
            if len(self._packet_queue) >= self._max_queue_size:
                self._packet_queue.popleft()
                self._stats["dropped_packets"] += 1
            row = _model_to_dict(packet)
            row.setdefault("metadata", {})
            row["metadata"] = dict(row["metadata"] or {})
            row["metadata"]["android_sync_source"] = source
            self._packet_queue.append(row)

        self._ensure_task()
        return self.status

    async def enqueue_alerts(self, alerts: list[Any]) -> dict[str, Any]:
        if not self.enabled or not alerts:
            return self.status

        for alert in alerts:
            self._alert_queue.append(_model_to_dict(alert))

        self._ensure_task()
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

    async def test_connection(self, target_url: Optional[str] = None) -> dict[str, Any]:
        base_url = _normalize_base_url(target_url or self._target_url)
        if not base_url:
            return {"ok": False, "error": "Target URL is empty"}

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            last_error = ""
            for path in ("/health/ready", "/"):
                try:
                    response = await client.get(f"{base_url}{path}")
                    if 200 <= response.status_code < 300:
                        return {
                            "ok": True,
                            "target_url": base_url,
                            "status_code": response.status_code,
                            "path": path,
                        }
                    last_error = f"{path} returned {response.status_code}"
                except Exception as exc:  # pragma: no cover - network dependent
                    last_error = _error_text(exc)
            return {"ok": False, "target_url": base_url, "error": last_error}

    def _ensure_task(self) -> None:
        if self._task and not self._task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._task = loop.create_task(self._run_loop())

    async def _run_loop(self) -> None:
        while self.enabled:
            try:
                await self._flush_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive loop guard
                self._stats["last_error"] = _error_text(exc)
                logger.warning("Remote sync loop error: %s", exc)
            await asyncio.sleep(self._flush_interval)

    async def _flush_once(self) -> None:
        packets = self._take_batch(self._packet_queue)
        alerts = self._take_batch(self._alert_queue)
        if not packets and not alerts:
            return

        payload = {
            "device_id": self._device_id,
            "device_name": self._device_name,
            "source": "android",
            "sent_at": time.time(),
            "stats": self._local_collector_stats(),
            "packets": packets,
            "alerts": alerts,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                headers = {}
                if self._api_key:
                    headers["X-GatewayGuard-Key"] = self._api_key
                response = await client.post(
                    f"{self._target_url}/api/mobile/ingest",
                    json=payload,
                    headers=headers,
                )
                response.raise_for_status()
        except Exception as exc:
            self._restore_batch(self._packet_queue, packets)
            self._restore_batch(self._alert_queue, alerts)
            self._stats["failed_batches"] += 1
            self._stats["last_error"] = _error_text(exc)
            logger.warning("Remote sync failed: %s", exc)
            return

        self._stats["sent_packets"] += len(packets)
        self._stats["sent_alerts"] += len(alerts)
        self._stats["last_sent_at"] = time.time()
        self._stats["last_error"] = ""

    def _take_batch(self, queue: deque[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = []
        for _ in range(min(self._batch_size, len(queue))):
            rows.append(queue.popleft())
        return rows

    def _restore_batch(
        self,
        queue: deque[dict[str, Any]],
        rows: list[dict[str, Any]],
    ) -> None:
        for row in reversed(rows):
            queue.appendleft(row)

    def _local_collector_stats(self) -> dict[str, Any]:
        try:
            from app.services.collector import collector

            return collector.stats
        except Exception:
            return {}


remote_sync = RemoteSyncService()
