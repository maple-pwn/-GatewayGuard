"""Runtime tool execution for LLM chat."""

from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import AnomalyEventORM
from app.models.packet import PacketORM


DATA_QUERY_KEYWORDS = (
    "数据",
    "真实",
    "当前",
    "现在",
    "最近",
    "流量",
    "报文",
    "包",
    "异常",
    "告警",
    "报警",
    "攻击",
    "统计",
    "事件",
    "can",
    "eth",
    "v2x",
    "packet",
    "traffic",
    "anomaly",
    "alert",
    "event",
)


def should_attach_live_context(message: str) -> bool:
    text = message.lower()
    return any(keyword in text for keyword in DATA_QUERY_KEYWORDS)


def default_live_context_tools() -> list[dict[str, Any]]:
    return [
        {"name": "query_traffic_stats", "arguments": {"protocol": "ALL"}},
        {"name": "get_anomaly_events", "arguments": {"severity": "all", "limit": 10}},
    ]


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _clamp_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(maximum, number))


def _normalize_protocol(value: Any) -> str | None:
    if value is None:
        return None
    protocol = str(value).strip().upper()
    if protocol in {"", "ALL", "*"}:
        return None
    if protocol in {"ETHERNET", "IP"}:
        return "ETH"
    if protocol.startswith("CAN"):
        return "CAN"
    if protocol.startswith("V2X"):
        return "V2X"
    if protocol.startswith("ETH"):
        return "ETH"
    return protocol


def _normalize_severity(value: Any) -> str | None:
    if value is None:
        return None
    severity = str(value).strip().lower()
    if severity in {"", "all", "*"}:
        return None
    return severity


def _json_value(value: Any, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _payload_hex(value: Any) -> str:
    if not value:
        return ""
    try:
        return bytes(value).hex().upper()
    except TypeError:
        return ""


def _apply_filters(stmt, filters: list[Any]):
    if filters:
        return stmt.where(*filters)
    return stmt


async def _query_traffic_stats(
    db: AsyncSession,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    protocol = _normalize_protocol(arguments.get("protocol"))
    raw_minutes = arguments.get("minutes")
    minutes = _clamp_int(raw_minutes, 0, 0, 24 * 60) if raw_minutes is not None else 0

    filters: list[Any] = []
    if protocol:
        filters.append(PacketORM.protocol == protocol)

    latest_ts_stmt = _apply_filters(select(func.max(PacketORM.timestamp)), filters)
    latest_ts = await db.scalar(latest_ts_stmt)

    start_time = None
    if latest_ts is not None and minutes > 0:
        start_time = float(latest_ts) - minutes * 60
        filters.append(PacketORM.timestamp >= start_time)

    total = await db.scalar(
        _apply_filters(select(func.count()).select_from(PacketORM), filters)
    )
    ts_min = await db.scalar(_apply_filters(select(func.min(PacketORM.timestamp)), filters))
    ts_max = await db.scalar(_apply_filters(select(func.max(PacketORM.timestamp)), filters))

    protocol_rows = (
        await db.execute(
            _apply_filters(
                select(PacketORM.protocol, func.count()).group_by(PacketORM.protocol),
                filters,
            )
        )
    ).all()
    domain_rows = (
        await db.execute(
            _apply_filters(
                select(PacketORM.domain, func.count()).group_by(PacketORM.domain),
                filters,
            )
        )
    ).all()
    msg_rows = (
        await db.execute(
            _apply_filters(
                select(PacketORM.msg_id, func.count())
                .group_by(PacketORM.msg_id)
                .order_by(func.count().desc())
                .limit(5),
                filters,
            )
        )
    ).all()
    latest_rows = (
        await db.execute(
            _apply_filters(
                select(PacketORM).order_by(PacketORM.timestamp.desc()).limit(5),
                filters,
            )
        )
    ).scalars().all()

    span = float(ts_max - ts_min) if ts_min is not None and ts_max is not None else 0.0
    packets_per_second = round((int(total or 0) / span), 2) if span > 0 else 0.0

    return {
        "scope": {
            "protocol": protocol or "ALL",
            "minutes": minutes or "ALL",
            "window_start": start_time,
            "window_end": float(latest_ts) if latest_ts is not None else None,
        },
        "total_packets": int(total or 0),
        "protocol_counts": {str(name or "UNKNOWN"): int(count) for name, count in protocol_rows},
        "domain_counts": {str(name or "UNKNOWN"): int(count) for name, count in domain_rows},
        "top_message_ids": [
            {"msg_id": str(msg_id or ""), "count": int(count)}
            for msg_id, count in msg_rows
        ],
        "time_range_start": float(ts_min) if ts_min is not None else None,
        "time_range_end": float(ts_max) if ts_max is not None else None,
        "packets_per_second": packets_per_second,
        "latest_packets": [
            {
                "id": row.id,
                "timestamp": row.timestamp,
                "protocol": row.protocol,
                "source": row.source,
                "destination": row.destination,
                "msg_id": row.msg_id,
                "domain": row.domain,
                "payload_hex": _payload_hex(row.payload),
                "payload_decoded": _json_value(row.payload_decoded, {}),
            }
            for row in latest_rows
        ],
    }


async def _get_anomaly_events(
    db: AsyncSession,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    severity = _normalize_severity(arguments.get("severity"))
    limit = _clamp_int(arguments.get("limit"), default=10, minimum=1, maximum=50)

    filters: list[Any] = []
    if severity:
        filters.append(AnomalyEventORM.severity == severity)

    total = await db.scalar(
        _apply_filters(select(func.count()).select_from(AnomalyEventORM), filters)
    )
    severity_rows = (
        await db.execute(
            _apply_filters(
                select(AnomalyEventORM.severity, func.count()).group_by(AnomalyEventORM.severity),
                filters,
            )
        )
    ).all()
    protocol_rows = (
        await db.execute(
            _apply_filters(
                select(AnomalyEventORM.protocol, func.count()).group_by(AnomalyEventORM.protocol),
                filters,
            )
        )
    ).all()
    latest_rows = (
        await db.execute(
            _apply_filters(
                select(AnomalyEventORM)
                .order_by(AnomalyEventORM.timestamp.desc())
                .limit(limit),
                filters,
            )
        )
    ).scalars().all()

    return {
        "scope": {"severity": severity or "all", "limit": limit},
        "total_events": int(total or 0),
        "severity_counts": {
            str(name or "unknown"): int(count) for name, count in severity_rows
        },
        "protocol_counts": {
            str(name or "unknown"): int(count) for name, count in protocol_rows
        },
        "latest_events": [
            {
                "id": row.id,
                "event_id": row.event_id,
                "timestamp": row.timestamp,
                "anomaly_type": row.anomaly_type,
                "severity": row.severity,
                "confidence": row.confidence,
                "protocol": row.protocol,
                "source_node": row.source_node,
                "target_node": row.target_node,
                "description": row.description,
                "detection_method": row.detection_method,
                "status": row.status,
                "packet_count": row.packet_count,
            }
            for row in latest_rows
        ],
    }


async def execute_chat_tools(
    db: AsyncSession,
    tool_calls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for call in tool_calls:
        name = str(call.get("name") or "")
        arguments = _as_dict(call.get("arguments"))
        try:
            if name == "query_traffic_stats":
                result = await _query_traffic_stats(db, arguments)
            elif name == "get_anomaly_events":
                result = await _get_anomaly_events(db, arguments)
            else:
                result = {"error": f"Unsupported tool: {name}"}
        except Exception as exc:
            result = {"error": str(exc)}
        results.append({"name": name, "arguments": arguments, "result": result})
    return results


def format_tool_results_for_prompt(
    user_message: str,
    tool_results: list[dict[str, Any]],
) -> str:
    data = json.dumps(tool_results, ensure_ascii=False, indent=2)
    return (
        "以下是后端刚刚从本机数据库查询到的真实数据。"
        "请只基于这些数据和已有对话回答用户，不要编造不存在的采集结果；"
        "如果数据为空，请明确说明当前本机没有可见的采集/检测数据。\n\n"
        f"用户原始问题：{user_message}\n\n"
        f"真实数据：\n{data}"
    )


def summarize_tool_results(tool_results: list[dict[str, Any]]) -> str:
    traffic = next(
        (item.get("result", {}) for item in tool_results if item.get("name") == "query_traffic_stats"),
        None,
    )
    anomalies = next(
        (item.get("result", {}) for item in tool_results if item.get("name") == "get_anomaly_events"),
        None,
    )

    lines = ["已读取本机后端真实数据。"]
    if traffic:
        total_packets = traffic.get("total_packets", 0)
        protocol_counts = traffic.get("protocol_counts", {})
        lines.append(f"流量包总数：{total_packets}，协议分布：{protocol_counts}。")
    if anomalies:
        total_events = anomalies.get("total_events", 0)
        severity_counts = anomalies.get("severity_counts", {})
        lines.append(f"异常事件总数：{total_events}，严重级别分布：{severity_counts}。")
    if len(lines) == 1:
        lines.append("当前没有查询到可见的流量或异常事件。")
    return "\n".join(lines)


def plain_text_response(content: str) -> str:
    text = content or ""
    text = text.replace("\r\n", "\n")
    text = re.sub(r"```(?:[A-Za-z0-9_-]+)?\s*\n?(.*?)\n?```", r"\1", text, flags=re.S)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"(?m)^\s{0,3}#{1,6}\s*", "", text)
    text = re.sub(r"(?m)^\s{0,3}>\s?", "", text)
    text = re.sub(r"(?m)^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$", "", text)
    text = re.sub(r"(?m)^\s*[-*+]\s+", "", text)
    text = re.sub(r"(?m)^\s*\d+[.)]\s+", "", text)
    text = re.sub(r"(\*\*|__)(.*?)\1", r"\2", text)
    text = re.sub(r"(?<!\*)\*(?!\s)(.*?)(?<!\s)\*(?!\*)", r"\1", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
