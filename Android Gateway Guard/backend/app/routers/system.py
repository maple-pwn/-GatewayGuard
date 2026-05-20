"""System-related endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.android_runtime import read_recent_log_lines
from app.config import DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, settings
from app.database import get_db
from app.models.anomaly import AnomalyEventORM
from app.models.packet import PacketORM
from app.platform import is_android_env

router = APIRouter(prefix="/api/system", tags=["system"])


class LLMApiKeyRequest(BaseModel):
    api_key: str
    provider: str = "deepseek"
    base_url: Optional[str] = None
    model: Optional[str] = None


def _current_llm_model() -> str:
    if settings.llm.provider == "ollama":
        return settings.llm.ollama_model
    return settings.llm.deepseek_model


def _current_llm_has_api_key() -> bool:
    if settings.llm.provider == "ollama":
        return True
    return bool(settings.llm.deepseek_api_key)


def _persist_deepseek_config() -> None:
    path = Path(settings.config_path)
    data = {}
    if path.is_file():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    llm_data = data.setdefault("llm", {})
    llm_data.update(
        {
            "provider": "deepseek",
            "deepseek_api_key": settings.llm.deepseek_api_key,
            "deepseek_base_url": settings.llm.deepseek_base_url,
            "deepseek_model": settings.llm.deepseek_model,
        }
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def _reload_llm_engine() -> None:
    from app.routers import llm as llm_router

    llm_router.llm._init_client()


@router.get("/status")
async def get_system_status():
    return {
        "status": "running",
        "android": is_android_env(),
        "runtime_home": settings.runtime_home,
        "config_path": settings.config_path,
        "db_path": settings.db_path,
        "imports_dir": settings.imports_dir,
        "reports_dir": settings.reports_dir,
        "logs_dir": settings.logs_dir,
        "llm_provider": settings.llm.provider,
        "llm_model": _current_llm_model(),
        "llm_has_api_key": _current_llm_has_api_key(),
        "detector": {
            "rule_enabled": settings.detector.rule_enabled,
            "ml_enabled": settings.detector.ml_enabled,
            "iforest_enabled": settings.detector.enable_iforest_aux,
        },
    }


@router.post("/api-key")
async def configure_deepseek_api_key(payload: LLMApiKeyRequest):
    """Write the DeepSeek API key and refresh the in-process LLM client."""
    provider = (payload.provider or "deepseek").strip().lower()
    if provider in {"openai", "codex"}:
        provider = "deepseek"
    if provider != "deepseek":
        raise HTTPException(status_code=400, detail="Only DeepSeek provider is supported")

    api_key = payload.api_key.strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="DeepSeek API key is required")

    settings.llm.provider = "deepseek"
    settings.llm.deepseek_api_key = api_key
    settings.llm.deepseek_base_url = (payload.base_url or DEEPSEEK_BASE_URL).rstrip("/")
    settings.llm.deepseek_model = payload.model or DEEPSEEK_MODEL
    settings.llm.openai_api_key = settings.llm.deepseek_api_key
    settings.llm.openai_base_url = settings.llm.deepseek_base_url
    settings.llm.openai_model = settings.llm.deepseek_model

    _persist_deepseek_config()
    _reload_llm_engine()
    return {
        "provider": settings.llm.provider,
        "model": settings.llm.deepseek_model,
        "base_url": settings.llm.deepseek_base_url,
        "llm_has_api_key": True,
        "message": "DeepSeek API key saved",
    }


@router.get("/logs/recent")
async def get_recent_logs(lines: int = Query(120, ge=20, le=1000)):
    return {
        "lines": lines,
        "content": read_recent_log_lines(lines=lines),
    }


@router.delete("/clear-data")
async def clear_all_data(db: AsyncSession = Depends(get_db)):
    table_statements = {
        "chat_history": {
            "count": text("SELECT COUNT(*) FROM chat_history"),
            "delete": text("DELETE FROM chat_history"),
        },
        "analysis_reports": {
            "count": text("SELECT COUNT(*) FROM analysis_reports"),
            "delete": text("DELETE FROM analysis_reports"),
        },
        "anomaly_events": {
            "count": text("SELECT COUNT(*) FROM anomaly_events"),
            "delete": text("DELETE FROM anomaly_events"),
        },
        "packets": {
            "count": text("SELECT COUNT(*) FROM packets"),
            "delete": text("DELETE FROM packets"),
        },
    }

    counts = {}
    for table, statements in table_statements.items():
        result = await db.execute(statements["count"])
        counts[table] = result.scalar()
        await db.execute(statements["delete"])
    await db.commit()
    return {"cleared": counts, "message": "All data cleared"}


@router.delete("/clear-packets")
async def clear_packets_partial(
    protocol: Optional[str] = Query(None, description="CAN/ETH/V2X"),
    keep_recent: Optional[int] = Query(None, description="Keep latest N rows"),
    start_time: Optional[float] = Query(None, description="Start timestamp in seconds"),
    end_time: Optional[float] = Query(None, description="End timestamp in seconds"),
    all_records: bool = Query(False, description="Clear all packet records"),
    db: AsyncSession = Depends(get_db),
):
    count_q = select(func.count()).select_from(PacketORM)
    if protocol:
        count_q = count_q.where(PacketORM.protocol == protocol.upper())
    if start_time is not None:
        count_q = count_q.where(PacketORM.timestamp >= start_time)
    if end_time is not None:
        count_q = count_q.where(PacketORM.timestamp <= end_time)
    before = int((await db.execute(count_q)).scalar() or 0)

    if keep_recent and keep_recent > 0:
        cutoff_q = (
            select(PacketORM.id)
            .order_by(PacketORM.timestamp.desc())
            .offset(keep_recent)
            .limit(1)
        )
        cutoff_row = (await db.execute(cutoff_q)).scalar()
        if cutoff_row:
            await db.execute(
                text("DELETE FROM packets WHERE id <= :cutoff"),
                {"cutoff": cutoff_row},
            )
    elif all_records or protocol or start_time is not None or end_time is not None:
        delete_stmt = delete(PacketORM)
        if protocol:
            delete_stmt = delete_stmt.where(PacketORM.protocol == protocol.upper())
        if start_time is not None:
            delete_stmt = delete_stmt.where(PacketORM.timestamp >= start_time)
        if end_time is not None:
            delete_stmt = delete_stmt.where(PacketORM.timestamp <= end_time)
        await db.execute(delete_stmt)
    else:
        return {"error": "protocol, time range, keep_recent, or all_records is required"}

    await db.commit()
    after = int(
        (await db.execute(select(func.count()).select_from(PacketORM))).scalar() or 0
    )

    return {
        "deleted": before - after,
        "remaining": after,
        "message": f"Deleted {before - after} packet records",
    }


@router.delete("/clear-anomalies")
async def clear_anomalies_partial(
    severity: Optional[str] = Query(
        None, description="critical/high/medium/low"
    ),
    status: Optional[str] = Query(None, description="open/investigating/resolved"),
    protocol: Optional[str] = Query(None, description="CAN/ETH/V2X"),
    keep_recent: Optional[int] = Query(None, description="Keep latest N rows"),
    start_time: Optional[float] = Query(None, description="Start timestamp in seconds"),
    end_time: Optional[float] = Query(None, description="End timestamp in seconds"),
    all_records: bool = Query(False, description="Clear all anomaly events"),
    db: AsyncSession = Depends(get_db),
):
    count_q = select(func.count()).select_from(AnomalyEventORM)
    if severity:
        count_q = count_q.where(AnomalyEventORM.severity == severity)
    if status:
        count_q = count_q.where(AnomalyEventORM.status == status)
    if protocol:
        count_q = count_q.where(AnomalyEventORM.protocol == protocol.upper())
    if start_time is not None:
        count_q = count_q.where(AnomalyEventORM.timestamp >= start_time)
    if end_time is not None:
        count_q = count_q.where(AnomalyEventORM.timestamp <= end_time)
    before = int((await db.execute(count_q)).scalar() or 0)

    if keep_recent and keep_recent > 0:
        cutoff_q = (
            select(AnomalyEventORM.id)
            .order_by(AnomalyEventORM.timestamp.desc())
            .offset(keep_recent)
            .limit(1)
        )
        cutoff_row = (await db.execute(cutoff_q)).scalar()
        if cutoff_row:
            await db.execute(
                text("DELETE FROM anomaly_events WHERE id <= :cutoff"),
                {"cutoff": cutoff_row},
            )
    elif all_records or severity or status or protocol or start_time is not None or end_time is not None:
        delete_stmt = delete(AnomalyEventORM)
        if severity:
            delete_stmt = delete_stmt.where(AnomalyEventORM.severity == severity)
        if status:
            delete_stmt = delete_stmt.where(AnomalyEventORM.status == status)
        if protocol:
            delete_stmt = delete_stmt.where(AnomalyEventORM.protocol == protocol.upper())
        if start_time is not None:
            delete_stmt = delete_stmt.where(AnomalyEventORM.timestamp >= start_time)
        if end_time is not None:
            delete_stmt = delete_stmt.where(AnomalyEventORM.timestamp <= end_time)
        await db.execute(delete_stmt)
    else:
        return {"error": "severity, status, protocol, time range, keep_recent, or all_records is required"}

    await db.commit()
    after = int(
        (await db.execute(select(func.count()).select_from(AnomalyEventORM))).scalar()
        or 0
    )

    return {
        "deleted": before - after,
        "remaining": after,
        "message": f"Deleted {before - after} anomaly records",
    }

