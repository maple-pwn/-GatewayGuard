"""系统相关API路由"""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.packet import PacketORM
from app.models.anomaly import AnomalyEventORM

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/status")
async def get_system_status():
    """系统状态"""
    return {
        "status": "running",
        "llm_provider": settings.llm.provider,
        "llm_model": (
            settings.llm.ollama_model
            if settings.llm.provider == "ollama"
            else settings.llm.openai_model
        ),
        "detector": {
            "rule_enabled": settings.detector.rule_enabled,
            "ml_enabled": settings.detector.ml_enabled,
        },
    }


@router.delete("/clear-data")
async def clear_all_data(db: AsyncSession = Depends(get_db)):
    """清空所有数据库数据"""
    tables = ["chat_history", "analysis_reports", "anomaly_events", "packets"]
    counts = {}
    for table in tables:
        result = await db.execute(text(f"SELECT COUNT(*) FROM {table}"))
        counts[table] = result.scalar()
        await db.execute(text(f"DELETE FROM {table}"))
    await db.commit()
    return {"cleared": counts, "message": "所有数据已清空"}


@router.delete("/clear-packets")
async def clear_packets_partial(
    protocol: Optional[str] = Query(None, description="按协议删除: CAN/ETH/V2X"),
    keep_recent: Optional[int] = Query(None, description="只保留最近N条，删除其余"),
    db: AsyncSession = Depends(get_db),
):
    """按条件部分清理流量数据"""
    # 清理前计数
    count_q = select(func.count()).select_from(PacketORM)
    if protocol:
        count_q = count_q.where(PacketORM.protocol == protocol.upper())
    before = (await db.execute(count_q)).scalar()

    if keep_recent and keep_recent > 0:
        # 找到第N条的id作为分界线
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
    elif protocol:
        await db.execute(
            text("DELETE FROM packets WHERE protocol = :proto"),
            {"proto": protocol.upper()},
        )
    else:
        return {"error": "请指定 protocol 或 keep_recent 参数"}

    await db.commit()

    after = (await db.execute(
        select(func.count()).select_from(PacketORM)
    )).scalar()

    return {
        "deleted": before - after,
        "remaining": after,
        "message": f"已删除 {before - after} 条流量记录",
    }


@router.delete("/clear-anomalies")
async def clear_anomalies_partial(
    severity: Optional[str] = Query(None, description="按严重程度删除: critical/high/medium/low"),
    keep_recent: Optional[int] = Query(None, description="只保留最近N条"),
    db: AsyncSession = Depends(get_db),
):
    """按条件部分清理异常事件"""
    count_q = select(func.count()).select_from(AnomalyEventORM)
    if severity:
        count_q = count_q.where(AnomalyEventORM.severity == severity)
    before = (await db.execute(count_q)).scalar()

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
    elif severity:
        await db.execute(
            text("DELETE FROM anomaly_events WHERE severity = :sev"),
            {"sev": severity},
        )
    else:
        return {"error": "请指定 severity 或 keep_recent 参数"}

    await db.commit()

    after = (await db.execute(
        select(func.count()).select_from(AnomalyEventORM)
    )).scalar()

    return {
        "deleted": before - after,
        "remaining": after,
        "message": f"已删除 {before - after} 条异常事件",
    }
