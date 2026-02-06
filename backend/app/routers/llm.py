"""LLM分析相关API路由"""

import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.anomaly import AnomalyEventORM, AnomalyEvent
from app.models.report import AnalysisReportORM, ChatHistoryORM
from app.services.llm_engine import LLMEngine

router = APIRouter(prefix="/api/llm", tags=["llm"])

llm = LLMEngine()


@router.post("/analyze")
async def analyze_event(
    event_id: int,
    db: AsyncSession = Depends(get_db),
):
    """对指定异常事件进行LLM语义分析"""
    result = await db.execute(
        select(AnomalyEventORM).where(AnomalyEventORM.id == event_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        return {"error": "Event not found"}

    event = AnomalyEvent(
        timestamp=row.timestamp,
        anomaly_type=row.anomaly_type,
        severity=row.severity,
        confidence=row.confidence or 0,
        protocol=row.protocol or "",
        source_node=row.source_node or "",
        target_node=row.target_node or "",
        description=row.description or "",
        detection_method=row.detection_method or "",
    )

    analysis = await llm.analyze_anomaly(event)

    # 保存报告
    report = AnalysisReportORM(
        event_id=event_id,
        report_type="semantic_analysis",
        content=json.dumps(analysis, ensure_ascii=False),
        llm_model=llm.model,
    )
    db.add(report)
    await db.commit()

    return {"event_id": event_id, "analysis": analysis}


@router.post("/report")
async def generate_report(
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """基于最近的异常事件生成预警报告"""
    result = await db.execute(
        select(AnomalyEventORM)
        .order_by(AnomalyEventORM.timestamp.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    if not rows:
        return {"error": "No anomaly events found"}

    events = [
        AnomalyEvent(
            timestamp=r.timestamp,
            anomaly_type=r.anomaly_type,
            severity=r.severity,
            confidence=r.confidence or 0,
            protocol=r.protocol or "",
            source_node=r.source_node or "",
            description=r.description or "",
            detection_method=r.detection_method or "",
        )
        for r in rows
    ]

    report_data = await llm.generate_report(events)

    report = AnalysisReportORM(
        report_type="alert_report",
        content=json.dumps(report_data, ensure_ascii=False),
        llm_model=llm.model,
    )
    db.add(report)
    await db.commit()

    return {"report": report_data}


@router.post("/chat")
async def chat_endpoint(
    message: str,
    session_id: str = None,
    db: AsyncSession = Depends(get_db),
):
    """HTTP方式的对话接口"""
    if not session_id:
        session_id = str(uuid.uuid4())[:8]

    # 加载历史消息
    result = await db.execute(
        select(ChatHistoryORM)
        .where(ChatHistoryORM.session_id == session_id)
        .order_by(ChatHistoryORM.created_at)
        .limit(20)
    )
    history_rows = result.scalars().all()
    messages = [{"role": r.role, "content": r.content} for r in history_rows]
    messages.append({"role": "user", "content": message})

    # 调用LLM
    resp = await llm.chat(messages)

    # 保存对话
    db.add(ChatHistoryORM(
        session_id=session_id, role="user", content=message,
    ))
    db.add(ChatHistoryORM(
        session_id=session_id, role="assistant", content=resp["content"],
        tool_calls=json.dumps(resp["tool_calls"]) if resp["tool_calls"] else None,
    ))
    await db.commit()

    return {
        "session_id": session_id,
        "response": resp["content"],
        "tool_calls": resp["tool_calls"],
    }
