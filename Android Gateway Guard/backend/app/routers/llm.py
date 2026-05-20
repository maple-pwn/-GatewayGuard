"""LLM分析相关API路由"""

import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.anomaly import AnomalyEventORM, AnomalyEvent
from app.models.report import AnalysisReportORM, ChatHistoryORM
from app.services.llm_engine import LLMEngine
from app.services.llm_tools import (
    default_live_context_tools,
    execute_chat_tools,
    format_tool_results_for_prompt,
    plain_text_response,
    should_attach_live_context,
    summarize_tool_results,
)

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
        raise HTTPException(status_code=404, detail="Event not found")

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

    try:
        analysis = await llm.analyze_anomaly(event)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="LLM service unavailable") from exc

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
        raise HTTPException(status_code=404, detail="No anomaly events found")

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

    try:
        report_data = await llm.generate_report(events)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="LLM service unavailable") from exc

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
    session_id: Optional[str] = None,
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
    try:
        resp = await llm.chat(messages)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="LLM service unavailable") from exc

    requested_tool_calls = resp.get("tool_calls") or []
    executed_tool_calls = requested_tool_calls
    if not executed_tool_calls and should_attach_live_context(message):
        executed_tool_calls = default_live_context_tools()

    tool_results = []
    if executed_tool_calls:
        tool_results = await execute_chat_tools(db, executed_tool_calls)
        tool_prompt = format_tool_results_for_prompt(message, tool_results)
        followup_messages = [*messages]
        initial_content = (resp.get("content") or "").strip()
        if initial_content:
            followup_messages.append({"role": "assistant", "content": initial_content})
        followup_messages.append({"role": "user", "content": tool_prompt})
        try:
            final_resp = await llm.chat(followup_messages, use_tools=False)
            final_content = (final_resp.get("content") or "").strip()
            if final_content:
                resp = {
                    **final_resp,
                    "content": final_content,
                    "tool_calls": requested_tool_calls,
                }
            else:
                resp = {
                    **resp,
                    "content": summarize_tool_results(tool_results),
                    "tool_calls": requested_tool_calls,
                }
        except Exception:
            resp = {
                **resp,
                "content": summarize_tool_results(tool_results),
                "tool_calls": requested_tool_calls,
            }

    # 保存对话
    tool_calls = resp.get("tool_calls")
    content = plain_text_response(resp.get("content", ""))
    tool_metadata = None
    if requested_tool_calls or tool_results:
        tool_metadata = json.dumps(
            {
                "calls": requested_tool_calls,
                "executed": executed_tool_calls,
                "results": tool_results,
            },
            ensure_ascii=False,
        )
    db.add(ChatHistoryORM(
        session_id=session_id, role="user", content=message,
    ))
    db.add(ChatHistoryORM(
        session_id=session_id, role="assistant", content=content,
        tool_calls=tool_metadata or (json.dumps(tool_calls) if tool_calls else None),
    ))
    await db.commit()

    return {
        "session_id": session_id,
        "response": content,
        "tool_calls": tool_calls,
        "tool_results": tool_results,
    }
