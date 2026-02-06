"""LLM分析引擎

支持OpenAI API和Ollama本地模型，提供：
1. 异常事件语义分析
2. 预警报告生成
3. 交互式安全问答（Function Calling）
"""

import json
import re
from typing import List, Optional

from openai import AsyncOpenAI

from app.config import settings
from app.utils.prompt_templates import (
    SYSTEM_PROMPT,
    ANOMALY_ANALYSIS_PROMPT,
    REPORT_GENERATION_PROMPT,
)
from app.utils.tools import CHAT_TOOLS
from app.models.anomaly import AnomalyEvent


class LLMEngine:
    """LLM分析引擎，支持OpenAI/Ollama双模式"""

    @staticmethod
    def _parse_json_response(content: str) -> dict:
        """解析LLM返回的JSON，自动去除markdown代码块包裹"""
        text = content.strip()
        m = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
        if m:
            text = m.group(1).strip()
        return json.loads(text)

    def __init__(self):
        self._init_client()

    def _init_client(self):
        cfg = settings.llm
        if cfg.provider == "ollama":
            self.client = AsyncOpenAI(
                base_url=f"{cfg.ollama_base_url}/v1",
                api_key="ollama",
            )
            self.model = cfg.ollama_model
        else:
            self.client = AsyncOpenAI(
                base_url=cfg.openai_base_url,
                api_key=cfg.openai_api_key,
            )
            self.model = cfg.openai_model

    async def _call_llm(self, messages: list, **kwargs) -> str:
        """统一的LLM调用入口"""
        resp = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=settings.llm.temperature,
            max_tokens=settings.llm.max_tokens,
            **kwargs,
        )
        return resp

    async def analyze_anomaly(self, event: AnomalyEvent) -> dict:
        """对单个异常事件进行LLM语义分析"""
        prompt = ANOMALY_ANALYSIS_PROMPT.format(
            timestamp=event.timestamp,
            protocol=event.protocol,
            anomaly_type=event.anomaly_type,
            severity=event.severity,
            confidence=event.confidence,
            source_node=event.source_node,
            target_node=event.target_node,
            detection_method=event.detection_method,
            description=event.description,
        )

        resp = await self._call_llm([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ])
        content = resp.choices[0].message.content
        try:
            return self._parse_json_response(content)
        except (json.JSONDecodeError, ValueError):
            return {"analyze_raw": content}

    async def generate_report(self, events: List[AnomalyEvent]) -> dict:
        """基于多个异常事件生成预警报告"""
        events_data = [
            {
                "timestamp": e.timestamp,
                "anomaly_type": e.anomaly_type,
                "severity": e.severity,
                "protocol": e.protocol,
                "source_node": e.source_node,
                "description": e.description,
            }
            for e in events
        ]
        prompt = REPORT_GENERATION_PROMPT.format(
            events_json=json.dumps(events_data, ensure_ascii=False, indent=2)
        )

        resp = await self._call_llm([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ])
        content = resp.choices[0].message.content
        try:
            return self._parse_json_response(content)
        except (json.JSONDecodeError, ValueError):
            return {"report_raw": content}

    async def chat(self, messages: List[dict], use_tools: bool = True) -> dict:
        """交互式安全分析对话"""
        full_messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            *messages,
        ]

        kwargs = {}
        if use_tools:
            kwargs["tools"] = CHAT_TOOLS

        resp = await self._call_llm(full_messages, **kwargs)
        choice = resp.choices[0]

        result = {
            "content": choice.message.content or "",
            "tool_calls": None,
            "usage": {
                "prompt_tokens": resp.usage.prompt_tokens if resp.usage else 0,
                "completion_tokens": resp.usage.completion_tokens if resp.usage else 0,
            },
        }

        if choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "name": tc.function.name,
                    "arguments": json.loads(tc.function.arguments),
                }
                for tc in choice.message.tool_calls
            ]

        return result
