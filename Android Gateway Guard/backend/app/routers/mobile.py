"""Android remote sync control endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from app.services.remote_sync import remote_sync

router = APIRouter(prefix="/api/mobile", tags=["mobile"])


class SyncConfigRequest(BaseModel):
    target_url: str = ""
    enabled: bool = True
    api_key: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None


class SyncTestRequest(BaseModel):
    target_url: Optional[str] = None


@router.get("/sync/status")
async def sync_status():
    return remote_sync.status


@router.post("/sync/config")
async def configure_sync(payload: SyncConfigRequest):
    return remote_sync.configure(
        target_url=payload.target_url,
        enabled=payload.enabled,
        device_id=payload.device_id,
        device_name=payload.device_name,
        api_key=payload.api_key,
    )


@router.post("/sync/test")
async def test_sync(payload: SyncTestRequest):
    return await remote_sync.test_connection(payload.target_url)
