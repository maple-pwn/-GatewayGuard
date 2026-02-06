"""GatewayGuard - FastAPI 主入口"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.routers import traffic, anomaly, llm, system


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="GatewayGuard",
    description="LLM驱动的智能网关网络流量分析与异常预警系统",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(traffic.router)
app.include_router(anomaly.router)
app.include_router(llm.router)
app.include_router(system.router)


@app.get("/")
async def root():
    return {
        "name": "GatewayGuard",
        "version": "0.1.0",
        "description": "智能网关网络流量分析与异常预警系统",
    }
