# GatewayGuard

**基于大语言模型的智能网关网络流量分析与异常预警系统**

以智能网联汽车网关为核心场景，集多协议流量解析、两级异常检测、LLM 语义分析、交互式安全问答于一体的网络安全分析平台。

---

## 目录

- [项目背景](#项目背景)
- [系统架构](#系统架构)
- [核心功能](#核心功能)
- [技术栈](#技术栈)
- [项目结构](#项目结构)
- [环境要求](#环境要求)
- [安装与启动](#安装与启动)
- [使用流程](#使用流程)
- [API 接口说明](#api-接口说明)
- [数据库设计](#数据库设计)
- [LLM 集成说明](#llm-集成说明)
- [异常检测算法](#异常检测算法)

---

## 项目背景

随着智能网联汽车的发展，车载网关承载了 CAN 总线、车载以太网、V2X 等多种协议的流量转发与安全防护职责。传统基于规则/阈值的入侵检测系统存在以下局限：

- 告警信息缺乏语义解释，安全人员需要大量经验才能判断威胁等级
- 无法自动生成结构化的预警报告与处置建议
- 多协议融合场景下的关联分析能力不足

本项目引入大语言模型（LLM），将其作为系统的核心分析引擎，实现：

1. **异常事件语义分析**：对检测到的异常自动进行攻击分类、影响评估、溯源分析，生成可解释的预警报告
2. **交互式安全问答**：安全人员通过自然语言查询网络状态、分析攻击事件、获取处置建议，LLM 通过 Function Calling 机制调用后端 API 获取实时数据

---

## 系统架构

```
┌─────────────────────────────────────────────────────┐
│                   Vue 3 前端                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
│  │ 流量监控  │ │ 告警中心  │ │ LLM 交互式分析面板   │ │
│  │ Dashboard │ │  Anomaly │ │  (Chat Interface)    │ │
│  └──────────┘ └──────────┘ └──────────────────────┘ │
└───────────────────────┬─────────────────────────────┘
                        │ REST API
┌───────────────────────┴─────────────────────────────┐
│                 FastAPI 后端                          │
│                                                      │
│  ┌─────────────┐ ┌─────────────┐ ┌───────────────┐  │
│  │ 流量采集与   │ │  异常检测    │ │  LLM 分析     │  │
│  │ 协议解析模块 │ │  引擎       │ │  引擎         │  │
│  │             │ │ (规则+ML)   │ │ (OpenAI/      │  │
│  │ CAN/ETH/V2X│ │ IForest     │ │  Ollama)      │  │
│  └──────┬──────┘ └──────┬──────┘ └───────┬───────┘  │
│         │               │                │           │
│  ┌──────┴───────────────┴────────────────┴───────┐  │
│  │         统一数据层 (SQLite + aiosqlite)         │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 核心功能

### 1. 多协议流量模拟与解析

- **CAN 总线**：模拟 12 种 ECU 报文（发动机、变速箱、ABS、EPS 等），支持 DoS / Fuzzy / Spoofing 三种攻击场景
- **车载以太网**：基于 SOME/IP 协议模拟 7 种服务通信（摄像头、雷达、ADAS、OTA 等）
- **V2X 通信**：模拟 BSM / MAP / SPAT 三种消息类型

所有协议流量统一解析为 `UnifiedPacket` 数据模型，实现跨协议的统一分析。

### 2. 两级异常检测

**第一级 — 规则引擎（快速过滤）**：
- 报文频率异常检测（DoS 攻击特征）
- 未知 CAN ID 检测（Fuzzy 攻击特征）
- 负载模式异常检测（Spoofing 攻击特征）

**第二级 — ML 模型（深度分析）**：
- Isolation Forest 无监督异常检测
- 特征向量：报文 ID、负载长度、字节熵、协议类型、功能域
- 自动训练 + 在线推理

### 3. LLM 语义分析

- **异常事件分析**：对告警事件进行攻击分类、影响评估、攻击意图判断、处置建议生成
- **预警报告生成**：自动汇总多条异常事件，生成结构化安全预警报告
- **交互式问答**：通过 Function Calling 机制，LLM 可主动调用后端 API 查询流量统计和异常事件，实现数据驱动的智能问答

### 4. 前端可视化

- **Dashboard**：流量统计概览、协议分布、攻击场景选择、一键模拟与检测
- **告警中心**：异常事件列表、严重程度筛选、单事件 AI 分析、预警报告生成
- **AI 分析助手**：多轮对话界面，支持自然语言安全分析

---

## 技术栈

| 层级 | 技术选型 | 说明 |
|------|----------|------|
| 前端 | Vue 3 + Vite + Element Plus | SPA 应用，响应式布局 |
| 后端 | Python 3.12 + FastAPI + Uvicorn | 异步 API 服务 |
| LLM | OpenAI API / Ollama | 双模式切换，支持云端与本地部署 |
| ML | scikit-learn (Isolation Forest) | 无监督异常检测 |
| ORM | SQLAlchemy 2.0 + aiosqlite | 异步数据库操作 |
| 数据库 | SQLite | 轻量级，零配置 |
| 流量解析 | Scapy + python-can | 多协议报文构造与解析 |

---

## 项目结构

```
gateway-guard/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI 入口，CORS、路由注册
│   │   ├── config.py               # 配置管理（LLM/检测器/应用）
│   │   ├── database.py             # 异步数据库引擎与会话管理
│   │   ├── models/                 # 数据模型（ORM + Pydantic）
│   │   │   ├── packet.py           # 流量报文模型
│   │   │   ├── anomaly.py          # 异常事件模型
│   │   │   └── report.py           # 分析报告与对话历史模型
│   │   ├── routers/                # API 路由
│   │   │   ├── traffic.py          # 流量模拟与查询 API
│   │   │   ├── anomaly.py          # 异常检测与事件查询 API
│   │   │   ├── llm.py              # LLM 分析与对话 API
│   │   │   └── system.py           # 系统状态 API
│   │   ├── services/               # 核心业务逻辑
│   │   │   ├── traffic_parser.py   # 多协议统一解析服务
│   │   │   ├── anomaly_detector.py # 两级异常检测引擎
│   │   │   └── llm_engine.py       # LLM 分析引擎（含 Function Calling）
│   │   ├── simulators/             # 流量模拟器
│   │   │   ├── can_simulator.py    # CAN 总线模拟（含攻击场景）
│   │   │   ├── eth_simulator.py    # 车载以太网 SOME/IP 模拟
│   │   │   └── v2x_simulator.py    # V2X BSM/MAP/SPAT 模拟
│   │   └── utils/
│   │       ├── prompt_templates.py # LLM Prompt 模板集中管理
│   │       └── tools.py            # Function Calling 工具定义
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.vue                 # 主布局（侧边栏导航）
│   │   ├── main.js                 # Vue 应用入口
│   │   ├── router.js               # 路由配置
│   │   ├── api/
│   │   │   └── index.js            # Axios API 封装
│   │   └── views/
│   │       ├── Dashboard.vue       # 流量监控面板
│   │       ├── Anomaly.vue         # 告警中心
│   │       └── Chat.vue            # AI 交互分析
│   ├── index.html
│   ├── package.json
│   └── vite.config.js              # Vite 配置（含 API 代理）
├── start.sh                        # 一键启动脚本
└── README.md
```

---

## 环境要求

- **Python** 3.12+
- **Node.js** 18+
- **LLM 服务**（二选一）：
  - OpenAI API Key（推荐 gpt-4o-mini 或以上）
  - Ollama 本地部署（推荐 qwen2.5:7b）

---

## 安装与启动

### 方式一：一键启动

```bash
# 配置 LLM（二选一）
export OPENAI_API_KEY="sk-your-key"    # OpenAI 模式
# 或
export LLM_PROVIDER="ollama"            # Ollama 本地模式

# 启动
chmod +x start.sh
./start.sh
```

### 方式二：手动启动

**后端：**

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**前端：**

```bash
cd frontend
npm install
npm run dev
```

### 访问地址

| 服务 | 地址 |
|------|------|
| 前端界面 | http://localhost:5173 |
| 后端 API 文档 | http://localhost:8000/docs |
| 后端 API (Redoc) | http://localhost:8000/redoc |

---

## 使用流程

### 步骤 1：生成模拟流量

在 Dashboard 页面选择攻击场景（正常流量 / DoS 攻击 / Fuzzy 攻击 / Spoofing 攻击 / 混合场景），点击「生成模拟流量」。系统将生成 CAN + 以太网 + V2X 多协议混合流量并存入数据库。

### 步骤 2：执行异常检测

点击「执行异常检测」，系统自动执行两级检测：
- 规则引擎快速筛查频率异常、未知 ID、负载异常
- Isolation Forest 模型对全量特征进行无监督异常检测

### 步骤 3：查看告警与 AI 分析

进入告警中心页面：
- 按严重程度、状态筛选异常事件
- 点击单条事件的「AI 分析」按钮，调用 LLM 进行语义分析
- 点击「生成预警报告」，LLM 自动汇总生成结构化安全报告

### 步骤 4：交互式安全问答

进入 AI 分析页面，通过自然语言与系统交互，例如：
- "最近检测到了哪些异常事件？"
- "分析一下 DoS 攻击的特征和影响"
- "当前网络流量的协议分布情况如何？"

LLM 通过 Function Calling 自动调用后端 API 获取实时数据后回答。

---

## API 接口说明

### 流量管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/traffic/simulate` | 生成模拟流量（支持多种攻击场景） |
| GET | `/api/traffic/stats` | 获取流量统计概览 |
| GET | `/api/traffic/packets` | 分页查询流量记录 |

### 异常检测

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/anomaly/detect` | 触发异常检测 |
| GET | `/api/anomaly/events` | 查询异常事件列表（支持筛选） |
| GET | `/api/anomaly/events/{id}` | 获取单条异常事件详情 |

### LLM 分析

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/llm/analyze` | 对指定异常事件进行 LLM 语义分析 |
| POST | `/api/llm/report` | 生成安全预警报告 |
| POST | `/api/llm/chat` | 交互式安全问答（支持 Function Calling） |

### 系统

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/system/status` | 获取系统运行状态 |

---

## 数据库设计

系统使用 SQLite 作为持久化存储，包含 4 张核心表：

| 表名 | 说明 |
|------|------|
| `packets` | 流量报文记录（时间戳、协议、源/目标、报文ID、负载、功能域） |
| `anomaly_events` | 异常事件（类型、严重程度、置信度、检测方法、状态） |
| `analysis_reports` | LLM 分析报告（关联事件ID、报告内容、模型信息、Token 用量） |
| `chat_history` | 对话历史（会话ID、角色、内容、工具调用记录） |

---

## LLM 集成说明

### 双模式支持

| 模式 | 配置方式 | 适用场景 |
|------|----------|----------|
| OpenAI | `export OPENAI_API_KEY="sk-xxx"` | 分析能力强，需联网 |
| Ollama | `export LLM_PROVIDER="ollama"` | 本地部署，离线可用 |

### Prompt 工程

所有 Prompt 模板集中管理在 `utils/prompt_templates.py`：

- **SYSTEM_PROMPT**：系统角色设定（车载网络安全专家）
- **ANOMALY_ANALYSIS_PROMPT**：异常事件语义分析模板，输出结构化 JSON
- **REPORT_GENERATION_PROMPT**：预警报告生成模板

### Function Calling

交互式问答模式下，LLM 可调用以下工具函数获取实时数据：

| 工具函数 | 说明 |
|----------|------|
| `query_traffic_stats` | 查询流量统计信息 |
| `get_anomaly_events` | 获取异常事件列表 |

---

## 异常检测算法

### 规则引擎

| 规则 | 检测目标 | 攻击类型 |
|------|----------|----------|
| 频率异常检测 | 单 ID 报文频率超过均值 N 倍 | DoS 攻击 |
| 未知 ID 检测 | CAN ID 不在白名单内 | Fuzzy 攻击 |
| 负载模式检测 | 负载字节全部相同（如全 0xFF） | Spoofing 攻击 |

### Isolation Forest

- **算法**：基于随机森林的无监督异常检测，通过隔离路径长度判断异常程度
- **特征向量**：`[msg_id_num, payload_len, byte_entropy, protocol, domain]`
- **训练方式**：使用正常流量自动训练，无需标注数据
- **污染率**：默认 5%（可配置）

---

## 配置参数

主要配置通过环境变量和 `app/config.py` 管理：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `OPENAI_API_KEY` | - | OpenAI API 密钥 |
| `LLM_PROVIDER` | `openai` | LLM 提供商（openai / ollama） |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama 服务地址 |
| 检测器频率阈值 | `3.0` | 频率异常判定倍数 |
| IForest 污染率 | `0.05` | Isolation Forest contamination 参数 |
| LLM temperature | `0.3` | 生成温度（低值更确定性） |
| LLM max_tokens | `2048` | 单次生成最大 Token 数 |
