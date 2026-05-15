let packetCountValue;
let alertCountValue;
let clock;
let chatList;
let chatInput;
let logsPanel;
let aboutPanel;
let consolePanel;
let relayUrlInput;
let relayKeyInput;
let relayStatusText;

const DEFAULT_RELAY_URL = "http://114.55.164.250:8000";

const state = {
  sessionId: Math.random().toString(36).slice(2, 10),
  messages: []
};

function esc(v) {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function pretty(v) {
  try {
    return JSON.stringify(v, null, 2);
  } catch (_) {
    return String(v);
  }
}

function isObject(v) {
  return v && typeof v === "object" && !Array.isArray(v);
}

function metricCard(label, value) {
  return `
    <div class="metric-card">
      <div class="metric-k">${esc(label)}</div>
      <div class="metric-v">${esc(value ?? "-")}</div>
    </div>
  `;
}

function kvCard(label, value) {
  return `
    <div class="kv-card">
      <div class="kv-k">${esc(label)}</div>
      <div class="kv-v">${esc(value ?? "-")}</div>
    </div>
  `;
}

function detailBox(label, value) {
  return `
    <div class="detail-box">
      <div class="detail-head">${esc(label)}</div>
      <div class="detail-body">${esc(typeof value === "string" ? value : pretty(value))}</div>
    </div>
  `;
}

function extractCount(value, ...keys) {
  if (!isObject(value)) return null;
  for (const key of keys) {
    if (value[key] !== undefined && value[key] !== null) return value[key];
  }
  return null;
}

function formatHm(value) {
  if (value === null || value === undefined || value === "") return "--:--";
  const num = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(num)) return "--:--";
  const d = new Date(num * 1000);
  if (Number.isNaN(d.getTime())) return "--:--";
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

function trafficItemHtml(item, index) {
  const title = item.anomaly_type || item.description || `异常流量 ${index + 1}`;
  const first = item.first_seen ?? item.timestamp;
  const last = item.last_seen;
  const timeText = last !== undefined && last !== null
    ? `${formatHm(first)} - ${formatHm(last)}`
    : formatHm(first);
  const chips = [
    item.severity ? `级别 ${item.severity}` : null,
    item.confidence !== undefined && item.confidence !== null ? `置信度 ${item.confidence}` : null,
    item.packet_count !== undefined && item.packet_count !== null ? `${item.packet_count} 条报文` : null,
    item.protocol ? item.protocol : null,
    item.event_id ? `事件 ${item.event_id}` : null
  ].filter(Boolean);

  return `
    <div class="traffic-item">
      <div class="traffic-top">
        <div class="traffic-title">${esc(title)}</div>
        <div class="traffic-time">${esc(timeText)}</div>
      </div>
      <div class="traffic-meta">
        ${chips.map((chip) => `<div class="traffic-chip">${esc(chip)}</div>`).join("")}
      </div>
      <div class="traffic-desc">${esc(item.description || "该条流量已被检测器标记为异常。")}</div>
    </div>
  `;
}

function trafficListHtml(title, items) {
  if (!items.length) {
    return detailBox(title, "当前没有可展示的异常流量。");
  }
  return `
    <div class="detail-box">
      <div class="detail-head">${esc(title)}</div>
      <div class="traffic-list">
        ${items.map((item, index) => trafficItemHtml(item, index)).join("")}
      </div>
    </div>
  `;
}

function renderConsoleHtml(title, data) {
  if (typeof data === "string") {
    return `
      <div class="result-stack">
        <div class="result-banner">
          <div>
            <div class="result-title">${esc(title)}</div>
            <div class="result-subtitle">返回了文本结果</div>
          </div>
        </div>
        ${detailBox("详细信息", data)}
      </div>
    `;
  }

  if (title === "控制台" && isObject(data)) {
    const health = data.health || {};
    const system = data.system || {};
    const stats = data.stats || {};
    return `
      <div class="result-stack">
        <div class="result-banner">
          <div>
            <div class="result-title">模拟控制台总览</div>
            <div class="result-subtitle">汇总当前后端、运行环境和流量状态</div>
          </div>
          <div class="result-pill">${esc(health.status || "未知")}</div>
        </div>
        <div class="metric-grid">
          ${metricCard("报文总数", extractCount(stats, "total_packets", "total", "count") ?? 0)}
          ${metricCard("报警数量", extractCount(stats, "alerts", "anomaly_count") ?? 0)}
          ${metricCard("后端状态", health.status || "未知")}
        </div>
        <div class="kv-grid">
          ${kvCard("监听地址", system.bind || system.host || "未提供")}
          ${kvCard("模型提供方", system.llm_provider || "未配置")}
          ${kvCard("API Key 状态", system.llm_has_api_key ? "已写入" : "未写入")}
          ${kvCard("运行模式", system.mode || system.env || "未提供")}
        </div>
        ${detailBox("原始状态", data)}
      </div>
    `;
  }

  if (title === "模拟流量" && isObject(data)) {
    return `
      <div class="result-stack">
        <div class="result-banner">
          <div>
            <div class="result-title">模拟流量已提交</div>
            <div class="result-subtitle">已向后端发送报文生成请求</div>
          </div>
          <div class="result-pill">${esc(data.scenario || "已执行")}</div>
        </div>
        <div class="metric-grid">
          ${metricCard("生成数量", extractCount(data, "count", "generated", "packets", "total") ?? "-")}
          ${metricCard("场景", data.scenario || "-")}
          ${metricCard("结果", data.status || "完成")}
        </div>
        ${detailBox("详细结果", data)}
      </div>
    `;
  }

  if (title === "训练检测器" && isObject(data)) {
    return `
      <div class="result-stack">
        <div class="result-banner">
          <div>
            <div class="result-title">训练任务已完成</div>
            <div class="result-subtitle">检测器训练结果如下</div>
          </div>
          <div class="result-pill">${esc(data.status || "完成")}</div>
        </div>
        <div class="metric-grid">
          ${metricCard("训练样本", extractCount(data, "train_count", "samples", "records", "count") ?? "-")}
          ${metricCard("模型数量", extractCount(data, "models", "model_count") ?? "-")}
          ${metricCard("结果", data.message || data.status || "-")}
        </div>
        ${detailBox("训练详情", data)}
      </div>
    `;
  }

  if (title === "异常检测" && isObject(data)) {
    const items = Array.isArray(data.aggregated_events)
      ? data.aggregated_events
      : Array.isArray(data.alerts)
        ? data.alerts
        : [];
    const detectedCount = typeof data.detected === "number"
      ? data.detected
      : Array.isArray(data.alerts)
        ? data.alerts.length
        : Array.isArray(data.aggregated_events)
          ? data.aggregated_events.length
          : 0;
    return `
      <div class="result-stack">
        <div class="result-banner">
          <div>
            <div class="result-title">流量检测完成</div>
            <div class="result-subtitle">已返回最新检测结果</div>
          </div>
          <div class="result-pill">${esc(data.status || "完成")}</div>
        </div>
        <div class="metric-grid">
          ${metricCard("异常数量", detectedCount)}
          ${metricCard("检测范围", extractCount(data, "scanned", "checked", "processed", "limit") ?? "-")}
          ${metricCard("结果", data.message || data.status || "-")}
        </div>
        ${trafficListHtml("逐条异常流量", items)}
      </div>
    `;
  }

  if (title === "流量统计" && isObject(data)) {
    const pills = Object.entries(data)
      .slice(0, 4)
      .map(([key, value]) => `<div class="result-pill">${esc(`${key}: ${value}`)}</div>`)
      .join("");
    return `
      <div class="result-stack">
        <div class="result-banner">
          <div>
            <div class="result-title">流量统计</div>
            <div class="result-subtitle">当前已采集的报文与事件概览</div>
          </div>
        </div>
        <div class="result-pills">${pills}</div>
        <div class="kv-grid">
          ${Object.entries(data).map(([key, value]) => kvCard(key, value)).join("")}
        </div>
      </div>
    `;
  }

  if (title === "实时流量" && isObject(data)) {
    return `
      <div class="result-stack">
        <div class="result-banner">
          <div>
            <div class="result-title">实时流量</div>
            <div class="result-subtitle">当前采集器的运行状态</div>
          </div>
          <div class="result-pill">${esc(data.running ? "运行中" : "未运行")}</div>
        </div>
        <div class="kv-grid">
          ${Object.entries(data).map(([key, value]) => kvCard(key, value)).join("")}
        </div>
      </div>
    `;
  }

  return `
    <div class="result-stack">
      <div class="result-banner">
        <div>
          <div class="result-title">${esc(title)}</div>
          <div class="result-subtitle">已返回结果</div>
        </div>
      </div>
      ${detailBox("详细信息", data)}
    </div>
  `;
}

async function req(url, method = "GET", body = null) {
  const options = { method, headers: {} };
  if (body !== null) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(url, options);
  const text = await response.text();
  let data = text;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (_) {}
  if (!response.ok) throw { status: response.status, body: data };
  return data;
}

function errText(e) {
  if (!e) return "未知错误";
  if (e.body && typeof e.body === "object" && e.body.detail) {
    return typeof e.body.detail === "string" ? e.body.detail : pretty(e.body.detail);
  }
  if (typeof e.body === "string") return e.body;
  if (e.message) return e.message;
  return pretty(e);
}

function relayBody(enabled = true) {
  return {
    target_url: relayUrlInput.value.trim() || DEFAULT_RELAY_URL,
    enabled,
    api_key: relayKeyInput.value.trim(),
    device_name: "Android Gateway UI"
  };
}

function saveRelayInputs() {
  localStorage.setItem("gatewayguardRelayUrl", relayUrlInput.value.trim() || DEFAULT_RELAY_URL);
  localStorage.setItem("gatewayguardRelayKey", relayKeyInput.value.trim());
}

function updateRelayStatusText(data) {
  if (!relayStatusText) return;
  if (typeof data === "string") {
    relayStatusText.textContent = data;
    return;
  }
  const queued = (data.queued_packets || 0) + (data.queued_alerts || 0);
  const sent = (data.sent_packets || 0) + (data.sent_alerts || 0);
  const failed = data.failed_batches || 0;
  const error = data.last_error ? ` | ${data.last_error}` : "";
  relayStatusText.textContent = `Relay: ${data.enabled ? "on" : "off"} | queued ${queued} | sent ${sent} | failed ${failed}${error}`;
}

async function refreshRelayStatus(showResult = false) {
  try {
    const data = await req("/api/mobile/sync/status");
    if (data.target_url && relayUrlInput && !relayUrlInput.value.trim()) {
      relayUrlInput.value = data.target_url;
    }
    updateRelayStatusText(data);
    if (showResult) {
      switchPage("console");
      renderResult("Relay Sync", data);
    }
    return data;
  } catch (e) {
    const message = errText(e);
    updateRelayStatusText(`Relay: status failed | ${message}`);
    if (showResult) {
      switchPage("console");
      renderResult("Relay Sync", message);
    }
    return null;
  }
}

async function testRelay() {
  saveRelayInputs();
  switchPage("console");
  try {
    const data = await req("/api/mobile/sync/test", "POST", {
      target_url: relayUrlInput.value.trim() || DEFAULT_RELAY_URL
    });
    updateRelayStatusText(data.ok ? `Relay: reachable | ${data.target_url}` : `Relay: failed | ${data.error || "unknown"}`);
    renderResult("Relay Test", data);
  } catch (e) {
    const message = errText(e);
    updateRelayStatusText(`Relay: test failed | ${message}`);
    renderResult("Relay Test", message);
  }
}

async function enableRelay() {
  saveRelayInputs();
  switchPage("console");
  try {
    const data = await req("/api/mobile/sync/config", "POST", relayBody(true));
    updateRelayStatusText(data);
    renderResult("Relay Sync", data);
  } catch (e) {
    const message = errText(e);
    updateRelayStatusText(`Relay: sync failed | ${message}`);
    renderResult("Relay Sync", message);
  }
}

async function stopRelay() {
  saveRelayInputs();
  switchPage("console");
  try {
    const data = await req("/api/mobile/sync/config", "POST", relayBody(false));
    updateRelayStatusText(data);
    renderResult("Relay Stop", data);
  } catch (e) {
    const message = errText(e);
    updateRelayStatusText(`Relay: stop failed | ${message}`);
    renderResult("Relay Stop", message);
  }
}

function renderResult(title, data) {
  const text = typeof data === "string" ? data : pretty(data);
  if (title === "控制台" || title === "模拟流量" || title === "训练检测器" || title === "异常检测" || title === "流量统计" || title === "实时流量" || title.startsWith("Relay")) {
    consolePanel.innerHTML = renderConsoleHtml(title, data);
  }
  if (title === "最近日志") logsPanel.textContent = text;
  if (title === "关于我们") aboutPanel.textContent = text;
  if (title.includes("API Key")) consolePanel.innerHTML = renderConsoleHtml(title, data);
}

function renderChat() {
  chatList.innerHTML = state.messages.map((msg) => `
    <div class="chat-msg ${esc(msg.role)}">
      <div class="chat-role">${esc(msg.role === "user" ? "分析员" : "AI 助手")}</div>
      <div class="chat-text">${esc(msg.content || "（空响应）")}</div>
    </div>
  `).join("");
  chatList.scrollTop = chatList.scrollHeight;
}

async function refreshStats() {
  try {
    const [health, stats, anomalies] = await Promise.all([
      req("/health/ready"),
      req("/api/traffic/stats"),
      req("/api/anomaly/events?limit=1")
    ]);
    packetCountValue.textContent = String(stats.total_packets || 0);
    alertCountValue.textContent = String(anomalies.total || 0);
  } catch (e) {
    renderResult("状态刷新失败", errText(e));
  }
}

async function showConsole() {
  switchPage("console");
  try {
    const [health, system, stats] = await Promise.all([
      req("/health/ready"),
      req("/api/system/status"),
      req("/api/traffic/stats")
    ]);
    renderResult("控制台", { health, system, stats });
  } catch (e) {
    renderResult("控制台", errText(e));
  }
}

async function showLogs() {
  switchPage("logs");
  try {
    const data = await req("/api/system/logs/recent?lines=160");
    renderResult("最近日志", data.content || "(暂无日志)");
  } catch (e) {
    renderResult("日志读取失败", errText(e));
  }
}

function showAbout() {
  switchPage("about");
  renderResult("关于我们", [
    "GatewayGuard 面向车载流量安全检测与分析。",
    "当前主界面为 AI 助手聊天，侧边栏用于切换页面。",
    "你可以先写入 API Key，再直接向助手提问。"
  ].join("\n"));
}

async function saveApiKey() {
  const input = document.getElementById("apiKeyInput");
  const apiKey = input.value.trim();
  if (!apiKey) {
    renderResult("写入 API Key 失败", "请输入有效的 API Key。");
    return;
  }
  try {
    const data = await req("/api/system/api-key", "POST", {
      api_key: apiKey,
      provider: "openai"
    });
    switchPage("console");
    renderResult("API Key 已写入", data);
  } catch (e) {
    switchPage("console");
    renderResult("写入 API Key 失败", errText(e));
  }
}

async function ensureApiKeyConfigured() {
  const input = document.getElementById("apiKeyInput");
  const apiKey = input.value.trim();
  if (!apiKey) return;

  try {
    const status = await req("/api/system/status");
    if (status.llm_has_api_key) return;
  } catch (_) {
    return;
  }

  try {
    await req("/api/system/api-key", "POST", {
      api_key: apiKey,
      provider: "openai"
    });
  } catch (_) {
    // Keep startup quiet; chat page will surface real errors if LLM remains unavailable.
  }
}

async function simulateTraffic() {
  switchPage("console");
  const scenario = document.getElementById("scenario").value;
  const count = document.getElementById("count").value || "120";
  try {
    const data = await req(`/api/traffic/simulate?scenario=${encodeURIComponent(scenario)}&count=${encodeURIComponent(count)}`, "POST");
    renderResult("模拟流量", data);
    await refreshStats();
    await refreshRelayStatus(false);
  } catch (e) {
    renderResult("模拟流量", errText(e));
  }
}

async function trainDetector() {
  switchPage("console");
  try {
    const data = await req("/api/anomaly/train?limit=2000", "POST");
    renderResult("训练检测器", data);
    await refreshStats();
  } catch (e) {
    renderResult("训练检测器", errText(e));
  }
}

async function detectAnomalies() {
  switchPage("console");
  try {
    const data = await req("/api/anomaly/detect?limit=500", "POST");
    renderResult("异常检测", data);
    await refreshStats();
  } catch (e) {
    renderResult("异常检测", errText(e));
  }
}

async function showTrafficStats() {
  switchPage("console");
  try {
    const data = await req("/api/traffic/stats");
    renderResult("流量统计", data);
  } catch (e) {
    renderResult("流量统计", errText(e));
  }
}

async function startRealtimeTraffic() {
  switchPage("console");
  try {
    const data = await req("/api/traffic/collect/start?mode=simulator", "POST");
    renderResult("实时流量", data);
    await refreshRelayStatus(false);
  } catch (e) {
    renderResult("实时流量", errText(e));
  }
}

async function showRealtimeStatus() {
  switchPage("console");
  try {
    const data = await req("/api/traffic/collect/status");
    renderResult("实时流量", data);
  } catch (e) {
    renderResult("实时流量", errText(e));
  }
}

async function sendChat() {
  const message = chatInput.value.trim();
  if (!message) return;

  state.messages.push({ role: "user", content: message });
  renderChat();
  chatInput.value = "";

  try {
    const result = await req(
      `/api/llm/chat?message=${encodeURIComponent(message)}&session_id=${encodeURIComponent(state.sessionId)}`,
      "POST"
    );
    state.sessionId = result.session_id || state.sessionId;
    state.messages.push({
      role: "assistant",
      content: result.response || "（空响应）"
    });
    renderChat();
    await refreshStats();
  } catch (e) {
    state.messages.push({
      role: "assistant",
      content: `对话请求失败：${errText(e)}`
    });
    renderChat();
    renderResult("AI 助手请求失败", errText(e));
  }
}

function resetChat() {
  state.sessionId = Math.random().toString(36).slice(2, 10);
  state.messages = [
    {
      role: "assistant",
      content: "已开始新的 AI 助手会话。你可以重新提问。"
    }
  ];
  renderChat();
}

function switchPage(page) {
  document.querySelectorAll(".page-panel").forEach((el) => {
    el.classList.toggle("active", el.id === `page${page[0].toUpperCase()}${page.slice(1)}`);
  });
  document.querySelectorAll(".sidebar-actions .sidebar-btn").forEach((el) => {
    el.classList.remove("active");
  });
  const activeBtnMap = {
    chat: "btnChatPage",
    console: "btnConsole",
    logs: "btnLogs",
    about: "btnAbout"
  };
  const activeBtn = document.getElementById(activeBtnMap[page]);
  if (activeBtn) activeBtn.classList.add("active");
}

function tickClock() {
  const d = new Date();
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  clock.textContent = `${hh}:${mm}`;
}

document.addEventListener("DOMContentLoaded", async () => {
  packetCountValue = document.getElementById("packetCountValue");
  alertCountValue = document.getElementById("alertCountValue");
  clock = document.getElementById("clock");
  chatList = document.getElementById("chatList");
  chatInput = document.getElementById("chatInput");
  logsPanel = document.getElementById("logsPanel");
  aboutPanel = document.getElementById("aboutPanel");
  consolePanel = document.getElementById("consolePanel");
  relayUrlInput = document.getElementById("relayUrlInput");
  relayKeyInput = document.getElementById("relayKeyInput");
  relayStatusText = document.getElementById("relayStatusText");

  relayUrlInput.value = localStorage.getItem("gatewayguardRelayUrl") || DEFAULT_RELAY_URL;
  relayKeyInput.value = localStorage.getItem("gatewayguardRelayKey") || "";

  document.getElementById("btnChatPage").addEventListener("click", () => switchPage("chat"));
  document.getElementById("btnConsole").addEventListener("click", showConsole);
  document.getElementById("btnLogs").addEventListener("click", showLogs);
  document.getElementById("btnAbout").addEventListener("click", showAbout);
  document.getElementById("btnSaveApiKey").addEventListener("click", saveApiKey);
  document.getElementById("btnSimulate").addEventListener("click", simulateTraffic);
  document.getElementById("btnTrain").addEventListener("click", trainDetector);
  document.getElementById("btnDetect").addEventListener("click", detectAnomalies);
  document.getElementById("btnStats").addEventListener("click", showTrafficStats);
  document.getElementById("btnRealtimeStart").addEventListener("click", startRealtimeTraffic);
  document.getElementById("btnRealtimeStatus").addEventListener("click", showRealtimeStatus);
  document.getElementById("btnSendChat").addEventListener("click", sendChat);
  document.getElementById("btnResetChat").addEventListener("click", resetChat);
  document.getElementById("btnRelayTest").addEventListener("click", testRelay);
  document.getElementById("btnRelaySync").addEventListener("click", enableRelay);
  document.getElementById("btnRelayStatus").addEventListener("click", () => refreshRelayStatus(true));
  document.getElementById("btnRelayStop").addEventListener("click", stopRelay);

  renderChat();
  switchPage("chat");
  tickClock();
  setInterval(tickClock, 1000);
  await ensureApiKeyConfigured();
  await refreshStats();
  await refreshRelayStatus(false);
});
