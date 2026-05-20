<template>
  <div class="chat-layout">
    <section v-if="isImmersive" class="section-block">
      <el-row :gutter="18">
        <el-col v-for="item in overviewCards" :key="item.label" :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card" shadow="never">
            <div class="metric-card__label">{{ item.label }}</div>
            <div class="metric-card__value">{{ item.value }}</div>
            <div class="metric-card__meta">{{ item.meta }}</div>
          </el-card>
        </el-col>
      </el-row>
    </section>

    <section class="panel-card chat-panel">
      <div ref="msgBox" class="message-list">
        <div v-if="!messages.length" class="chat-empty">
          <div>
            <div class="chat-empty__title">从一个具体问题开始</div>
            <div class="chat-empty__desc">
              例如：请结合当前异常事件，给出优先排查顺序和可能的攻击意图。
            </div>
          </div>
        </div>

        <div
          v-for="(msg, i) in messages"
          :key="i"
          class="message-row"
          :class="{ 'message-row--user': msg.role === 'user' }"
        >
          <div class="message-bubble">
            <div class="message-bubble__role">
              {{ msg.role === 'user' ? '分析员' : 'AI 助手' }}
            </div>
            <div class="message-bubble__text">{{ msg.content }}</div>
          </div>
        </div>

        <div v-if="loading" class="chat-loading">
          <el-icon class="is-loading"><Loading /></el-icon>
          <span>AI 正在分析...</span>
        </div>
      </div>

      <div class="composer">
        <el-input
          v-model="input"
          type="textarea"
          :rows="5"
          resize="none"
          placeholder="例如：请根据最近异常事件判断后端是否稳定，并给出下一步排查建议。"
          @keydown.enter.exact.prevent="sendMessage"
          :disabled="loading"
        />
        <div class="composer-actions">
          <span>Enter 发送，Shift + Enter 换行</span>
          <el-button class="send-message-btn" type="primary" @click="sendMessage" :loading="loading">
            发送消息
          </el-button>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { Loading } from '@element-plus/icons-vue'
import { anomalyApi, llmApi, trafficApi } from '../api/index.js'

const route = useRoute()
const CHAT_SESSION_STORAGE_KEY = 'gatewayGuardChatSessionId'
const CHAT_MESSAGES_STORAGE_KEY = 'gatewayGuardChatMessages'

function randomSessionId() {
  return Math.random().toString(36).slice(2, 10)
}

function getStoredSessionId() {
  if (typeof window === 'undefined') {
    return randomSessionId()
  }
  const existing = window.localStorage.getItem(CHAT_SESSION_STORAGE_KEY)
  if (existing) {
    return existing
  }
  const nextSessionId = randomSessionId()
  window.localStorage.setItem(CHAT_SESSION_STORAGE_KEY, nextSessionId)
  return nextSessionId
}

function loadStoredMessages() {
  if (typeof window === 'undefined') {
    return []
  }
  try {
    const parsed = JSON.parse(window.localStorage.getItem(CHAT_MESSAGES_STORAGE_KEY) || '[]')
    if (!Array.isArray(parsed)) {
      return []
    }
    return parsed
      .filter((item) => (
        (item?.role === 'user' || item?.role === 'assistant') &&
        typeof item?.content === 'string'
      ))
      .map((item) => ({ ...item, content: plainTextResponse(item.content) }))
  } catch {
    return []
  }
}

function saveStoredMessages() {
  if (typeof window === 'undefined') {
    return
  }
  window.localStorage.setItem(
    CHAT_MESSAGES_STORAGE_KEY,
    JSON.stringify(messages.value.slice(-40)),
  )
}

const input = ref('')
const messages = ref([])
const loading = ref(false)
const msgBox = ref(null)
const sessionId = ref(getStoredSessionId())
const stats = ref({
  totalPackets: 0,
  alertCount: 0,
})
const clockLabel = ref('--:--')
let statsTimer = null
let clockTimer = null

const isImmersive = computed(() => route.meta.shell === 'immersive')
const overviewCards = computed(() => ([
  {
    label: '总报文数',
    value: stats.value.totalPackets,
    meta: '当前平台已接入并累计记录的流量规模',
  },
  {
    label: '异常事件',
    value: stats.value.alertCount,
    meta: '最近事件流中已识别的异常告警总量',
  },
  {
    label: '当前模块',
    value: 'LLM',
    meta: '当前所在工作区与分析上下文标识',
  },
  {
    label: '本地时间',
    value: clockLabel.value,
    meta: '用于对齐事件时间线与实时研判节奏',
  },
]))

function applyPrompt(text) {
  input.value = text
}

function plainTextResponse(value) {
  return String(value || '')
    .replace(/\r\n/g, '\n')
    .replace(/```[A-Za-z0-9_-]*\s*\n?([\s\S]*?)\n?```/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/^\s{0,3}#{1,6}\s*/gm, '')
    .replace(/^\s{0,3}>\s?/gm, '')
    .replace(/^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/gm, '')
    .replace(/^\s*[-*+]\s+/gm, '')
    .replace(/^\s*\d+[.)]\s+/gm, '')
    .replace(/(\*\*|__)(.*?)\1/g, '$2')
    .replace(/(^|[^\*])\*([^\s][^*]*?[^\s])\*(?!\*)/g, '$1$2')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

function updateClock() {
  const now = new Date()
  const hh = String(now.getHours()).padStart(2, '0')
  const mm = String(now.getMinutes()).padStart(2, '0')
  clockLabel.value = `${hh}:${mm}`
}

async function refreshOverview() {
  try {
    const [statsRes, anomalyRes] = await Promise.all([
      trafficApi.getStats(),
      anomalyApi.getEvents({ limit: 20 }),
    ])
    stats.value = {
      totalPackets: statsRes?.data?.total_packets || 0,
      alertCount: anomalyRes?.data?.total || 0,
    }
  } catch {
    // Keep assistant shell usable even if overview requests fail.
  }
}

async function sendMessage() {
  const text = input.value.trim()
  if (!text || loading.value) return

  messages.value.push({ role: 'user', content: text })
  saveStoredMessages()
  input.value = ''
  loading.value = true
  await scrollBottom()

  try {
    const res = await llmApi.chat(text, sessionId.value)
    messages.value.push({
      role: 'assistant',
      content: plainTextResponse(res.data.response),
    })
    saveStoredMessages()
  } catch {
    messages.value.push({
      role: 'assistant',
      content: 'LLM 调用失败，请检查后端配置。',
    })
    saveStoredMessages()
  } finally {
    loading.value = false
    await scrollBottom()
  }
}

async function scrollBottom() {
  await nextTick()
  if (msgBox.value) {
    msgBox.value.scrollTop = msgBox.value.scrollHeight
  }
}

onMounted(async () => {
  messages.value = loadStoredMessages()
  await scrollBottom()
  updateClock()
  if (isImmersive.value) {
    await refreshOverview()
    statsTimer = setInterval(refreshOverview, 1000 * 20)
    clockTimer = setInterval(updateClock, 1000 * 30)
  }
})

onUnmounted(() => {
  if (statsTimer) clearInterval(statsTimer)
  if (clockTimer) clearInterval(clockTimer)
})
</script>

<style scoped>
.chat-layout {
  display: block;
  min-height: calc(100vh - 220px);
}

.chat-panel {
  display: grid;
  grid-template-rows: minmax(0, 1fr) auto;
  min-height: calc(100vh - 220px);
}

.chat-panel :deep(.el-card__body) {
  display: contents;
}

.message-list {
  min-height: 0;
  overflow: auto;
  padding: 22px 22px 8px;
  display: grid;
  align-content: start;
  gap: 14px;
}

.chat-empty {
  display: grid;
  place-items: center;
  min-height: 300px;
  border: 1px dashed var(--gg-line-strong);
  border-radius: 20px;
  background: linear-gradient(180deg, #f9fbff, #f3f7fc);
  text-align: center;
}

.chat-empty__title {
  color: var(--gg-text-strong);
  font-size: 22px;
  font-family: var(--gg-font-display);
}

.chat-empty__desc {
  margin-top: 10px;
  max-width: 420px;
  color: var(--gg-text-soft);
  line-height: 1.7;
}

.message-row {
  display: flex;
}

.message-row--user {
  justify-content: flex-end;
}

.message-bubble {
  max-width: min(760px, 84%);
  padding: 16px 18px;
  border-radius: 20px;
  border: 1px solid rgba(84, 123, 184, 0.16);
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(245, 249, 255, 0.84)),
    linear-gradient(90deg, rgba(14, 165, 183, 0.06), transparent);
  box-shadow: 0 14px 34px rgba(18, 32, 56, 0.08);
}

.message-row--user .message-bubble {
  position: relative;
  overflow: hidden;
  color: #f5f9ff;
  border-color: rgba(93, 215, 255, 0.34);
  background:
    linear-gradient(135deg, rgba(18, 45, 83, 0.94), rgba(16, 72, 94, 0.86)),
    repeating-linear-gradient(90deg, rgba(93, 215, 255, 0.07) 0, rgba(93, 215, 255, 0.07) 1px, transparent 1px, transparent 22px),
    radial-gradient(260px 140px at 0% 0%, rgba(93, 215, 255, 0.22), transparent 68%);
  box-shadow:
    0 16px 36px rgba(13, 44, 76, 0.22),
    0 0 24px rgba(93, 215, 255, 0.1);
}

.message-row--user .message-bubble::before {
  position: absolute;
  inset: 0;
  pointer-events: none;
  border-radius: inherit;
  background: linear-gradient(90deg, rgba(93, 215, 255, 0.18), transparent 38%, rgba(61, 103, 255, 0.12));
  content: '';
  opacity: 0.72;
}

.message-row--user .message-bubble__role,
.message-row--user .message-bubble__text {
  position: relative;
  z-index: 1;
}

.message-bubble__role {
  margin-bottom: 8px;
  font-size: 12px;
  font-weight: 700;
  color: var(--gg-text-soft);
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.message-row--user .message-bubble__role {
  color: rgba(255, 255, 255, 0.78);
}

.message-bubble__text {
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.75;
}

.chat-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: var(--gg-text-soft);
}

.composer {
  display: grid;
  gap: 12px;
  padding: 18px 22px 22px;
  border-top: 1px solid var(--gg-line);
  background: #fff;
  border-radius: 0 0 22px 22px;
}

.composer-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  color: var(--gg-text-soft);
  font-size: 12px;
}

.send-message-btn {
  --el-button-bg-color: rgba(45, 83, 210, 0.92);
  --el-button-border-color: rgba(93, 215, 255, 0.28);
  --el-button-hover-bg-color: rgba(63, 111, 238, 0.96);
  --el-button-hover-border-color: rgba(119, 225, 255, 0.46);
  --el-button-active-bg-color: rgba(35, 72, 174, 0.96);
  min-width: 124px;
  min-height: 42px;
  border-radius: 999px;
  font-family: var(--gg-font-ui);
  font-weight: 800;
  letter-spacing: 0.06em;
  box-shadow:
    0 14px 30px rgba(45, 83, 210, 0.18),
    inset 0 1px 0 rgba(255, 255, 255, 0.12);
}

:global(.shell--immersive) .message-bubble {
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.075), rgba(255, 255, 255, 0.045)),
    linear-gradient(90deg, rgba(93, 215, 255, 0.08), transparent) !important;
  border-color: rgba(136, 183, 255, 0.14) !important;
  box-shadow: 0 16px 38px rgba(0, 0, 0, 0.22);
}

:global(.shell--immersive) .message-row--user .message-bubble {
  background:
    linear-gradient(135deg, rgba(22, 51, 88, 0.82), rgba(13, 73, 88, 0.64)),
    repeating-linear-gradient(90deg, rgba(93, 215, 255, 0.06) 0, rgba(93, 215, 255, 0.06) 1px, transparent 1px, transparent 22px),
    radial-gradient(260px 140px at 0% 0%, rgba(93, 215, 255, 0.22), transparent 68%) !important;
  border-color: rgba(93, 215, 255, 0.3) !important;
  box-shadow:
    0 16px 38px rgba(0, 0, 0, 0.24),
    0 0 26px rgba(93, 215, 255, 0.08) !important;
}

@media (max-width: 1080px) {
  .chat-layout {
    min-height: auto;
  }

  .chat-panel,
  .message-bubble {
    min-height: auto;
    max-width: 100%;
  }
}
</style>
