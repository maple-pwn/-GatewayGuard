<template>
  <Transition name="shell-swap" mode="out-in">
    <div v-if="isStandaloneHome" key="landing" class="landing-shell">
      <router-view v-slot="{ Component, route: viewRoute }">
        <Transition name="landing-route" mode="out-in">
          <component :is="Component" :key="viewRoute.fullPath" />
        </Transition>
      </router-view>
    </div>

    <div
      v-else
      key="immersive"
      class="shell shell--immersive"
      :class="{ 'shell--critical-alert': criticalFrameActive }"
    >
      <div class="immersive-backdrop" />
      <div class="immersive-veil" />

      <header class="immersive-topbar">
        <div class="immersive-brand">
          <div class="brand-mark">
            <img :src="brandIcon" alt="GatewayGuard" class="brand-mark__icon" />
          </div>
          <div>
            <div class="brand-title">GatewayGuard</div>
            <div class="brand-subtitle">Official Security Console</div>
          </div>
        </div>

        <nav class="immersive-nav">
          <button
            v-for="item in navItems"
            :key="item.section"
            type="button"
            class="immersive-nav__btn"
            :class="{ active: currentSection === item.section }"
            @click="goToSection(item.section)"
          >
            <el-icon><component :is="item.icon" /></el-icon>
            <span>{{ item.label }}</span>
          </button>
        </nav>

        <div class="immersive-topbar__clock" aria-label="本地时间">
          <div class="immersive-topbar__clock-inner">
            <span class="immersive-topbar__clock-label">LOCAL TIME</span>
            <strong>{{ clockLabel }}</strong>
          </div>
        </div>
      </header>

      <main class="immersive-workspace">
        <section v-if="showImmersiveChrome" class="immersive-head" :class="{ 'immersive-head--compact': !showWorkspaceHead }">
          <div v-if="showWorkspaceHead" class="immersive-head__meta">
            <div class="workspace-eyebrow">{{ currentMeta.eyebrow }}</div>
            <h1>{{ currentMeta.title }}</h1>
            <p>{{ currentMeta.description }}</p>
          </div>

          <div class="immersive-overview" :class="{ 'immersive-overview--pulse-only': hideImmersiveStats }">
            <section v-if="!hideImmersiveStats" class="immersive-stats">
              <div class="status-card status-card--immersive immersive-stat-card">
                <div class="status-k">总报文数</div>
                <div class="status-v">{{ sidebarStats.totalPackets }}</div>
              </div>
              <div class="status-card status-card--immersive immersive-stat-card">
                <div class="status-k">异常事件</div>
                <div class="status-v">{{ sidebarStats.alertCount }}</div>
              </div>
              <div class="status-card status-card--immersive immersive-stat-card">
                <div class="status-k">当前模块</div>
                <div class="status-v">{{ currentMeta.short }}</div>
              </div>
              <div class="status-card status-card--immersive immersive-stat-card">
                <div class="status-k">本地时间</div>
                <div class="status-v">{{ clockLabel }}</div>
              </div>
            </section>

            <div class="immersive-pulse" :class="`immersive-pulse--${riskLevelTone}`">
              <div class="pulse-ring pulse-ring--lg" />
              <div class="pulse-ring pulse-ring--sm" />
              <div class="pulse-core" :class="`pulse-core--${riskLevelTone}`">
                <span>风险</span>
                <strong>{{ riskLevelLabel }}</strong>
              </div>
            </div>
          </div>
        </section>

        <section class="immersive-body" :class="{ 'immersive-body--metrics-hero': usePageMetricsHero }">
          <router-view v-slot="{ Component, route: viewRoute }">
            <Transition name="immersive-route" mode="out-in">
              <component :is="Component" :key="viewRoute.fullPath" />
            </Transition>
          </router-view>
        </section>
      </main>
    </div>
  </Transition>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElNotification } from 'element-plus'
import { ChatDotRound, Cpu, House, InfoFilled, WarningFilled } from '@element-plus/icons-vue'
import { anomalyApi, trafficApi } from './api/index.js'
import brandIcon from './assets/icon.png'

const route = useRoute()
const router = useRouter()

const navItems = [
  { section: 'home', label: '首页', icon: House },
  { section: 'assistant', label: 'AI 助手', icon: ChatDotRound },
  { section: 'console', label: '模拟控制台', icon: Cpu },
  { section: 'events', label: '事件中心', icon: WarningFilled },
  { section: 'about', label: '关于我们', icon: InfoFilled },
]

const metaMap = {
  landing: {
    eyebrow: 'GatewayGuard',
    title: '平台首页',
    description: '以主视觉首页承接平台定位、运行状态和控制台入口，作为 PC 端统一入口。',
    caption: '总览、入口与运行快照',
    short: 'HOME',
  },
  assistant: {
    eyebrow: 'AI Assistant',
    title: 'AI 助手',
    description: '保持现有 LLM 对话能力，并扩展为沉浸式分析工作区。',
    caption: '对话、追问与处置建议',
    short: 'LLM',
  },
  console: {
    eyebrow: 'Simulation Console',
    title: '模拟控制台',
    description: '统一组织流量生成、实时采集、训练检测和数据清理动作，不改变任何后端接口。',
    caption: '采集、训练、检测与维护',
    short: 'OPS',
  },
  events: {
    eyebrow: 'Incident Center',
    title: '事件中心',
    description: '将异常筛选、AI 研判和预警报告集中在一个页面，形成沉浸式事件指挥面板。',
    caption: '异常事件与 AI 报告',
    short: 'SOC',
  },
  about: {
    eyebrow: 'Platform Info',
    title: '关于我们',
    description: '展示平台定位、当前后端状态和桌面端信息架构说明。',
    caption: '系统概览与版本说明',
    short: 'INFO',
  },
}

const sidebarStats = ref({
  totalPackets: 0,
  alertCount: 0,
})
const riskLevel = ref('none')
const criticalFrameActive = ref(false)
const clockLabel = ref('--:--')
let refreshTimer = null
let clockTimer = null
let criticalFrameTimer = null
let lastCriticalAlertKey = ''

const isStandaloneHome = computed(() => route.meta.shell === 'landing' || route.path === '/')
const currentShell = computed(() => route.meta.shell || 'landing')
const currentSection = computed(() => route.meta.section || 'home')
const currentMeta = computed(() => {
  if (currentShell.value === 'landing') return metaMap.landing
  return metaMap[currentSection.value] || metaMap.assistant
})
const showWorkspaceHead = computed(() => !['assistant', 'console', 'events', 'about'].includes(currentSection.value))
const showImmersiveChrome = computed(() => currentSection.value !== 'about')
const hideImmersiveStats = computed(() => (
  currentShell.value === 'immersive' && ['assistant', 'events', 'console'].includes(currentSection.value)
))
const usePageMetricsHero = computed(() => (
  currentShell.value === 'immersive' && ['assistant', 'events', 'console'].includes(currentSection.value)
))
const riskLevelLabel = computed(() => ({
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  none: '正常',
}[riskLevel.value] || '未知'))
const riskLevelTone = computed(() => ({
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  none: 'none',
}[riskLevel.value] || 'none'))

function pickHighestSeverity(items) {
  const order = ['critical', 'high', 'medium', 'low']
  for (const level of order) {
    if (items.some((item) => item?.severity === level)) {
      return level
    }
  }
  return 'none'
}

function latestCriticalAlertKey(items) {
  const critical = items.find((item) => item?.severity === 'critical')
  if (!critical) return ''
  return String(
    critical.event_id
      || critical.id
      || `${critical.timestamp || ''}-${critical.anomaly_type || ''}-${critical.source_node || ''}-${critical.target_node || ''}`,
  )
}

function persistMode(mode) {
  if (typeof window !== 'undefined') {
    window.localStorage.setItem('gg-ui-mode', mode)
  }
}

function sectionPath(section, mode = currentShell.value) {
  if (section === 'home') return '/'
  return `/${mode}/${section}`
}

function goToSection(section) {
  router.push(sectionPath(section))
}

function updateClock() {
  const now = new Date()
  const hh = String(now.getHours()).padStart(2, '0')
  const mm = String(now.getMinutes()).padStart(2, '0')
  clockLabel.value = `${hh}:${mm}`
}

function triggerCriticalAlert() {
  criticalFrameActive.value = true
  if (criticalFrameTimer) clearTimeout(criticalFrameTimer)
  criticalFrameTimer = setTimeout(() => {
    criticalFrameActive.value = false
    criticalFrameTimer = null
  }, 5000)

  ElNotification({
    title: '严重风险流量',
    message: '检测到严重风险流量',
    type: 'error',
    position: 'top-right',
    duration: 5000,
    customClass: 'gg-critical-notification',
    showClose: true,
  })
}

async function refreshSidebarStats() {
  try {
    const [statsRes, anomalyRes] = await Promise.all([
      trafficApi.getStats(),
      anomalyApi.getEvents({ limit: 20 }),
    ])
    sidebarStats.value = {
      totalPackets: statsRes?.data?.total_packets || 0,
      alertCount: anomalyRes?.data?.total || 0,
    }
    const anomalyItems = anomalyRes?.data?.items || anomalyRes?.data?.events || anomalyRes?.data || []
    riskLevel.value = pickHighestSeverity(anomalyItems)

    const criticalKey = latestCriticalAlertKey(anomalyItems)
    if (criticalKey && criticalKey !== lastCriticalAlertKey) {
      lastCriticalAlertKey = criticalKey
      triggerCriticalAlert()
    } else if (!criticalKey) {
      lastCriticalAlertKey = ''
    }
  } catch {
    // Keep shell usable even when summary requests fail.
    riskLevel.value = 'none'
  }
}

watch(
  () => currentShell.value,
  (shell) => {
    if (shell === 'immersive') {
      persistMode(shell)
    }
  },
  { immediate: true },
)

onMounted(async () => {
  updateClock()
  await refreshSidebarStats()
  clockTimer = setInterval(updateClock, 1000 * 30)
  refreshTimer = setInterval(refreshSidebarStats, 1000 * 20)
})

onUnmounted(() => {
  if (clockTimer) clearInterval(clockTimer)
  if (refreshTimer) clearInterval(refreshTimer)
  if (criticalFrameTimer) clearTimeout(criticalFrameTimer)
})
</script>

<style scoped>
.landing-shell {
  position: relative;
  min-height: 100vh;
  padding: 0;
}

.landing-route-enter-active,
.landing-route-leave-active,
.immersive-route-enter-active,
.immersive-route-leave-active {
  transition:
    opacity 0.34s ease,
    transform 0.34s ease,
    filter 0.34s ease;
}

.landing-route-enter-from,
.landing-route-leave-to {
  opacity: 0;
  transform: translateY(18px) scale(0.992);
  filter: blur(8px);
}

.immersive-route-enter-from,
.immersive-route-leave-to {
  opacity: 0;
  transform: translateX(28px) translateY(8px) scale(0.99);
  filter: blur(10px);
}

.landing-route-enter-to,
.landing-route-leave-from,
.immersive-route-enter-to,
.immersive-route-leave-from {
  opacity: 1;
  transform: none;
  filter: blur(0);
}

.landing-route-leave-active,
.immersive-route-leave-active {
  position: absolute;
  inset: 0;
  width: 100%;
}

.shell-swap-enter-active,
.shell-swap-leave-active {
  transition:
    opacity 0.42s ease,
    transform 0.42s ease,
    filter 0.42s ease;
}

.shell-swap-enter-from,
.shell-swap-leave-to {
  opacity: 0;
  transform: translateY(18px) scale(0.992);
  filter: blur(10px);
}

.shell-swap-enter-to,
.shell-swap-leave-from {
  opacity: 1;
  transform: none;
  filter: blur(0);
}

.shell-swap-leave-active {
  position: absolute;
  inset: 0;
  width: 100%;
}

.immersive-nav__btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  min-height: 46px;
  padding: 0 16px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 999px;
  color: #edf3ff;
  background: rgba(255, 255, 255, 0.08);
  font-family: var(--gg-font-ui);
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  cursor: pointer;
  transition: transform 0.2s ease, background 0.2s ease, border-color 0.2s ease;
}

.immersive-nav__btn:hover,
.immersive-nav__btn.active {
  transform: translateY(-1px);
  background: rgba(99, 132, 255, 0.2);
  border-color: rgba(151, 175, 255, 0.34);
}

.immersive-backdrop,
.immersive-veil {
  position: fixed;
  inset: 0;
  pointer-events: none;
}

.immersive-backdrop {
  background:
    linear-gradient(120deg, rgba(4, 12, 21, 0.92), rgba(5, 17, 27, 0.64)),
    url('./assets/home-hero.png') center / cover no-repeat;
  transform: scale(1.05);
  animation: backdropFloat 18s ease-in-out infinite alternate;
}

.immersive-veil {
  background:
    radial-gradient(680px 280px at 12% 18%, rgba(74, 118, 255, 0.18), transparent 70%),
    radial-gradient(460px 220px at 88% 16%, rgba(50, 212, 178, 0.16), transparent 72%),
    linear-gradient(180deg, rgba(3, 7, 13, 0.2), rgba(3, 7, 13, 0.8));
}

.shell--immersive {
  position: relative;
  display: block;
  min-height: 100vh;
  color: #eef4ff;
}

.shell--immersive::after {
  position: fixed;
  inset: 10px;
  z-index: 12;
  pointer-events: none;
  border: 1px solid transparent;
  border-radius: 24px;
  content: '';
  opacity: 0;
}

.shell--critical-alert::after {
  border-color: rgba(255, 82, 112, 0.86);
  box-shadow:
    0 0 0 1px rgba(255, 211, 220, 0.2) inset,
    0 0 26px rgba(255, 61, 96, 0.46),
    0 0 70px rgba(255, 61, 96, 0.24);
  animation: criticalFramePulse 1s ease-in-out infinite;
}

.immersive-topbar {
  position: relative;
  z-index: 1;
}

.immersive-topbar {
  display: grid;
  grid-template-columns: auto 1fr auto auto;
  align-items: center;
  gap: 20px;
  padding: 18px 24px 0;
}

.immersive-brand,
.immersive-nav {
  display: flex;
}

.immersive-brand {
  align-items: center;
  gap: 14px;
}

.immersive-nav {
  justify-content: center;
  flex-wrap: wrap;
  gap: 10px;
}

.immersive-topbar__clock {
  display: grid;
  place-items: center;
  justify-self: end;
  min-height: 44px;
  padding: 0 14px;
  border: 1px solid rgba(93, 215, 255, 0.18);
  border-radius: 999px;
  background:
    linear-gradient(180deg, rgba(15, 31, 52, 0.72), rgba(7, 16, 29, 0.72)),
    linear-gradient(90deg, rgba(93, 215, 255, 0.12), transparent);
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.08),
    0 10px 26px rgba(0, 0, 0, 0.22);
  color: rgba(218, 233, 255, 0.9);
}

.immersive-topbar__clock-inner {
  display: inline-flex;
  align-items: flex-end;
  gap: 10px;
}

.immersive-topbar__clock-label {
  color: rgba(188, 214, 248, 0.58);
  font-size: 11px;
  font-family: var(--gg-font-ui);
  letter-spacing: 0.22em;
  text-transform: uppercase;
  line-height: 1;
}

.immersive-topbar__clock strong {
  color: #eaf4ff;
  font-size: 18px;
  font-family: var(--gg-font-metric);
  letter-spacing: 0.06em;
  line-height: 1;
}

.immersive-workspace {
  position: relative;
  z-index: 1;
  padding: 18px 24px 28px;
}

.immersive-head {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 18px;
  align-items: center;
  margin-bottom: 18px;
}

.immersive-head--compact {
  grid-template-columns: 1fr;
}

.immersive-overview {
  display: grid;
  grid-template-columns: minmax(520px, 1fr) 220px;
  gap: 18px;
  align-items: center;
  justify-self: stretch;
  width: 100%;
}

.immersive-overview--pulse-only {
  grid-template-columns: 220px;
  justify-content: end;
}

.immersive-head__meta {
  padding: 28px 30px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 28px;
  background: rgba(10, 19, 32, 0.48);
  backdrop-filter: blur(12px);
  box-shadow: 0 28px 64px rgba(0, 0, 0, 0.24);
}

.immersive-head__meta h1 {
  margin: 10px 0 8px;
  font-size: 38px;
  color: #fff;
  font-family: var(--gg-font-display);
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

.immersive-head__meta p {
  margin: 0;
  color: rgba(233, 241, 255, 0.76);
  line-height: 1.82;
  max-width: 860px;
}

.immersive-pulse {
  --pulse-ring: rgba(159, 190, 255, 0.68);
  --pulse-fill: rgba(140, 176, 255, 0.08);
  --pulse-line: rgba(140, 176, 255, 0.2);
  --pulse-accent: rgba(125, 233, 214, 0.14);
  --pulse-glow: rgba(111, 151, 255, 0.34);
  --pulse-glow-strong: rgba(125, 233, 214, 0.16);
  position: relative;
  display: grid;
  place-items: center;
  height: 220px;
}

.pulse-ring,
.pulse-core {
  position: absolute;
  border-radius: 999px;
}

.pulse-ring {
  border: 2px solid var(--pulse-ring);
  background:
    radial-gradient(circle, var(--pulse-fill) 0 54%, var(--pulse-line) 55% 56%, transparent 58%),
    radial-gradient(circle, transparent 60%, var(--pulse-accent) 61% 63%, transparent 66%);
  box-shadow:
    0 0 0 1px rgba(255, 255, 255, 0.16) inset,
    0 0 22px var(--pulse-glow),
    0 0 46px var(--pulse-glow-strong);
  animation: pulseRing 3.6s ease-in-out infinite;
}

.immersive-pulse--critical {
  --pulse-ring: rgba(255, 123, 146, 0.78);
  --pulse-fill: rgba(255, 93, 124, 0.1);
  --pulse-line: rgba(255, 93, 124, 0.26);
  --pulse-accent: rgba(255, 188, 203, 0.18);
  --pulse-glow: rgba(255, 93, 124, 0.42);
  --pulse-glow-strong: rgba(255, 74, 113, 0.22);
}

.immersive-pulse--high {
  --pulse-ring: rgba(255, 180, 105, 0.76);
  --pulse-fill: rgba(255, 165, 72, 0.1);
  --pulse-line: rgba(255, 165, 72, 0.25);
  --pulse-accent: rgba(255, 219, 158, 0.16);
  --pulse-glow: rgba(255, 165, 72, 0.38);
  --pulse-glow-strong: rgba(255, 137, 43, 0.2);
}

.immersive-pulse--medium {
  --pulse-ring: rgba(255, 216, 111, 0.76);
  --pulse-fill: rgba(255, 214, 79, 0.1);
  --pulse-line: rgba(255, 214, 79, 0.24);
  --pulse-accent: rgba(255, 241, 167, 0.16);
  --pulse-glow: rgba(255, 214, 79, 0.36);
  --pulse-glow-strong: rgba(255, 197, 45, 0.18);
}

.immersive-pulse--low {
  --pulse-ring: rgba(89, 216, 178, 0.76);
  --pulse-fill: rgba(89, 216, 178, 0.1);
  --pulse-line: rgba(89, 216, 178, 0.24);
  --pulse-accent: rgba(151, 242, 219, 0.16);
  --pulse-glow: rgba(89, 216, 178, 0.36);
  --pulse-glow-strong: rgba(70, 221, 190, 0.18);
}

.immersive-pulse--none {
  --pulse-ring: rgba(159, 190, 255, 0.68);
  --pulse-fill: rgba(140, 176, 255, 0.08);
  --pulse-line: rgba(140, 176, 255, 0.2);
  --pulse-accent: rgba(125, 233, 214, 0.14);
  --pulse-glow: rgba(111, 151, 255, 0.34);
  --pulse-glow-strong: rgba(125, 233, 214, 0.16);
}

.pulse-ring--lg {
  width: 210px;
  height: 210px;
}

.pulse-ring--sm {
  width: 150px;
  height: 150px;
  animation-delay: 0.8s;
}

.pulse-core {
  display: grid;
  place-items: center;
  width: 104px;
  height: 104px;
  color: #fff;
  background: radial-gradient(circle at 30% 30%, #5078ff, #152746 72%);
  box-shadow: 0 0 38px rgba(80, 120, 255, 0.28);
}

.pulse-core span {
  font-size: 12px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  font-family: var(--gg-font-ui);
}

.pulse-core strong {
  font-size: 28px;
  font-family: var(--gg-font-display);
  letter-spacing: 0.06em;
}

.pulse-core--critical {
  background: radial-gradient(circle at 30% 30%, #ff7b92, #5b1221 72%);
  box-shadow: 0 0 38px rgba(255, 93, 124, 0.34);
}

.pulse-core--high {
  background: radial-gradient(circle at 30% 30%, #ffb469, #5b2f10 72%);
  box-shadow: 0 0 38px rgba(255, 165, 72, 0.3);
}

.pulse-core--medium {
  background: radial-gradient(circle at 30% 30%, #ffd86f, #5a4b12 72%);
  box-shadow: 0 0 38px rgba(255, 214, 79, 0.28);
}

.pulse-core--low {
  background: radial-gradient(circle at 30% 30%, #59d8b2, #123e33 72%);
  box-shadow: 0 0 38px rgba(89, 216, 178, 0.28);
}

.pulse-core--none {
  background: radial-gradient(circle at 30% 30%, #7f96c8, #1a2942 72%);
  box-shadow: 0 0 38px rgba(127, 150, 200, 0.24);
}

.immersive-stats {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
  width: 100%;
}

.status-card--immersive {
  min-width: 0;
  min-height: 112px;
}

.immersive-stat-card {
  animation: immersiveStatRise 0.56s ease both;
}

.immersive-stat-card:nth-child(1) {
  animation-delay: 0.04s;
}

.immersive-stat-card:nth-child(2) {
  animation-delay: 0.12s;
}

.immersive-stat-card:nth-child(3) {
  animation-delay: 0.2s;
}

.immersive-stat-card:nth-child(4) {
  animation-delay: 0.28s;
}

.immersive-body {
  position: relative;
  min-height: 0;
}

:deep(.workspace-body) {
  position: relative;
}

.immersive-body--metrics-hero :deep(.chat-layout > .section-block:first-child),
.immersive-body--metrics-hero :deep(.console-page > .section-block:first-child),
.immersive-body--metrics-hero :deep(.events-page > .section-block:first-child) {
  position: relative;
  z-index: 2;
  margin-top: -252px;
  margin-right: 238px;
  max-width: none;
}

.immersive-body--metrics-hero :deep(.chat-layout > .section-block:first-child .el-row),
.immersive-body--metrics-hero :deep(.console-page > .section-block:first-child .el-row),
.immersive-body--metrics-hero :deep(.events-page > .section-block:first-child .el-row) {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
  margin-left: 0 !important;
  margin-right: 0 !important;
  align-items: stretch;
}

.immersive-body--metrics-hero :deep(.chat-layout > .section-block:first-child .el-row > .el-col),
.immersive-body--metrics-hero :deep(.console-page > .section-block:first-child .el-row > .el-col),
.immersive-body--metrics-hero :deep(.events-page > .section-block:first-child .el-row > .el-col) {
  max-width: none;
  flex: none;
  width: auto;
  padding-left: 0 !important;
  padding-right: 0 !important;
}

.immersive-body--metrics-hero :deep(.chat-layout > .section-block:first-child .metric-card),
.immersive-body--metrics-hero :deep(.console-page > .section-block:first-child .metric-card),
.immersive-body--metrics-hero :deep(.events-page > .section-block:first-child .metric-card) {
  min-height: 88px;
  height: 100%;
}

.immersive-body--metrics-hero :deep(.chat-layout > .section-block:first-child .metric-card__value),
.immersive-body--metrics-hero :deep(.console-page > .section-block:first-child .metric-card__value),
.immersive-body--metrics-hero :deep(.events-page > .section-block:first-child .metric-card__value) {
  margin-top: 6px;
  font-size: 26px;
}

.immersive-body--metrics-hero :deep(.chat-layout > .section-block:first-child .metric-card__meta),
.immersive-body--metrics-hero :deep(.console-page > .section-block:first-child .metric-card__meta),
.immersive-body--metrics-hero :deep(.events-page > .section-block:first-child .metric-card__meta) {
  margin-top: 4px;
  line-height: 1.35;
}

@keyframes backdropFloat {
  from {
    background-position: center, 50% 0%;
  }
  to {
    background-position: center, 50% 12%;
  }
}

@keyframes pulseRing {
  0%,
  100% {
    transform: scale(0.96);
    opacity: 0.72;
  }
  50% {
    transform: scale(1.04);
    opacity: 1;
  }
}

@keyframes criticalFramePulse {
  0%,
  100% {
    opacity: 0.42;
    transform: scale(0.998);
  }
  50% {
    opacity: 1;
    transform: scale(1);
  }
}

@keyframes immersiveStatRise {
  from {
    opacity: 0;
    transform: translateY(18px) scale(0.985);
    filter: blur(8px);
  }
  to {
    opacity: 1;
    transform: none;
    filter: blur(0);
  }
}

@media (max-width: 1180px) {
  .immersive-topbar,
  .immersive-head {
    grid-template-columns: 1fr;
  }

  .immersive-overview {
    grid-template-columns: 1fr;
  }

  .immersive-nav {
    justify-content: flex-start;
  }

  .immersive-topbar__clock {
    justify-self: start;
    width: fit-content;
  }

  .immersive-pulse {
    height: 160px;
  }

  .immersive-body--metrics-hero :deep(.chat-layout > .section-block:first-child),
  .immersive-body--metrics-hero :deep(.console-page > .section-block:first-child),
  .immersive-body--metrics-hero :deep(.events-page > .section-block:first-child) {
    margin-top: -138px;
    margin-right: 0;
  }
}

@media (max-width: 820px) {
  .landing-shell {
    padding: 0;
  }

  .immersive-topbar,
  .immersive-workspace {
    padding-left: 14px;
    padding-right: 14px;
  }

  .immersive-topbar__clock {
    width: 100%;
    justify-content: space-between;
  }

  .immersive-stats {
    grid-template-columns: 1fr;
  }

  .immersive-body--metrics-hero :deep(.chat-layout > .section-block:first-child),
  .immersive-body--metrics-hero :deep(.console-page > .section-block:first-child),
  .immersive-body--metrics-hero :deep(.events-page > .section-block:first-child) {
    margin-top: 0;
  }
}
</style>
