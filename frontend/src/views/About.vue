<template>
  <div v-if="!isImmersive" class="about-page">
    <section class="about-hero section-block">
      <div class="panel-card about-hero__copy">
        <div class="about-eyebrow">GatewayGuard Overview</div>
        <h3>面向智能网联汽车场景的多源安全分析平台</h3>
        <p>
          GatewayGuard 聚合 CAN、以太网、V2X 与离线抓包流量入口，以规则检测、机器学习检测和
          AI 解释层协同构成完整的车载网络安全分析闭环。它更接近一体化安全分析工作台，而不是单一检测算法页面。
        </p>
      </div>

      <div class="hero-stats">
        <div class="portal-card metric-card">
          <div class="metric-card__label">开源数据集</div>
          <div class="metric-card__value">4</div>
          <div class="metric-card__meta">发布版正式纳入的公开 CAN 数据集数量</div>
        </div>
        <div class="portal-card metric-card">
          <div class="metric-card__label">有效攻击 Case</div>
          <div class="metric-card__value">11</div>
          <div class="metric-card__meta">全部攻击 case 均具备有效 ML F1</div>
        </div>
        <div class="portal-card metric-card">
          <div class="metric-card__label">加权 F1</div>
          <div class="metric-card__value">0.9617</div>
          <div class="metric-card__meta">当前发布版攻击 case 的 weighted F1</div>
        </div>
        <div class="portal-card metric-card">
          <div class="metric-card__label">正常段 FPR</div>
          <div class="metric-card__value">≈ 0</div>
          <div class="metric-card__meta">正常流量 ML 误报接近零，仅 B-CAN 为 0.0001</div>
        </div>
      </div>
    </section>

    <section class="section-block">
      <div class="section-head">
        <div>
          <div class="section-head__title">核心优势</div>
          <div class="section-head__desc">重点展示项目的系统能力、评测表现和解释能力。</div>
        </div>
      </div>

      <div class="advantage-grid">
        <div v-for="item in advantages" :key="item.title" class="panel-card advantage-card">
          <div class="advantage-card__kicker">{{ item.kicker }}</div>
          <h4>{{ item.title }}</h4>
          <p>{{ item.desc }}</p>
        </div>
      </div>
    </section>

    <section class="section-block about-grid">
      <el-card class="panel-card">
        <template #header>
          <div class="about-head">
            <div class="about-head__title">系统状态</div>
            <el-button text @click="loadStatus" :loading="loading">刷新</el-button>
          </div>
        </template>

        <div v-if="status" class="status-grid">
          <div class="status-item">
            <span>运行状态</span>
            <strong>{{ status.status }}</strong>
          </div>
          <div class="status-item">
            <span>LLM Provider</span>
            <strong>{{ status.llm_provider }}</strong>
          </div>
          <div class="status-item">
            <span>LLM Model</span>
            <strong>{{ status.llm_model }}</strong>
          </div>
          <div class="status-item">
            <span>规则检测</span>
            <strong>{{ status.detector?.rule_enabled ? '启用' : '关闭' }}</strong>
          </div>
          <div class="status-item">
            <span>机器学习检测</span>
            <strong>{{ status.detector?.ml_enabled ? '启用' : '关闭' }}</strong>
          </div>
        </div>
        <el-empty v-else description="暂未获取到系统状态" />
      </el-card>

      <el-card class="panel-card">
        <template #header>
          <div class="about-head">
            <div class="about-head__title">方案对比</div>
          </div>
        </template>

        <div class="compare-grid">
          <div class="compare-row compare-row--head">
            <span>能力维度</span>
            <span>传统规则</span>
            <span>纯 ML</span>
            <span>GatewayGuard</span>
          </div>
          <div v-for="row in compareRows" :key="row.label" class="compare-row">
            <strong>{{ row.label }}</strong>
            <span>{{ row.rule }}</span>
            <span>{{ row.ml }}</span>
            <span>{{ row.gg }}</span>
          </div>
        </div>
      </el-card>
    </section>
  </div>

  <div v-else class="about-page about-page--immersive">
    <div class="about-carousel">
      <button type="button" class="carousel-arrow carousel-arrow--left" @click="prevSlide" aria-label="上一屏">
        ‹
      </button>

      <div class="carousel-stage" @mouseover="handleCardHover" @mouseout="handleCardLeave">
        <div class="carousel-track" :style="trackStyle">
          <section class="carousel-panel">
            <section class="about-hero section-block">
              <div class="about-hero__copy" :class="{ 'panel-card panel-card--dark': isImmersive, 'panel-card': !isImmersive }">
                <div class="about-eyebrow">GatewayGuard Overview</div>
                <h3>面向智能网联汽车场景的多源安全分析平台</h3>
                <p>
                  GatewayGuard 聚合 CAN、以太网、V2X 与离线抓包流量入口，以规则检测、机器学习检测和
                  AI 解释层协同构成完整的车载网络安全分析闭环。它不是单一检测算法演示，而是从采集、
                  检测、事件聚合到报告输出的一体化工作台。
                </p>

                <div class="hero-tags">
                  <span>多源接入</span>
                  <span>低误报控制</span>
                  <span>跨数据集评测</span>
                  <span>AI 语义分析</span>
                </div>
              </div>

              <div class="hero-stats">
                <div class="portal-card metric-card">
                  <div class="metric-card__label">开源数据集</div>
                  <div class="metric-card__value">4</div>
                  <div class="metric-card__meta">发布版正式纳入的公开 CAN 数据集数量</div>
                </div>
                <div class="portal-card metric-card">
                  <div class="metric-card__label">有效攻击 Case</div>
                  <div class="metric-card__value">11</div>
                  <div class="metric-card__meta">全部攻击 case 均具备有效 ML F1</div>
                </div>
                <div class="portal-card metric-card">
                  <div class="metric-card__label">加权 F1</div>
                  <div class="metric-card__value">0.9617</div>
                  <div class="metric-card__meta">当前发布版攻击 case 的 weighted F1</div>
                </div>
                <div class="portal-card metric-card">
                  <div class="metric-card__label">正常段 FPR</div>
                  <div class="metric-card__value">≈ 0</div>
                  <div class="metric-card__meta">正常流量 ML 误报接近零，仅 B-CAN 为 0.0001</div>
                </div>
              </div>
            </section>

            <section class="section-block">
              <div class="section-head">
                <div>
                  <div class="section-head__title">核心优势</div>
                  <div class="section-head__desc">从系统能力而不是单点分数，解释这个项目为什么有价值。</div>
                </div>
              </div>

              <div class="advantage-grid">
                <div v-for="item in advantages" :key="item.title" class="panel-card advantage-card">
                  <div class="advantage-card__kicker">{{ item.kicker }}</div>
                  <h4>{{ item.title }}</h4>
                  <p>{{ item.desc }}</p>
                </div>
              </div>
            </section>
          </section>

          <section class="carousel-panel">
            <section class="section-block">
              <div class="section-head">
                <div>
                  <div class="section-head__title">创新点</div>
                  <div class="section-head__desc">项目创新不只在模型分数，还在系统级闭环与口径控制。</div>
                </div>
              </div>

              <div class="innovation-strip">
                <div v-for="(item, index) in innovations" :key="item.title" class="panel-card innovation-card">
                  <div class="innovation-card__index">0{{ index + 1 }}</div>
                  <div>
                    <h4>{{ item.title }}</h4>
                    <p>{{ item.desc }}</p>
                  </div>
                </div>
              </div>
            </section>
          </section>

          <section class="carousel-panel">
            <section class="section-block">
              <div class="section-head">
                <div>
                  <div class="section-head__title">评测结果</div>
                  <div class="section-head__desc">用结果分布说明项目效果，而不是只展示单个最好看的 case。</div>
                </div>
              </div>

              <div class="chart-grid">
                <el-card class="panel-card chart-card">
                  <template #header>
                    <div class="chart-card__head">
                      <div>
                        <div class="chart-card__title">攻击 Case F1 分布</div>
                        <div class="chart-card__desc">不同攻击场景下的检测效果分布</div>
                      </div>
                    </div>
                  </template>
                  <VChart class="chart-surface" :option="f1ChartOption" autoresize />
                </el-card>

                <el-card class="panel-card chart-card">
                  <template #header>
                    <div class="chart-card__head">
                      <div>
                        <div class="chart-card__title">Precision-Recall 散点图</div>
                        <div class="chart-card__desc">横轴 Recall，纵轴 Precision，展示不同 case 的分布位置</div>
                      </div>
                    </div>
                  </template>
                  <VChart class="chart-surface" :option="prScatterOption" autoresize />
                </el-card>
              </div>
            </section>
          </section>

          <section class="carousel-panel">
            <section class="section-block about-grid">
              <el-card class="panel-card">
                <template #header>
                  <div class="about-head">
                    <div class="about-head__title">系统状态</div>
                    <el-button text @click="loadStatus" :loading="loading">刷新</el-button>
                  </div>
                </template>

                <div v-if="status" class="status-grid">
                  <div class="status-item">
                    <span>运行状态</span>
                    <strong>{{ status.status }}</strong>
                  </div>
                  <div class="status-item">
                    <span>LLM Provider</span>
                    <strong>{{ status.llm_provider }}</strong>
                  </div>
                  <div class="status-item">
                    <span>LLM Model</span>
                    <strong>{{ status.llm_model }}</strong>
                  </div>
                  <div class="status-item">
                    <span>规则检测</span>
                    <strong>{{ status.detector?.rule_enabled ? '启用' : '关闭' }}</strong>
                  </div>
                  <div class="status-item">
                    <span>机器学习检测</span>
                    <strong>{{ status.detector?.ml_enabled ? '启用' : '关闭' }}</strong>
                  </div>
                </div>
                <el-empty v-else description="暂未获取到系统状态" />
              </el-card>

              <el-card class="panel-card">
                <template #header>
                  <div class="about-head">
                    <div class="about-head__title">方案对比</div>
                  </div>
                </template>

                <div class="compare-grid">
                  <div class="compare-row compare-row--head">
                    <span>能力维度</span>
                    <span>传统规则</span>
                    <span>纯 ML</span>
                    <span>GatewayGuard</span>
                  </div>
                  <div v-for="row in compareRows" :key="row.label" class="compare-row">
                    <strong>{{ row.label }}</strong>
                    <span>{{ row.rule }}</span>
                    <span>{{ row.ml }}</span>
                    <span>{{ row.gg }}</span>
                  </div>
                </div>
              </el-card>
            </section>
          </section>
        </div>
      </div>

      <button type="button" class="carousel-arrow carousel-arrow--right" @click="nextSlide" aria-label="下一屏">
        ›
      </button>
    </div>

    <div class="carousel-dots">
      <button
        v-for="index in slideCount"
        :key="index"
        type="button"
        class="carousel-dot"
        :class="{ active: activeSlide === index - 1 }"
        @click="goToSlide(index - 1)"
        :aria-label="`跳转到第 ${index} 屏`"
      />
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart, ScatterChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import VChart from 'vue-echarts'
import { systemApi } from '../api/index.js'

use([CanvasRenderer, BarChart, ScatterChart, GridComponent, TooltipComponent, LegendComponent])

const route = useRoute()
const isImmersive = computed(() => route.meta.shell === 'immersive')
const status = ref(null)
const loading = ref(false)
const activeSlide = ref(0)
const slideCount = 4
let autoplayTimer = null
const isCardHovered = ref(false)

const advantages = [
  {
    kicker: 'Multi-source Access',
    title: '多源流量统一接入',
    desc: '平台不仅覆盖 CAN，还兼容以太网、V2X、PCAP 文件与模拟器输入，便于在统一工作台内完成多协议域观察。',
  },
  {
    kicker: 'Hybrid Detection',
    title: '规则与机器学习协同检测',
    desc: '不是单一规则库或纯黑盒模型，而是让规则检测、协议 profile 和 ML 辅助检测协同工作。',
  },
  {
    kicker: 'Low False Positives',
    title: '低误报控制',
    desc: '正常流量段的 ML 误报接近零，说明系统强调可用性，而不是通过激进告警换取表面上的高召回。',
  },
  {
    kicker: 'Explainable Workflow',
    title: '从检测到解释的闭环',
    desc: '异常事件、AI 分析、语义报告与处置建议被整合在同一平台内，减少检测和研判之间的断层。',
  },
]

const innovations = [
  {
    title: '跨数据集发布口径',
    desc: '在多个开源 CAN 数据集上独立训练和评测，避免把单一数据集上的局部最优误当成系统能力。',
  },
  {
    title: '薄弱场景修复导向',
    desc: '不仅展示高分样例，还重点修复原本接近不可用的场景，让系统具备更可信的工程价值。',
  },
  {
    title: '低误报优先级',
    desc: '在攻击检测能力之外，明确保留正常段接近零误报的目标，使系统更接近真实部署要求。',
  },
  {
    title: 'AI 解释层补全',
    desc: '通过 AI 助手和事件分析模块，把检测结果扩展为攻击意图解释、根因分析和处置建议。',
  },
]

const compareRows = [
  { label: '多源接入', rule: '多为单总线输入', ml: '依赖训练数据设计', gg: '已接入 CAN / ETH / V2X / PCAP / 模拟器' },
  { label: '误报控制', rule: '依赖规则调参', ml: '依赖验证集校准', gg: '当前发布结果显示正常段 ML FPR 接近零' },
  { label: '跨集适配', rule: '常需重写规则', ml: '受训练分布影响', gg: '已在多个开源 CAN 数据集独立评测' },
  { label: '异常解释', rule: '多为命中说明', ml: '通常缺少语义解释', gg: '补充了事件分析与 AI 摘要' },
  { label: '报告闭环', rule: '常需外部串联', ml: '多停留在模型输出', gg: '已串联检测、事件与报告展示' },
  { label: '展示形态', rule: '偏单点演示', ml: '偏模型展示', gg: '更接近一体化分析工作台' },
]

const f1Cases = [
  ['Car-Hacking dos', 1.0],
  ['CAN-FD flooding', 1.0],
  ['CAN-FD fuzzing', 0.9988],
  ['Car-Hacking fuzzy', 0.9692],
  ['Car-Hacking rpm', 0.9553],
  ['B-CAN ddos', 0.9473],
  ['B-CAN fuzzing', 0.9138],
  ['M-CAN fuzzing', 0.9135],
  ['Car-Hacking gear', 0.8962],
  ['CAN-FD malfunction', 0.8955],
]

const prCases = [
  ['B-CAN ddos', 0.9001, 0.9997, 16000],
  ['B-CAN fuzzing', 0.8413, 1.0, 3000],
  ['M-CAN ddos', 0.8847, 1.0, 37587],
  ['M-CAN fuzzing', 0.8409, 1.0, 11455],
  ['Car-Hacking dos', 1.0, 1.0, 23673],
  ['Car-Hacking fuzzy', 0.9415, 0.9986, 12021],
  ['Car-Hacking rpm', 1.0, 0.9144, 18952],
  ['Car-Hacking gear', 1.0, 0.8118, 18817],
  ['CAN-FD flooding', 1.0, 1.0, 43070],
  ['CAN-FD fuzzing', 0.9992, 0.9984, 28156],
  ['CAN-FD malfunction', 0.9974, 0.8125, 8212],
]

const f1ChartOption = computed(() => ({
  backgroundColor: 'transparent',
  grid: { left: 36, right: 16, top: 24, bottom: 72 },
  tooltip: { trigger: 'axis' },
  xAxis: {
    type: 'category',
    data: f1Cases.map(([name]) => name),
    axisLabel: { interval: 0, rotate: 28, color: isImmersive.value ? '#c5d6f5' : '#60748f' },
    axisLine: { lineStyle: { color: isImmersive.value ? 'rgba(255,255,255,0.16)' : '#d7e1ee' } },
  },
  yAxis: {
    type: 'value',
    min: 0.8,
    max: 1.02,
    axisLabel: { color: isImmersive.value ? '#c5d6f5' : '#60748f' },
    splitLine: { lineStyle: { color: isImmersive.value ? 'rgba(255,255,255,0.08)' : '#edf2f7' } },
  },
  series: [
    {
      type: 'bar',
      data: f1Cases.map(([, value]) => value),
      barWidth: 22,
      itemStyle: {
        borderRadius: [10, 10, 0, 0],
        color: (params) => (params.data >= 0.99 ? '#69a8ff' : params.data >= 0.94 ? '#4fd0a4' : '#f3b35c'),
      },
    },
  ],
}))

const prScatterOption = computed(() => ({
  backgroundColor: 'transparent',
  grid: { left: 44, right: 20, top: 24, bottom: 36 },
  tooltip: {
    formatter: (params) => {
      const [recall, precision, size, name] = params.data
      return `${name}<br/>Recall: ${recall}<br/>Precision: ${precision}<br/>Attack Samples: ${size}`
    },
  },
  xAxis: {
    type: 'value',
    min: 0.8,
    max: 1.02,
    name: 'Recall',
    nameTextStyle: { color: isImmersive.value ? '#c5d6f5' : '#60748f' },
    axisLabel: { color: isImmersive.value ? '#c5d6f5' : '#60748f' },
    splitLine: { lineStyle: { color: isImmersive.value ? 'rgba(255,255,255,0.08)' : '#edf2f7' } },
  },
  yAxis: {
    type: 'value',
    min: 0.8,
    max: 1.02,
    name: 'Precision',
    nameTextStyle: { color: isImmersive.value ? '#c5d6f5' : '#60748f' },
    axisLabel: { color: isImmersive.value ? '#c5d6f5' : '#60748f' },
    splitLine: { lineStyle: { color: isImmersive.value ? 'rgba(255,255,255,0.08)' : '#edf2f7' } },
  },
  series: [
    {
      type: 'scatter',
      data: prCases.map(([name, recall, precision, size]) => [recall, precision, size, name]),
      symbolSize: (value) => Math.max(12, Math.min(30, value[2] / 1800)),
      itemStyle: {
        color: isImmersive.value ? '#72a9ff' : '#3d67ff',
        shadowBlur: isImmersive.value ? 18 : 0,
        shadowColor: isImmersive.value ? 'rgba(114,169,255,0.28)' : 'transparent',
      },
    },
  ],
}))
const trackStyle = computed(() => ({
  transform: `translateX(-${activeSlide.value * 100}%)`,
}))

async function loadStatus() {
  loading.value = true
  try {
    const res = await systemApi.getStatus()
    status.value = res.data
  } finally {
    loading.value = false
  }
}

function goToSlide(index) {
  activeSlide.value = index
}

function nextSlide() {
  activeSlide.value = (activeSlide.value + 1) % slideCount
}

function prevSlide() {
  activeSlide.value = (activeSlide.value - 1 + slideCount) % slideCount
}

function startAutoplay() {
  stopAutoplay()
  if (!isCardHovered.value) {
    autoplayTimer = setInterval(nextSlide, 5000)
  }
}

function stopAutoplay() {
  if (autoplayTimer) {
    clearInterval(autoplayTimer)
    autoplayTimer = null
  }
}

function isPauseCard(target) {
  return Boolean(
    target?.closest(
      '.panel-card, .portal-card, .metric-card, .status-item, .compare-row, .innovation-card, .advantage-card',
    ),
  )
}

function handleCardHover(event) {
  if (isPauseCard(event.target)) {
    isCardHovered.value = true
    stopAutoplay()
  }
}

function handleCardLeave(event) {
  const fromCard = isPauseCard(event.target)
  const toCard = isPauseCard(event.relatedTarget)
  if (fromCard && !toCard) {
    isCardHovered.value = false
    startAutoplay()
  }
}

onMounted(() => {
  loadStatus()
  startAutoplay()
})

onUnmounted(stopAutoplay)
</script>

<style scoped>
.about-page {
  display: grid;
  gap: 18px;
}

.about-carousel {
  position: relative;
  display: grid;
  grid-template-columns: 56px minmax(0, 1fr) 56px;
  gap: 16px;
  align-items: center;
  min-height: 760px;
}

.carousel-stage {
  min-width: 0;
  overflow: hidden;
}

.carousel-panel {
  flex: 0 0 100%;
  min-height: 760px;
}

.carousel-track {
  display: flex;
  width: 100%;
  transition: transform 0.5s ease;
  will-change: transform;
}

.carousel-arrow {
  width: 56px;
  height: 56px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 999px;
  color: #edf3ff;
  background: rgba(255, 255, 255, 0.08);
  backdrop-filter: blur(10px);
  font-size: 34px;
  line-height: 1;
  font-family: var(--gg-font-display);
  cursor: pointer;
  transition: transform 0.2s ease, background 0.2s ease, border-color 0.2s ease;
}

.carousel-arrow:hover {
  transform: translateY(-1px);
  background: rgba(99, 132, 255, 0.18);
  border-color: rgba(151, 175, 255, 0.32);
}

.carousel-dots {
  display: flex;
  justify-content: center;
  gap: 10px;
}

.carousel-dot {
  width: 12px;
  height: 12px;
  border: 0;
  border-radius: 999px;
  background: rgba(126, 145, 172, 0.26);
  cursor: pointer;
  transition: transform 0.2s ease, background 0.2s ease;
}

.carousel-dot.active {
  transform: scale(1.15);
  background: #5e88ff;
}

.about-hero,
.about-grid,
.chart-grid,
.advantage-grid,
.hero-stats {
  display: grid;
  gap: 18px;
}

.about-hero {
  grid-template-columns: minmax(320px, 1.1fr) minmax(420px, 0.9fr);
  align-items: stretch;
}

.about-eyebrow {
  color: #5f8fd6;
  font-size: 12px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  font-family: var(--gg-font-ui);
}

.about-hero__copy {
  padding: 28px;
}

.about-page h3,
.advantage-card h4,
.innovation-card h4 {
  margin: 12px 0 10px;
  font-family: var(--gg-font-display);
  letter-spacing: 0.04em;
  color: #10233d;
}

.about-page h3 {
  font-size: 34px;
  text-transform: uppercase;
}

.about-page p {
  margin: 0;
  line-height: 1.82;
  color: #5d6f85;
}

.hero-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 22px;
}

.hero-tags span {
  padding: 10px 14px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.1);
  font-family: var(--gg-font-ui);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #446ea8;
}

.hero-stats {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.advantage-grid {
  grid-template-columns: repeat(4, minmax(0, 1fr));
}

.advantage-card,
.innovation-card {
  padding: 22px;
}

.advantage-card__kicker,
.innovation-card__index {
  color: #4f8ed3;
  font-size: 12px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-family: var(--gg-font-ui);
}

.advantage-card h4,
.innovation-card h4 {
  font-size: 22px;
}

.advantage-card p,
.innovation-card p {
  color: var(--gg-text-soft);
}

.innovation-strip {
  display: grid;
  gap: 16px;
}

.innovation-card {
  display: grid;
  grid-template-columns: 72px minmax(0, 1fr);
  gap: 18px;
  align-items: start;
}

.innovation-card__index {
  display: grid;
  place-items: center;
  width: 72px;
  height: 72px;
  border-radius: 18px;
  font-size: 20px;
  font-weight: 700;
  font-family: var(--gg-font-display);
  background: linear-gradient(180deg, #eff4ff, #dfeaff);
}

.chart-grid,
.about-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.about-page .hero-stats .metric-card :deep(.el-card__body) {
  display: flex;
  flex-direction: column;
  justify-content: center;
  min-height: 100%;
  padding-top: 18px;
  padding-bottom: 18px;
}

.about-page .hero-stats .metric-card__label {
  text-align: center;
  color: #4f8ed3;
  font-size: 12px;
  letter-spacing: 0.05em;
}

.about-page .hero-stats .metric-card__value {
  text-align: center;
  color: #183764;
  font-size: 30px;
}

.about-page .hero-stats .metric-card__meta {
  text-align: center;
  color: #627790;
  font-size: 12px;
  line-height: 1.45;
}

.chart-card__title,
.about-head__title {
  font-size: 20px;
  font-weight: 700;
  color: #10233d;
  font-family: var(--gg-font-display);
  letter-spacing: 0.03em;
  text-transform: uppercase;
}

.chart-card__desc {
  margin-top: 6px;
  color: #64788f;
  line-height: 1.6;
}

.chart-surface {
  height: 360px;
}

.about-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.status-grid,
.compare-grid {
  display: grid;
  gap: 14px;
}

.status-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.status-item {
  display: grid;
  gap: 6px;
  padding: 16px;
  border-radius: 16px;
  border: 1px solid var(--gg-line);
  background: var(--gg-surface-soft);
}

.status-item span {
  color: #6080a8;
  line-height: 1.7;
}

.status-item strong {
  color: #15355b;
  font-size: 16px;
}

.compare-row {
  display: grid;
  grid-template-columns: 1.4fr repeat(3, minmax(0, 1fr));
  gap: 12px;
  align-items: center;
  padding: 10px 14px;
  border-radius: 16px;
  border: 1px solid var(--gg-line);
  background: var(--gg-surface-soft);
  min-height: 0;
  line-height: 1.45;
  font-size: 13px;
}

.compare-row--head {
  font-size: 11px;
  font-weight: 700;
  color: #5c84bb;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  font-family: var(--gg-font-ui);
}

.compare-row strong {
  color: #14365d;
  font-size: 14px;
}

.about-page--immersive .about-hero__copy {
  background:
    radial-gradient(320px 180px at 100% 0%, rgba(94, 138, 255, 0.16), transparent 70%),
    linear-gradient(180deg, rgba(18, 30, 48, 0.94), rgba(10, 18, 28, 0.84));
}

.about-page--immersive .about-eyebrow {
  color: #7fdcff;
}

.about-page--immersive :is(h3, .advantage-card h4, .innovation-card h4, .chart-card__title, .about-head__title) {
  color: #f4f8ff;
  text-shadow: 0 0 20px rgba(96, 143, 255, 0.12);
}

.about-page--immersive .hero-tags span {
  color: #9ddaff;
  background: rgba(255, 255, 255, 0.06);
}

.about-page--immersive .metric-card__label,
.about-page--immersive .advantage-card__kicker {
  color: #7fcaff;
}

.about-page--immersive .metric-card__value {
  background: linear-gradient(180deg, #ffffff 0%, #aed7ff 56%, #77f0d9 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}

.about-page--immersive .metric-card__meta,
.about-page--immersive .chart-card__desc,
.about-page--immersive .section-head__desc,
.about-page--immersive .about-hero p {
  color: rgba(204, 222, 248, 0.8);
}

.about-page--immersive .innovation-card__index {
  color: #f5fbff;
  background: linear-gradient(180deg, rgba(79, 137, 255, 0.92), rgba(38, 91, 214, 0.92));
  box-shadow: 0 10px 24px rgba(44, 93, 214, 0.24);
}

.about-page--immersive :is(.advantage-card p, .innovation-card p, .chart-card__desc) {
  color: rgba(219, 229, 246, 0.76);
}

.about-page--immersive .status-item span {
  color: #85d5ff;
}

.about-page--immersive .status-item strong {
  color: #eef7ff;
}

.about-page--immersive .compare-row {
  border-color: rgba(255, 255, 255, 0.08);
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.035));
}

.about-page--immersive .compare-row--head {
  color: #8fd4ff;
  background: rgba(255, 255, 255, 0.03);
}

.about-page--immersive .compare-row strong {
  color: #f3f8ff;
}

.about-page--immersive .compare-row span {
  color: rgba(206, 223, 247, 0.82);
}

@media (max-width: 1280px) {
  .about-hero,
  .advantage-grid,
  .chart-grid,
  .about-grid {
    grid-template-columns: 1fr;
  }

  .hero-stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 860px) {
  .about-carousel {
    grid-template-columns: 40px minmax(0, 1fr) 40px;
    gap: 10px;
    min-height: 0;
  }

  .carousel-panel {
    min-height: 0;
  }

  .carousel-arrow {
    width: 40px;
    height: 40px;
    font-size: 28px;
  }

  .hero-stats,
  .status-grid {
    grid-template-columns: 1fr;
  }

  .innovation-card,
  .compare-row {
    grid-template-columns: 1fr;
  }

  .chart-surface {
    height: 320px;
  }
}
</style>
