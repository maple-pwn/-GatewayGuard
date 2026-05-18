<template>
  <div class="events-page">
    <section class="section-block">
      <el-row :gutter="18">
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">事件总量</div>
            <div class="metric-card__value">{{ total }}</div>
            <div class="metric-card__meta">当前筛选条件下的异常事件总数</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">高危与严重</div>
            <div class="metric-card__value">{{ highRiskCount }}</div>
            <div class="metric-card__meta">需要优先处理的核心风险事件</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">处理中</div>
            <div class="metric-card__value">{{ openCount }}</div>
            <div class="metric-card__meta">待处理或调查中的异常状态</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">AI 可研判</div>
            <div class="metric-card__value">{{ Math.min(events.length, 5) }}</div>
            <div class="metric-card__meta">当前页支持批量分析的事件窗口</div>
          </el-card>
        </el-col>
      </el-row>
    </section>

    <section class="section-block situation-grid" v-loading="summaryLoading">
      <el-card class="panel-card situation-card situation-card--risk">
        <div class="situation-card__head">
          <div>
            <div class="situation-card__eyebrow">Risk Posture</div>
            <div class="situation-card__title">风险态势</div>
          </div>
          <el-tag :type="riskTagType(chartData.riskLabel.toLowerCase())" effect="dark">
            {{ chartData.riskLabel }}
          </el-tag>
        </div>
        <VChart class="situation-gauge" :option="riskGaugeOption" autoresize />
        <div class="situation-hint">{{ chartData.riskHint }}</div>
      </el-card>

      <el-card class="panel-card situation-card situation-card--trend">
        <div class="situation-card__head">
          <div>
            <div class="situation-card__eyebrow">Event Trend</div>
            <div class="situation-card__title">事件趋势</div>
          </div>
          <span class="situation-card__meta">最近一小时 / 按分钟聚合</span>
        </div>
        <VChart class="situation-chart situation-chart--large" :option="trendOption" autoresize />
      </el-card>

      <el-card class="panel-card situation-card situation-card--advice">
        <div class="situation-card__eyebrow">AI Triage</div>
        <div class="situation-card__title">处置优先级</div>
        <div class="triage-list">
          <div class="triage-item triage-item--critical">
            <span>高危优先</span>
            <strong>{{ highRiskCount }}</strong>
          </div>
          <div class="triage-item triage-item--open">
            <span>待调查</span>
            <strong>{{ openCount }}</strong>
          </div>
          <div class="triage-item triage-item--ai">
            <span>AI 分析队列</span>
            <strong>{{ Math.min(events.length, 5) }}</strong>
          </div>
        </div>
        <div class="situation-hint">建议优先分析高危和调查中的 CAN / 网关侧异常。</div>
      </el-card>
    </section>

    <section class="section-block chart-grid" v-loading="summaryLoading">
      <el-card class="panel-card chart-card">
        <div class="situation-card__head">
          <div>
            <div class="situation-card__eyebrow">Severity Mix</div>
            <div class="situation-card__title">严重程度占比</div>
          </div>
        </div>
        <VChart class="situation-chart" :option="severityPieOption" autoresize />
      </el-card>

      <el-card class="panel-card chart-card">
        <div class="situation-card__head">
          <div>
            <div class="situation-card__eyebrow">Protocol Domain</div>
            <div class="situation-card__title">协议域分布</div>
          </div>
        </div>
        <VChart class="situation-chart" :option="protocolBarOption" autoresize />
      </el-card>

      <el-card class="panel-card chart-card">
        <div class="situation-card__head">
          <div>
            <div class="situation-card__eyebrow">Attack Topology</div>
            <div class="situation-card__title">攻击类型 Top 5</div>
          </div>
        </div>
        <VChart class="situation-chart" :option="typeBarOption" autoresize />
      </el-card>
    </section>

    <section class="section-block events-grid">
      <el-card class="panel-card">
        <div class="filter-grid">
          <div class="filter-field">
            <label>严重程度</label>
            <el-select v-model="filter.severity" placeholder="严重程度">
              <el-option label="全部" value="all" />
              <el-option label="严重" value="critical" />
              <el-option label="高" value="high" />
              <el-option label="中" value="medium" />
              <el-option label="低" value="low" />
            </el-select>
          </div>
          <div class="filter-field">
            <label>状态</label>
            <el-select v-model="filter.status" placeholder="状态" clearable>
              <el-option label="待处理" value="open" />
              <el-option label="调查中" value="investigating" />
              <el-option label="已解决" value="resolved" />
            </el-select>
          </div>
          <div class="filter-action">
            <el-button
              type="primary"
              class="ai-action-btn ai-action-btn--query"
              :loading="eventsLoading || summaryLoading"
              @click="loadPageData"
            >
              查询事件
            </el-button>
          </div>
        </div>
      </el-card>

      <el-card class="panel-card panel-card--dark">
        <div class="ai-box__eyebrow">AI Intelligence</div>
        <h3>生成摘要、报告和批量语义分析</h3>

        <div class="ai-box__actions">
          <el-button
            type="warning"
            size="large"
            class="ai-action-btn ai-action-btn--report"
            @click="generateReport"
            :loading="reportLoading"
          >
            生成 AI 预警报告
          </el-button>
          <el-button
            type="danger"
            size="large"
            class="ai-action-btn ai-action-btn--batch"
            @click="batchAnalyze"
            :loading="batchLoading"
          >
            批量 AI 分析
          </el-button>
        </div>
      </el-card>
    </section>

    <section class="section-block">
      <div class="section-head">
        <div>
          <div class="section-head__title">异常事件列表</div>
          <div class="section-head__desc">保留原始数据字段与逐条 AI 分析能力。</div>
        </div>
      </div>

      <el-card class="panel-card table-card" v-loading="eventsLoading">
        <el-table :data="events" stripe style="width: 100%" max-height="560">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="anomaly_type" label="类型" width="180" />
          <el-table-column label="严重程度" width="110">
            <template #default="{ row }">
              <el-tag :type="severityColor(row.severity)" size="small">{{ row.severity }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="confidence" label="置信度" width="100">
            <template #default="{ row }">
              {{ ((row.confidence || 0) * 100).toFixed(0) }}%
            </template>
          </el-table-column>
          <el-table-column prop="protocol" label="协议" width="90" />
          <el-table-column prop="source_node" label="源节点" width="120" />
          <el-table-column prop="description" label="描述" min-width="240" show-overflow-tooltip />
          <el-table-column label="操作" width="150" fixed="right">
            <template #default="{ row }">
              <el-button size="small" type="warning" @click="analyzeEvent(row)">
                AI 分析
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </section>

    <el-dialog v-model="showAnalysis" title="AI 语义分析" width="720px">
      <div v-if="analysisLoading" class="dialog-loading">
        <el-icon class="is-loading" :size="32"><Loading /></el-icon>
        <p>正在调用 LLM 分析...</p>
      </div>
      <div v-else-if="analysisResult && !analysisResult.analyze_raw">
        <el-alert
          v-if="analysisResult.summary"
          :title="analysisResult.summary"
          :type="riskAlertType(analysisResult.risk_level)"
          show-icon
          :closable="false"
          style="margin-bottom: 16px"
        />

        <el-row :gutter="12" style="margin-bottom: 16px">
          <el-col :span="8">
            <div class="info-card">
              <div class="info-label">攻击类型</div>
              <div class="info-value">{{ analysisResult.attack_type || '-' }}</div>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="info-card">
              <div class="info-label">风险等级</div>
              <el-tag :type="riskTagType(analysisResult.risk_level)" size="large" effect="dark">
                {{ riskLabel(analysisResult.risk_level) }}
              </el-tag>
            </div>
          </el-col>
          <el-col :span="8">
            <div class="info-card">
              <div class="info-label">攻击意图</div>
              <div class="info-value">{{ analysisResult.attack_intent || '-' }}</div>
            </div>
          </el-col>
        </el-row>

        <el-descriptions :column="1" border style="margin-bottom: 16px">
          <el-descriptions-item label="攻击手法">{{ analysisResult.attack_method || '-' }}</el-descriptions-item>
          <el-descriptions-item label="根因分析">{{ analysisResult.root_cause || '-' }}</el-descriptions-item>
        </el-descriptions>

        <div v-if="analysisResult.affected_scope?.length" style="margin-bottom: 16px">
          <div class="section-title">影响范围</div>
          <el-tag
            v-for="(s, i) in analysisResult.affected_scope"
            :key="i"
            type="warning"
            class="scope-tag"
          >
            {{ s }}
          </el-tag>
        </div>

        <div v-if="analysisResult.recommendations?.length">
          <div class="section-title">处置建议</div>
          <div v-for="(r, i) in analysisResult.recommendations" :key="i" class="rec-item">
            <el-icon><SuccessFilled /></el-icon>
            <span>{{ r }}</span>
          </div>
        </div>
      </div>
      <pre v-else-if="analysisResult" class="raw-block">{{ formatRaw(analysisResult) }}</pre>
    </el-dialog>

    <el-dialog v-model="showReport" title="AI 预警报告" width="800px" top="5vh">
      <div v-if="reportLoading" class="dialog-loading">
        <el-icon class="is-loading" :size="32"><Loading /></el-icon>
        <p>正在生成预警报告，请稍候...</p>
      </div>
      <div v-else-if="reportResult && !reportResult.report_raw">
        <div class="report-head">
          <h3>{{ reportResult.title || '预警报告' }}</h3>
          <el-tag v-if="reportResult.risk_level" :type="riskTagType(reportResult.risk_level)" size="large" effect="dark">
            {{ riskLabel(reportResult.risk_level) }}
          </el-tag>
        </div>

        <el-alert
          v-if="reportResult.summary"
          :title="reportResult.summary"
          type="info"
          show-icon
          :closable="false"
          style="margin-bottom: 16px"
        />

        <div v-if="reportResult.attack_chain" style="margin-bottom: 16px">
          <div class="section-title">攻击链分析</div>
          <div class="report-text-block">{{ reportResult.attack_chain }}</div>
        </div>

        <div v-if="reportResult.timeline?.length" style="margin-bottom: 16px">
          <div class="section-title">关键事件时间线</div>
          <el-timeline>
            <el-timeline-item
              v-for="(t, i) in reportResult.timeline"
              :key="i"
              :timestamp="'#' + (i + 1)"
              placement="top"
            >
              {{ t }}
            </el-timeline-item>
          </el-timeline>
        </div>

        <div v-if="reportResult.impact_assessment" style="margin-bottom: 16px">
          <div class="section-title">影响评估</div>
          <div class="report-text-block">{{ reportResult.impact_assessment }}</div>
        </div>

        <div v-if="reportResult.recommendations?.length" style="margin-bottom: 16px">
          <div class="section-title">处置建议</div>
          <div v-for="(r, i) in reportResult.recommendations" :key="i" class="rec-item">
            <el-icon><SuccessFilled /></el-icon>
            <span>{{ r }}</span>
          </div>
        </div>

        <el-alert
          v-if="reportResult.conclusion"
          :title="reportResult.conclusion"
          :type="riskAlertType(reportResult.risk_level)"
          show-icon
          :closable="false"
        />
      </div>
      <pre v-else-if="reportResult" class="raw-block">{{ formatRaw(reportResult) }}</pre>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart, GaugeChart, LineChart, PieChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import VChart from 'vue-echarts'
import { Loading, SuccessFilled } from '@element-plus/icons-vue'
import { anomalyApi, llmApi } from '../api/index.js'
import { ElMessage } from 'element-plus'
import { buildEventChartData } from '../utils/eventCharts.js'

use([
  CanvasRenderer,
  BarChart,
  GaugeChart,
  LineChart,
  PieChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
])

const route = useRoute()
const events = ref([])
const total = ref(0)
const filter = ref({ severity: 'all', status: '' })
const reportLoading = ref(false)
const showAnalysis = ref(false)
const analysisLoading = ref(false)
const analysisResult = ref(null)
const batchLoading = ref(false)
const showReport = ref(false)
const reportResult = ref(null)

const isImmersive = computed(() => route.meta.shell === 'immersive')
const chartData = ref(buildEventChartData([]))
const highRiskCount = ref(0)
const openCount = ref(0)
const eventsLoading = ref(false)
const summaryLoading = ref(false)

function severityColor(s) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[s] || 'info'
}

function formatRaw(obj) {
  if (!obj) return ''
  const raw = obj.analyze_raw || obj.report_raw
  if (raw) {
    return raw.replace(/^```json\n?/, '').replace(/\n?```$/, '')
  }
  return JSON.stringify(obj, null, 2)
}

function riskTagType(level) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'success' }[level] || 'info'
}

function riskAlertType(level) {
  return { critical: 'error', high: 'error', medium: 'warning', low: 'success' }[level] || 'info'
}

function riskLabel(level) {
  return { critical: '严重', high: '高危', medium: '中危', low: '低危' }[level] || level
}

const chartTextColor = computed(() => (isImmersive.value ? '#dce8fb' : '#51647f'))
const chartSplitColor = computed(() => (isImmersive.value ? 'rgba(255,255,255,0.08)' : '#edf2f7'))

const riskGaugeOption = computed(() => ({
  backgroundColor: 'transparent',
  series: [
    {
      type: 'gauge',
      radius: '92%',
      startAngle: 210,
      endAngle: -30,
      min: 0,
      max: 100,
      progress: {
        show: true,
        width: 12,
        itemStyle: { color: chartData.value.riskScore >= 70 ? '#ff6678' : chartData.value.riskScore >= 45 ? '#ffc65c' : '#58d8c4' },
      },
      axisLine: {
        lineStyle: {
          width: 12,
          color: [[1, isImmersive.value ? 'rgba(255,255,255,0.08)' : '#e7edf6']],
        },
      },
      axisTick: { show: false },
      splitLine: { show: false },
      axisLabel: { show: false },
      pointer: { show: false },
      anchor: { show: false },
      detail: {
        valueAnimation: true,
        formatter: '{value}',
        color: isImmersive.value ? '#f5f9ff' : '#1f2d3d',
        fontSize: 30,
        fontWeight: 800,
        offsetCenter: [0, '-2%'],
      },
      title: {
        show: true,
        offsetCenter: [0, '32%'],
        color: chartTextColor.value,
        fontSize: 12,
      },
      data: [{ value: chartData.value.riskScore, name: 'Risk Score' }],
    },
  ],
}))

const trendOption = computed(() => ({
  backgroundColor: 'transparent',
  tooltip: { trigger: 'axis' },
  legend: {
    top: 0,
    right: 0,
    textStyle: { color: chartTextColor.value },
  },
  grid: { left: 36, right: 22, top: 42, bottom: 28 },
  xAxis: {
    type: 'category',
    data: chartData.value.trend.map((item) => item.name),
    axisLabel: { color: chartTextColor.value },
    axisLine: { lineStyle: { color: chartSplitColor.value } },
  },
  yAxis: {
    type: 'value',
    minInterval: 1,
    axisLabel: { color: chartTextColor.value },
    splitLine: { lineStyle: { color: chartSplitColor.value } },
  },
  series: [
    {
      name: '事件总量',
      type: 'line',
      smooth: true,
      symbolSize: 7,
      areaStyle: { color: 'rgba(86, 184, 255, 0.16)' },
      lineStyle: { width: 3, color: '#5dd7ff' },
      itemStyle: { color: '#5dd7ff' },
      data: chartData.value.trend.map((item) => item.total),
    },
    {
      name: '高危事件',
      type: 'line',
      smooth: true,
      symbolSize: 7,
      lineStyle: { width: 3, color: '#ff6678' },
      itemStyle: { color: '#ff6678' },
      data: chartData.value.trend.map((item) => item.highRisk),
    },
  ],
}))

const severityPieOption = computed(() => ({
  backgroundColor: 'transparent',
  tooltip: { trigger: 'item' },
  legend: {
    bottom: 0,
    textStyle: { color: chartTextColor.value },
  },
  color: ['#ff6678', '#ff9f5f', '#ffc65c', '#58d8c4'],
  series: [
    {
      type: 'pie',
      radius: ['48%', '72%'],
      center: ['50%', '44%'],
      avoidLabelOverlap: true,
      label: { color: chartTextColor.value, formatter: '{b}: {c}' },
      data: chartData.value.severity,
    },
  ],
}))

const protocolBarOption = computed(() => ({
  backgroundColor: 'transparent',
  tooltip: { trigger: 'axis' },
  grid: { left: 34, right: 16, top: 24, bottom: 30 },
  xAxis: {
    type: 'category',
    data: chartData.value.protocol.map((item) => item.name),
    axisLabel: { color: chartTextColor.value },
    axisLine: { lineStyle: { color: chartSplitColor.value } },
  },
  yAxis: {
    type: 'value',
    minInterval: 1,
    axisLabel: { color: chartTextColor.value },
    splitLine: { lineStyle: { color: chartSplitColor.value } },
  },
  series: [
    {
      type: 'bar',
      barWidth: 22,
      data: chartData.value.protocol.map((item) => item.value),
      itemStyle: {
        borderRadius: [8, 8, 0, 0],
        color: '#5dd7ff',
      },
    },
  ],
}))

const typeBarOption = computed(() => ({
  backgroundColor: 'transparent',
  tooltip: { trigger: 'axis' },
  grid: { left: 86, right: 16, top: 24, bottom: 24 },
  xAxis: {
    type: 'value',
    minInterval: 1,
    axisLabel: { color: chartTextColor.value },
    splitLine: { lineStyle: { color: chartSplitColor.value } },
  },
  yAxis: {
    type: 'category',
    data: chartData.value.typeTop.map((item) => item.name).reverse(),
    axisLabel: { color: chartTextColor.value },
    axisLine: { lineStyle: { color: chartSplitColor.value } },
  },
  series: [
    {
      type: 'bar',
      barWidth: 16,
      data: chartData.value.typeTop.map((item) => item.value).reverse(),
      itemStyle: {
        borderRadius: [0, 8, 8, 0],
        color: '#58d8c4',
      },
    },
  ],
}))

function buildQueryParams() {
  const params = {}
  if (filter.value.severity && filter.value.severity !== 'all') {
    params.severity = filter.value.severity
  }
  if (filter.value.status) params.status = filter.value.status
  return params
}

async function loadEvents() {
  eventsLoading.value = true
  try {
    const params = { ...buildQueryParams(), limit: 50 }
    const res = await anomalyApi.getEvents(params)
    events.value = res.data.events
    total.value = res.data.total
  } catch (e) {
    console.error(e)
  } finally {
    eventsLoading.value = false
  }
}

async function loadSummary() {
  summaryLoading.value = true
  try {
    const res = await anomalyApi.getSummary({ ...buildQueryParams(), window_minutes: 60 })
    chartData.value = res.data
    total.value = res.data.total
    highRiskCount.value = res.data.high_risk_count || 0
    openCount.value = res.data.open_count || 0
  } catch (e) {
    console.error(e)
  } finally {
    summaryLoading.value = false
  }
}

async function loadPageData() {
  await Promise.all([loadEvents(), loadSummary()])
}

async function analyzeEvent(row) {
  showAnalysis.value = true
  analysisLoading.value = true
  analysisResult.value = null
  try {
    const res = await llmApi.analyze(row.id)
    analysisResult.value = res.data.analysis
  } catch {
    ElMessage.error('LLM 分析失败，请检查 API Key 配置')
  } finally {
    analysisLoading.value = false
  }
}

async function generateReport() {
  showReport.value = true
  reportLoading.value = true
  reportResult.value = null
  try {
    const res = await llmApi.report(10)
    reportResult.value = res.data.report
  } catch {
    ElMessage.error('报告生成失败')
    showReport.value = false
  } finally {
    reportLoading.value = false
  }
}

async function batchAnalyze() {
  if (!events.value.length) {
    ElMessage.warning('暂无异常事件可分析')
    return
  }
  batchLoading.value = true
  let success = 0
  let fail = 0
  for (const ev of events.value.slice(0, 5)) {
    try {
      await llmApi.analyze(ev.id)
      success++
    } catch {
      fail++
    }
  }
  batchLoading.value = false
  ElMessage.info(`批量分析完成: 成功 ${success}, 失败 ${fail}`)
}

onMounted(loadPageData)
</script>

<style scoped>
.events-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(320px, 0.8fr);
  gap: 18px;
}

.situation-grid {
  display: grid;
  grid-template-columns: minmax(260px, 0.78fr) minmax(420px, 1.55fr) minmax(260px, 0.82fr);
  gap: 18px;
}

.chart-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 18px;
}

.situation-card,
.chart-card {
  position: relative;
  overflow: hidden;
}

.situation-card::before,
.chart-card::before {
  content: '';
  position: absolute;
  inset: 0;
  pointer-events: none;
  background:
    linear-gradient(90deg, rgba(93, 215, 255, 0.08), transparent 34%),
    linear-gradient(180deg, rgba(255, 255, 255, 0.05), transparent 44%);
}

.situation-card :deep(.el-card__body),
.chart-card :deep(.el-card__body) {
  position: relative;
  z-index: 1;
}

.situation-card__head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}

.situation-card__eyebrow {
  color: #76c9ff;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.situation-card__title {
  margin-top: 5px;
  color: var(--gg-text-strong);
  font-size: 18px;
  font-weight: 800;
}

.situation-card__meta,
.situation-hint {
  color: var(--gg-text-soft);
  font-size: 12px;
  line-height: 1.7;
}

.situation-gauge {
  height: 190px;
}

.situation-chart {
  height: 240px;
}

.situation-chart--large {
  height: 260px;
}

.triage-list {
  display: grid;
  gap: 10px;
  margin: 18px 0;
}

.triage-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 14px;
  border-radius: 12px;
  border: 1px solid var(--gg-line);
  background: var(--gg-surface-soft);
}

.triage-item span {
  color: var(--gg-text-soft);
  font-size: 13px;
}

.triage-item strong {
  color: var(--gg-text-strong);
  font-size: 26px;
  font-weight: 900;
}

:global(.shell--immersive) .triage-item strong {
  color: #ffffff;
  text-shadow: 0 0 14px rgba(255, 255, 255, 0.32);
}

:global(.shell--immersive) .triage-item span {
  color: rgba(204, 224, 252, 0.82);
}

.triage-item--critical {
  border-color: rgba(255, 102, 120, 0.26);
  background: rgba(255, 102, 120, 0.08);
}

.triage-item--critical strong {
  color: #ff405c;
}

:global(.shell--immersive) .triage-item--critical strong {
  color: #ff6f84;
  text-shadow: 0 0 18px rgba(255, 74, 104, 0.42);
}

.triage-item--open {
  border-color: rgba(255, 198, 92, 0.24);
  background: rgba(255, 198, 92, 0.08);
}

.triage-item--open strong {
  color: #c77900;
}

:global(.shell--immersive) .triage-item--open strong {
  color: #ffd36e;
  text-shadow: 0 0 18px rgba(255, 199, 84, 0.38);
}

.triage-item--ai {
  border-color: rgba(88, 216, 196, 0.24);
  background: rgba(88, 216, 196, 0.08);
}

.triage-item--ai strong {
  color: #008f82;
}

:global(.shell--immersive) .triage-item--ai strong {
  color: #55f1df;
  text-shadow: 0 0 18px rgba(85, 241, 223, 0.36);
}

.panel-header__title {
  color: var(--gg-text-strong);
  font-size: 20px;
  font-weight: 700;
}

.panel-header__desc {
  margin-top: 6px;
  color: var(--gg-text-soft);
  font-size: 13px;
}

.filter-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
  align-items: end;
}

.filter-field {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.filter-field label {
  color: var(--gg-text-soft);
  font-size: 13px;
}

.ai-box__eyebrow {
  color: #9fb6dd;
  font-size: 12px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

.ai-box__actions {
  display: grid;
  gap: 12px;
  margin-top: 22px;
}

.ai-box__actions :deep(.el-button + .el-button) {
  margin-left: 0;
}

.dialog-loading {
  padding: 40px;
  text-align: center;
  color: var(--gg-text-soft);
}

.info-card {
  height: 100%;
  padding: 16px;
  border-radius: 18px;
  background: linear-gradient(180deg, #f7faff, #f2f6fc);
  text-align: center;
}

.info-label {
  margin-bottom: 8px;
  color: var(--gg-text-soft);
  font-size: 12px;
}

.info-value {
  color: var(--gg-text-strong);
  font-size: 15px;
  font-weight: 600;
}

.section-title {
  margin-bottom: 10px;
  padding-left: 10px;
  border-left: 3px solid var(--gg-primary);
  color: var(--gg-text-strong);
  font-size: 14px;
  font-weight: 700;
}

.scope-tag {
  margin: 0 8px 8px 0;
}

.rec-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 10px 12px;
  margin-bottom: 8px;
  border-radius: 12px;
  background: #f0f8f2;
  color: var(--gg-text);
  line-height: 1.7;
}

.report-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 16px;
}

.report-head h3 {
  margin: 0;
  color: var(--gg-text-strong);
  font-size: 18px;
}

.report-text-block,
.raw-block {
  padding: 14px 16px;
  border-radius: 16px;
  background: #f6f9fd;
  color: var(--gg-text);
  line-height: 1.75;
  font-size: 14px;
  white-space: pre-wrap;
}

@media (max-width: 1080px) {
  .situation-grid,
  .chart-grid,
  .events-grid,
  .filter-grid {
    grid-template-columns: 1fr;
  }
}
</style>
