<template>
  <div>
    <!-- 筛选栏 -->
    <el-card style="margin-bottom: 20px">
      <el-row :gutter="16" align="middle">
        <el-col :span="6">
          <el-select v-model="filter.severity" placeholder="严重程度" clearable>
            <el-option label="严重" value="critical" />
            <el-option label="高" value="high" />
            <el-option label="中" value="medium" />
            <el-option label="低" value="low" />
          </el-select>
        </el-col>
        <el-col :span="6">
          <el-select v-model="filter.status" placeholder="状态" clearable>
            <el-option label="待处理" value="open" />
            <el-option label="调查中" value="investigating" />
            <el-option label="已解决" value="resolved" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-button type="primary" @click="loadEvents">查询</el-button>
        </el-col>
      </el-row>
    </el-card>

    <!-- AI 智能分析区 -->
    <el-card style="margin-bottom: 20px; border: 1px solid #e6a23c">
      <template #header>
        <div style="display: flex; align-items: center; gap: 8px; color: #e6a23c; font-weight: bold; font-size: 16px">
          <el-icon :size="20"><MagicStick /></el-icon>
          AI 智能分析
        </div>
      </template>
      <el-row :gutter="16">
        <el-col :span="12">
          <el-button
            type="warning"
            size="large"
            style="width: 100%; height: 56px; font-size: 16px; font-weight: bold"
            @click="generateReport"
            :loading="reportLoading"
          >
            <el-icon :size="20" style="margin-right: 8px"><DataAnalysis /></el-icon>
            生成 AI 预警报告
          </el-button>
          <p style="color: #999; font-size: 12px; margin-top: 8px; text-align: center">
            基于 LLM 对最近异常事件进行综合分析并生成报告
          </p>
        </el-col>
        <el-col :span="12">
          <el-button
            type="danger"
            size="large"
            style="width: 100%; height: 56px; font-size: 16px; font-weight: bold"
            @click="batchAnalyze"
            :loading="batchLoading"
          >
            <el-icon :size="20" style="margin-right: 8px"><MagicStick /></el-icon>
            批量 AI 分析异常事件
          </el-button>
          <p style="color: #999; font-size: 12px; margin-top: 8px; text-align: center">
            对列表中的异常事件逐一调用 LLM 进行语义分析
          </p>
        </el-col>
      </el-row>
    </el-card>

    <!-- 事件列表 -->
    <el-card>
      <template #header>
        <span>异常事件列表 (共 {{ total }} 条)</span>
      </template>
      <el-table :data="events" stripe style="width: 100%">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="anomaly_type" label="类型" width="160" />
        <el-table-column label="严重程度" width="100">
          <template #default="{ row }">
            <el-tag :type="severityColor(row.severity)" size="small">
              {{ row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="confidence" label="置信度" width="90">
          <template #default="{ row }">
            {{ (row.confidence * 100).toFixed(0) }}%
          </template>
        </el-table-column>
        <el-table-column prop="protocol" label="协议" width="70" />
        <el-table-column prop="source_node" label="源节点" width="100" />
        <el-table-column prop="description" label="描述" show-overflow-tooltip />
        <el-table-column label="操作" width="140" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="warning" @click="analyzeEvent(row)" style="font-weight: bold">
              <el-icon style="margin-right: 4px"><MagicStick /></el-icon>
              AI 分析
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- AI分析结果弹窗 -->
    <el-dialog v-model="showAnalysis" title="AI 语义分析" width="720px">
      <div v-if="analysisLoading" style="text-align: center; padding: 40px">
        <el-icon class="is-loading" :size="32"><Loading /></el-icon>
        <p style="color: #909399; margin-top: 12px">正在调用 LLM 分析...</p>
      </div>
      <div v-else-if="analysisResult && !analysisResult.analyze_raw">
        <!-- 顶部摘要 -->
        <el-alert
          v-if="analysisResult.summary"
          :title="analysisResult.summary"
          :type="riskAlertType(analysisResult.risk_level)"
          show-icon
          :closable="false"
          style="margin-bottom: 16px"
        />
        <!-- 核心信息 -->
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
              <el-tag :type="riskTagType(analysisResult.risk_level)" size="large" effect="dark" style="font-size: 14px">
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
        <!-- 攻击手法 & 根因 -->
        <el-descriptions :column="1" border style="margin-bottom: 16px">
          <el-descriptions-item label="攻击手法">{{ analysisResult.attack_method || '-' }}</el-descriptions-item>
          <el-descriptions-item label="根因分析">{{ analysisResult.root_cause || '-' }}</el-descriptions-item>
        </el-descriptions>
        <!-- 影响范围 -->
        <div v-if="analysisResult.affected_scope?.length" style="margin-bottom: 16px">
          <div class="section-title">影响范围</div>
          <el-tag v-for="(s, i) in analysisResult.affected_scope" :key="i" style="margin: 0 8px 8px 0" type="warning">{{ s }}</el-tag>
        </div>
        <!-- 处置建议 -->
        <div v-if="analysisResult.recommendations?.length">
          <div class="section-title">处置建议</div>
          <div v-for="(r, i) in analysisResult.recommendations" :key="i" class="rec-item">
            <el-icon style="color: #67c23a; margin-right: 6px; flex-shrink: 0"><SuccessFilled /></el-icon>
            <span>{{ r }}</span>
          </div>
        </div>
      </div>
      <pre v-else-if="analysisResult" style="white-space: pre-wrap; font-size: 13px; line-height: 1.6; color: #606266">{{ formatRaw(analysisResult) }}</pre>
    </el-dialog>

    <!-- 预警报告弹窗 -->
    <el-dialog v-model="showReport" title="AI 预警报告" width="800px" top="5vh">
      <div v-if="reportLoading" style="text-align: center; padding: 40px">
        <el-icon class="is-loading" :size="32"><Loading /></el-icon>
        <p style="color: #909399; margin-top: 12px">正在生成预警报告，请稍候...</p>
      </div>
      <div v-else-if="reportResult && !reportResult.report_raw">
        <!-- 报告标题 & 风险等级 -->
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px">
          <h3 style="margin: 0; font-size: 18px; color: #303133">{{ reportResult.title || '预警报告' }}</h3>
          <el-tag v-if="reportResult.risk_level" :type="riskTagType(reportResult.risk_level)" size="large" effect="dark">
            {{ riskLabel(reportResult.risk_level) }}
          </el-tag>
        </div>
        <!-- 摘要 -->
        <el-alert
          v-if="reportResult.summary"
          :title="reportResult.summary"
          type="info"
          show-icon
          :closable="false"
          style="margin-bottom: 16px"
        />
        <!-- 攻击链分析 -->
        <div v-if="reportResult.attack_chain" style="margin-bottom: 16px">
          <div class="section-title">攻击链分析</div>
          <div class="report-text-block">{{ reportResult.attack_chain }}</div>
        </div>
        <!-- 事件时间线 -->
        <div v-if="reportResult.timeline?.length" style="margin-bottom: 16px">
          <div class="section-title">关键事件时间线</div>
          <el-timeline>
            <el-timeline-item v-for="(t, i) in reportResult.timeline" :key="i" :timestamp="'#' + (i + 1)" placement="top">
              {{ t }}
            </el-timeline-item>
          </el-timeline>
        </div>
        <!-- 影响评估 -->
        <div v-if="reportResult.impact_assessment" style="margin-bottom: 16px">
          <div class="section-title">影响评估</div>
          <div class="report-text-block">{{ reportResult.impact_assessment }}</div>
        </div>
        <!-- 处置建议 -->
        <div v-if="reportResult.recommendations?.length" style="margin-bottom: 16px">
          <div class="section-title">处置建议</div>
          <div v-for="(r, i) in reportResult.recommendations" :key="i" class="rec-item">
            <el-icon style="color: #67c23a; margin-right: 6px; flex-shrink: 0"><SuccessFilled /></el-icon>
            <span>{{ r }}</span>
          </div>
        </div>
        <!-- 结论 -->
        <el-alert
          v-if="reportResult.conclusion"
          :title="reportResult.conclusion"
          :type="riskAlertType(reportResult.risk_level)"
          show-icon
          :closable="false"
        />
      </div>
      <pre v-else-if="reportResult" style="white-space: pre-wrap; font-size: 13px; line-height: 1.7; color: #606266">{{ formatRaw(reportResult) }}</pre>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Loading, MagicStick, DataAnalysis, SuccessFilled } from '@element-plus/icons-vue'
import { anomalyApi, llmApi } from '../api/index.js'
import { ElMessage } from 'element-plus'

const events = ref([])
const total = ref(0)
const filter = ref({ severity: '', status: '' })
const reportLoading = ref(false)
const showAnalysis = ref(false)
const analysisLoading = ref(false)
const analysisResult = ref(null)
const batchLoading = ref(false)
const showReport = ref(false)
const reportResult = ref(null)

function severityColor(s) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[s] || 'info'
}

const FIELD_LABELS = {
  attack_type: '攻击类型', attack_method: '攻击手法', root_cause: '根因分析',
  affected_scope: '影响范围', attack_intent: '攻击意图', risk_level: '风险等级',
  recommendations: '处置建议', summary: '总结', analyze_raw: '分析结果',
  report_raw: '报告内容', title: '标题', overview: '概述',
  statistics: '统计信息', details: '详细分析', conclusion: '结论',
}

function fieldLabel(key) {
  return FIELD_LABELS[key] || key
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

async function loadEvents() {
  try {
    const params = {}
    if (filter.value.severity) params.severity = filter.value.severity
    if (filter.value.status) params.status = filter.value.status
    const res = await anomalyApi.getEvents(params)
    events.value = res.data.events
    total.value = res.data.total
  } catch (e) { console.error(e) }
}

async function analyzeEvent(row) {
  showAnalysis.value = true
  analysisLoading.value = true
  analysisResult.value = null
  try {
    const res = await llmApi.analyze(row.id)
    analysisResult.value = res.data.analysis
  } catch (e) {
    ElMessage.error('LLM 分析失败，请检查 API Key 配置')
  } finally { analysisLoading.value = false }
}

async function generateReport() {
  showReport.value = true
  reportLoading.value = true
  reportResult.value = null
  try {
    const res = await llmApi.report(10)
    reportResult.value = res.data.report
  } catch (e) {
    ElMessage.error('报告生成失败')
    showReport.value = false
  } finally { reportLoading.value = false }
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

onMounted(loadEvents)
</script>

<style scoped>
.info-card {
  background: #f5f7fa;
  border-radius: 8px;
  padding: 14px;
  text-align: center;
}
.info-label {
  font-size: 12px;
  color: #909399;
  margin-bottom: 8px;
}
.info-value {
  font-size: 14px;
  color: #303133;
  font-weight: 500;
}
.section-title {
  font-weight: bold;
  color: #303133;
  font-size: 14px;
  margin-bottom: 10px;
  padding-left: 8px;
  border-left: 3px solid #409eff;
}
.rec-item {
  display: flex;
  align-items: flex-start;
  padding: 8px 12px;
  margin-bottom: 6px;
  background: #f0f9eb;
  border-radius: 6px;
  color: #606266;
  line-height: 1.6;
}
.report-text-block {
  color: #606266;
  line-height: 1.7;
  padding: 10px 14px;
  background: #f5f7fa;
  border-radius: 6px;
  font-size: 14px;
}
</style>
