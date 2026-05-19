<template>
  <div class="console-page">
    <section class="section-block">
      <el-row :gutter="18">
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">总报文数</div>
            <div class="metric-card__value">{{ stats.total_packets }}</div>
            <div class="metric-card__meta">数据库中累计采集的全量流量记录</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">CAN / ETH / V2X</div>
            <div class="metric-card__value">{{ stats.can_count }}/{{ stats.eth_count }}/{{ stats.v2x_count }}</div>
            <div class="metric-card__meta">三类协议域的当前累计规模</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">实时采集</div>
            <div class="metric-card__value">{{ collectStatus.running ? '运行中' : '未运行' }}</div>
            <div class="metric-card__meta">当前采集器状态与 WebSocket 联动展示</div>
          </el-card>
        </el-col>
        <el-col :xs="24" :sm="12" :xl="6">
          <el-card class="portal-card metric-card">
            <div class="metric-card__label">训练状态</div>
            <div class="metric-card__value">{{ trainingStatus.trained ? '已训练' : '未训练' }}</div>
            <div class="metric-card__meta">异常检测是否具备可执行的基线模型</div>
          </el-card>
        </el-col>
      </el-row>
    </section>

    <section class="section-block console-grid">
      <el-card class="panel-card console-control-panel">
        <div class="console-head">
          <div class="panel-header__title">运行控制</div>
          <el-tag class="ws-state-chip" :class="`ws-state-chip--${wsState}`" effect="plain">
            {{ wsStateLabel }}
          </el-tag>
        </div>

        <div class="console-cards">
          <div class="console-card">
            <div class="console-card__title">模拟流量</div>
            <div class="console-row">
              <el-select v-model="scenario">
                <el-option label="正常流量" value="normal" />
                <el-option label="DoS 攻击" value="dos" />
                <el-option label="Fuzzy 攻击" value="fuzzy" />
                <el-option label="Spoofing 攻击" value="spoofing" />
                <el-option label="混合场景" value="mixed" />
              </el-select>
            </div>
            <el-button
              type="primary"
              class="console-action-btn console-action-btn--simulate"
              @click="simulateTraffic"
              :loading="simLoading"
            >
              生成模拟流量
            </el-button>
          </div>

          <div class="console-card">
            <div class="console-card__head">
              <div class="console-card__title">检测器</div>
              <el-tag
                class="ws-state-chip detector-state-chip"
                :class="detectorStateClass"
                effect="plain"
              >
                {{ detectorStateLabel }}
              </el-tag>
            </div>
            <div class="console-actions">
              <el-button
                type="warning"
                class="console-action-btn console-action-btn--train"
                @click="trainDetector()"
                :loading="trainingLoading"
              >
                训练检测器
              </el-button>
              <el-button
                type="danger"
                class="console-action-btn console-action-btn--detect"
                @click="runDetection"
                :loading="detectLoading"
              >
                执行异常检测
              </el-button>
            </div>
            <div class="console-hint">建议先在“正常流量”场景下完成基线训练。</div>
          </div>

          <div class="console-card">
            <div class="console-card__title">实时流量</div>
            <div class="console-row">
              <el-select v-model="sourceMode" :disabled="collectStatus.running">
                <el-option label="模拟器" value="simulator" />
                <el-option label="CAN 总线" value="can" />
                <el-option label="以太网" value="ethernet" />
                <el-option label="PCAP 文件" value="pcap" />
                <el-option label="多源混合" value="multi" />
              </el-select>
            </div>
            <div class="console-actions">
              <el-button
                type="success"
                class="console-action-btn console-action-btn--collect"
                @click="startCollect"
                :loading="collectLoading"
                :disabled="collectStatus.running"
              >
                启动采集
              </el-button>
              <el-button
                @click="stopCollect"
                :loading="collectLoading"
                :disabled="!collectStatus.running"
              >
                停止采集
              </el-button>
            </div>
          </div>
        </div>

        <div class="console-summary">
          <div class="summary-box">
            <span>当前模式</span>
            <strong>{{ sourceMode.toUpperCase() }}</strong>
          </div>
          <div class="summary-box">
            <span>已采集</span>
            <strong>{{ collectStatus.total_collected || 0 }}</strong>
          </div>
          <div class="summary-box">
            <span>异常数</span>
            <strong>{{ collectStatus.total_anomalies || 0 }}</strong>
          </div>
        </div>

      </el-card>

      <el-card class="panel-card maintenance-panel">
        <template #header>
          <div class="panel-header">
            <div>
              <div class="panel-header__title">数据维护</div>
            </div>
          </div>
        </template>

        <div class="maintenance-stack">
          <div class="maintenance-item">
            <div class="maintenance-item__title">导入抓包文件</div>
            <div class="maintenance-item__desc">支持服务器上已有的 `pcap / pcapng / blf / asc` 文件。</div>
            <el-button
              type="primary"
              plain
              class="console-action-btn console-action-btn--import"
              @click="showImportDialog = true"
            >
              打开导入面板
            </el-button>
          </div>

          <div class="maintenance-item">
            <div class="maintenance-item__title">按条件清理</div>
            <div class="maintenance-item__desc">可按协议、严重程度或保留最近 N 条记录做细粒度清理。</div>
            <el-button
              type="warning"
              plain
              class="console-action-btn console-action-btn--partial-clean"
              @click="showPartialClean = true"
            >
              按条件清理
            </el-button>
          </div>
        </div>
      </el-card>
    </section>

    <section class="section-block">
      <div class="section-head">
        <div>
          <div class="section-head__title">实时告警流</div>
          <div class="section-head__desc">保留 WebSocket 驱动的异常推送，作为控制台下方的动态结果区。</div>
        </div>
        <el-button text @click="realtimeAlerts = []" :disabled="!realtimeAlerts.length">清空</el-button>
      </div>

      <el-card class="panel-card alert-card">
        <div v-if="realtimeAlerts.length" class="alert-stream">
          <div v-for="(alert, idx) in realtimeAlerts" :key="idx" class="alert-item">
            <div class="alert-item__marker" :class="`severity-${alert.severity}`" />
            <div class="alert-item__body">
              <div class="alert-item__meta">
                <el-tag :type="severityColor(alert.severity)" size="small">{{ alert.severity }}</el-tag>
                <span>{{ new Date(alert.timestamp * 1000).toLocaleTimeString() }}</span>
              </div>
              <div class="alert-item__text">{{ alert.description }}</div>
            </div>
          </div>
        </div>
        <el-empty v-else description="当前没有新的实时告警" />
      </el-card>
    </section>

    <el-dialog
      v-model="showPartialClean"
      width="480px"
      class="maintenance-dialog"
      modal-class="maintenance-dialog-modal"
      :show-close="false"
    >
      <div class="maintenance-dialog__head">
        <div class="maintenance-dialog__title">按条件清理数据</div>
        <button type="button" class="maintenance-dialog__close" @click="showPartialClean = false">×</button>
      </div>
      <el-form class="maintenance-dialog__form" label-width="100px">
        <el-form-item label="清理目标">
          <el-radio-group v-model="cleanTarget">
            <el-radio value="packets">流量报文</el-radio>
            <el-radio value="anomalies">异常事件</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="清理方式">
          <el-radio-group v-model="cleanMode">
            <el-radio value="keep_recent">保留最近N条</el-radio>
            <el-radio value="by_type">按类型删除</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="cleanMode === 'keep_recent'" label="保留条数">
          <el-input-number v-model="keepCount" :min="10" :max="5000" :step="50" />
        </el-form-item>
        <el-form-item v-if="cleanMode === 'by_type' && cleanTarget === 'packets'" label="协议">
          <el-select v-model="cleanProtocol">
            <el-option label="CAN" value="CAN" />
            <el-option label="ETH" value="ETH" />
            <el-option label="V2X" value="V2X" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="cleanMode === 'by_type' && cleanTarget === 'anomalies'" label="严重程度">
          <el-select v-model="cleanSeverity">
            <el-option label="低 (low)" value="low" />
            <el-option label="中 (medium)" value="medium" />
            <el-option label="高 (high)" value="high" />
            <el-option label="严重 (critical)" value="critical" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="maintenance-dialog__footer">
          <el-button class="maintenance-dialog__cancel" @click="showPartialClean = false">取消</el-button>
          <el-button class="maintenance-dialog__danger" type="danger" @click="doPartialClean">确认清理</el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog
      v-model="showImportDialog"
      width="480px"
      class="maintenance-dialog"
      modal-class="maintenance-dialog-modal"
      :show-close="false"
    >
      <div class="maintenance-dialog__head">
        <div class="maintenance-dialog__title">导入抓包文件</div>
        <button type="button" class="maintenance-dialog__close" @click="showImportDialog = false">×</button>
      </div>
      <el-form class="maintenance-dialog__form" label-width="100px">
        <el-form-item label="文件路径">
          <el-input
            v-model="importFilePath"
            placeholder="服务器上的文件路径，如 /data/capture.pcap"
          />
        </el-form-item>
        <el-form-item>
          <span class="dialog-tip">支持格式: .pcap / .pcapng / .blf / .asc</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="maintenance-dialog__footer">
          <el-button class="maintenance-dialog__cancel" @click="showImportDialog = false">取消</el-button>
          <el-button class="maintenance-dialog__primary" type="primary" @click="doImportFile" :loading="importLoading">
            导入
          </el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { trafficApi, anomalyApi, systemApi } from '../api/index.js'
import { createRealtimeWs } from '../api/ws.js'
import { ElMessage, ElMessageBox, ElNotification } from 'element-plus'

const stats = ref({ total_packets: 0, can_count: 0, eth_count: 0, v2x_count: 0 })
const scenario = ref('mixed')
const simLoading = ref(false)
const trainingLoading = ref(false)
const detectLoading = ref(false)
const showPartialClean = ref(false)
const cleanTarget = ref('packets')
const cleanMode = ref('keep_recent')
const keepCount = ref(200)
const cleanProtocol = ref('CAN')
const cleanSeverity = ref('low')
const sourceMode = ref('simulator')
const collectStatus = ref({ running: false, total_collected: 0, total_anomalies: 0 })
const collectLoading = ref(false)
const showImportDialog = ref(false)
const importFilePath = ref('')
const importLoading = ref(false)
let pollTimer = null

const wsState = ref('disconnected')
const realtimeAlerts = ref([])
let rtWs = null

const wsStateLabel = computed(() => ({
  connected: 'WS 已连接', connecting: 'WS 连接中', disconnected: 'WS 断开',
}[wsState.value] || 'WS 未知'))
const detectorStateLabel = computed(() => {
  if (trainingLoading.value) return '训练中'
  return trainingStatus.value.trained ? '检测器已训练' : '检测器未训练'
})
const detectorStateClass = computed(() => {
  if (trainingLoading.value) return 'ws-state-chip--connecting'
  return trainingStatus.value.trained ? 'ws-state-chip--connected' : 'ws-state-chip--disconnected'
})

const trainingStatus = ref({
  trained: false,
  vehicle_profile: 'default',
  min_train_packets: 10,
})

function severityColor(s) {
  return { critical: 'danger', high: 'warning', medium: '', low: 'info' }[s] || 'info'
}

async function loadData() {
  try {
    const [s, t] = await Promise.all([
      trafficApi.getStats(),
      anomalyApi.status(),
    ])
    stats.value = s.data
    trainingStatus.value = t.data
  } catch (e) {
    console.error(e)
  }
}

async function trainDetector(limit = 2000) {
  trainingLoading.value = true
  try {
    const res = await anomalyApi.train(limit)
    trainingStatus.value = {
      trained: Boolean(res?.data?.trained),
      vehicle_profile: res?.data?.vehicle_profile || trainingStatus.value.vehicle_profile,
      min_train_packets: Number(
        res?.data?.min_train_packets || trainingStatus.value.min_train_packets || 10,
      ),
    }
    if (res?.data?.trained) {
      ElMessage.success(
        `训练完成，使用 ${res?.data?.packet_count || 0} 条流量建立基线`,
      )
      return true
    }

    ElMessage.warning(res?.data?.message || '训练未完成')
    return false
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || '训练失败')
    return false
  } finally {
    trainingLoading.value = false
  }
}

async function simulateTraffic() {
  simLoading.value = true
  try {
    const res = await trafficApi.simulate(scenario.value, 200)
    const generated = Number(res?.data?.generated || 0)
    const attackPackets = Number(res?.data?.attack_packets || 0)
    ElMessage.success(
      attackPackets > 0
        ? `已生成 ${generated} 条模拟流量，其中 ${attackPackets} 条为恶意流量`
        : `已生成 ${generated} 条模拟流量`,
    )
    if (scenario.value === 'normal') {
      ElMessage.info('当前为正常流量，可直接点击“训练检测器”建立基线。')
    }
    await loadData()
  } catch {
    ElMessage.error('生成模拟流量失败')
  } finally {
    simLoading.value = false
  }
}

async function runDetection() {
  detectLoading.value = true
  try {
    const res = await anomalyApi.detect(500)
    ElMessage.success(`检测完成，发现 ${res?.data?.detected ?? 0} 个异常`)
  } catch (e) {
    const status = e?.response?.status
    const detail = e?.response?.data?.detail

    if (status === 428) {
      try {
        await ElMessageBox.confirm(
          '检测器当前未完成训练。是否立即使用当前流量训练基线，然后继续执行异常检测？\n\n建议优先在“正常流量”场景下完成训练。',
          '检测器未训练',
          {
            confirmButtonText: '立即训练',
            cancelButtonText: '取消',
            type: 'warning',
          },
        )
      } catch {
        return
      }

      const trained = await trainDetector(2000)
      if (trained) {
        await runDetection()
      }
      return
    }

    ElMessage.error(detail || '执行异常检测失败')
  } finally {
    detectLoading.value = false
  }
}

async function doPartialClean() {
  const params = {}
  if (cleanMode.value === 'keep_recent') {
    params.keep_recent = keepCount.value
  } else if (cleanTarget.value === 'packets') {
    params.protocol = cleanProtocol.value
  } else {
    params.severity = cleanSeverity.value
  }

  try {
    const apiFn = cleanTarget.value === 'packets'
      ? systemApi.clearPackets
      : systemApi.clearAnomalies
    const res = await apiFn(params)
    ElMessage.success(res.data.message)
    showPartialClean.value = false
    await loadData()
  } catch {
    ElMessage.error('清理失败')
  }
}

async function fetchCollectStatus() {
  try {
    const res = await trafficApi.collectStatus()
    collectStatus.value = res.data
  } catch {
    // ignore
  }
}

async function startCollect() {
  collectLoading.value = true
  try {
    const res = await trafficApi.collectStart(sourceMode.value)
    if (res.data.error) {
      ElMessage.warning(res.data.error)
    } else {
      ElMessage.success(`采集已启动 (${sourceMode.value})`)
      collectStatus.value.running = true
    }
  } finally {
    collectLoading.value = false
  }
}

async function stopCollect() {
  collectLoading.value = true
  try {
    await trafficApi.collectStop()
    ElMessage.info('采集已停止')
    collectStatus.value.running = false
    await loadData()
  } finally {
    collectLoading.value = false
  }
}

async function doImportFile() {
  if (!importFilePath.value.trim()) {
    ElMessage.warning('请输入文件路径')
    return
  }

  importLoading.value = true
  try {
    const res = await trafficApi.importFile(importFilePath.value.trim())
    if (res.data.error) {
      ElMessage.error(res.data.error)
    } else {
      ElMessage.success(`成功导入 ${res.data.imported} 条报文`)
      showImportDialog.value = false
      importFilePath.value = ''
      await loadData()
    }
  } catch {
    ElMessage.error('导入失败')
  } finally {
    importLoading.value = false
  }
}

function initWebSocket() {
  rtWs = createRealtimeWs()

  rtWs.on('state', (s) => {
    wsState.value = s
  })

  rtWs.on('stats_update', (data) => {
    collectStatus.value = data
    if (!pollTimer) {
      pollTimer = setInterval(() => loadData(), 5000)
    }
  })

  rtWs.on('traffic_update', (data) => {
    if (data?.stats) {
      stats.value = data.stats
    }
    if (!pollTimer) {
      pollTimer = setInterval(() => loadData(), 5000)
    }
  })

  rtWs.on('alerts', (alerts) => {
    for (const a of alerts) {
      realtimeAlerts.value.unshift(a)
      if (a.severity === 'critical' || a.severity === 'high') {
        ElNotification({
          title: '实时告警',
          message: a.description,
          type: a.severity === 'critical' ? 'error' : 'warning',
          duration: 5000,
          customClass: a.severity === 'critical'
            ? 'gg-critical-notification'
            : 'gg-console-notification',
        })
      }
    }
    if (realtimeAlerts.value.length > 20) {
      realtimeAlerts.value = realtimeAlerts.value.slice(0, 20)
    }
  })
}

onMounted(async () => {
  await loadData()
  await fetchCollectStatus()
  initWebSocket()
})

onUnmounted(() => {
  if (rtWs) {
    rtWs.close()
    rtWs = null
  }
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
})
</script>

<style scoped>
.console-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.35fr) minmax(320px, 0.85fr);
  gap: 18px;
}

.console-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 18px;
}

.ws-state-chip {
  --el-tag-bg-color: rgba(61, 103, 255, 0.1);
  --el-tag-border-color: rgba(61, 103, 255, 0.24);
  --el-tag-text-color: #3159b8;
  border-radius: 999px;
  font-family: var(--gg-font-ui);
  font-weight: 800;
  letter-spacing: 0.06em;
}

.ws-state-chip--connected {
  --el-tag-bg-color: rgba(38, 139, 119, 0.1);
  --el-tag-border-color: rgba(49, 145, 125, 0.38);
  --el-tag-text-color: #287f72;
}

.ws-state-chip--connecting {
  --el-tag-bg-color: rgba(168, 124, 36, 0.12);
  --el-tag-border-color: rgba(176, 132, 45, 0.42);
  --el-tag-text-color: #9d7320;
}

.ws-state-chip--disconnected {
  --el-tag-bg-color: rgba(94, 20, 35, 0.14);
  --el-tag-border-color: rgba(134, 39, 58, 0.5);
  --el-tag-text-color: #953349;
}

:global(.shell--immersive) .ws-state-chip--connected {
  --el-tag-bg-color: rgba(31, 112, 98, 0.22);
  --el-tag-border-color: rgba(78, 185, 165, 0.36);
  --el-tag-text-color: #a4e6da;
}

:global(.shell--immersive) .ws-state-chip--connecting {
  --el-tag-bg-color: rgba(105, 78, 22, 0.26);
  --el-tag-border-color: rgba(213, 164, 61, 0.42);
  --el-tag-text-color: #f1d28b;
}

:global(.shell--immersive) .ws-state-chip--disconnected {
  --el-tag-bg-color: rgba(78, 17, 32, 0.32);
  --el-tag-border-color: rgba(176, 55, 76, 0.46);
  --el-tag-text-color: #ebb0ba;
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
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

.console-cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}

.console-card {
  display: grid;
  gap: 12px;
  padding: 16px;
  border-radius: 18px;
  border: 1px solid var(--gg-line);
  background: var(--gg-surface-soft);
}

.console-card__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  min-height: 26px;
}

.console-card__title,
.maintenance-item__title {
  font-size: 17px;
  font-weight: 700;
  color: var(--gg-text-strong);
}

.detector-state-chip {
  flex: 0 0 auto;
  min-height: 24px;
  padding: 0 10px;
  font-size: 12px;
  letter-spacing: 0.04em;
}

.console-row,
.maintenance-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.console-actions {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  align-items: stretch;
}

.console-actions :deep(.el-button) {
  width: 100%;
  margin: 0;
}

.console-summary {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
  margin-top: 12px;
}

.console-control-panel {
  align-self: start;
}

.console-control-panel :deep(.el-card__body) {
  padding-bottom: 16px;
}

.summary-box {
  padding: 16px;
  border-radius: 16px;
  border: 1px solid var(--gg-line);
  background: #fff;
}

.summary-box span {
  display: block;
  color: var(--gg-text-soft);
  font-size: 12px;
}

.summary-box strong {
  display: block;
  margin-top: 8px;
  font-size: 24px;
  color: var(--gg-text-strong);
}

.console-hint,
.maintenance-item__desc,
.dialog-tip {
  color: var(--gg-text-soft);
  line-height: 1.7;
  font-size: 13px;
}

.maintenance-stack {
  display: grid;
  gap: 10px;
  align-content: start;
}

.maintenance-panel {
  align-self: start;
}

.maintenance-panel :deep(.el-card__header) {
  padding-bottom: 6px;
  border-bottom: 0 !important;
}

.maintenance-panel :deep(.el-card__body) {
  padding-top: 4px;
  padding-bottom: 16px;
}

.maintenance-item {
  display: grid;
  gap: 9px;
  min-height: 112px;
  align-content: start;
  padding: 14px 16px;
  border-radius: 16px;
  border: 1px solid rgba(61, 103, 255, 0.18);
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(239, 246, 255, 0.9)),
    linear-gradient(90deg, rgba(14, 165, 183, 0.08), transparent);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.76);
}

.maintenance-item__title {
  color: #ffffff;
  font-size: 16px;
  text-shadow: 0 0 16px rgba(93, 215, 255, 0.18);
}

.maintenance-item__desc {
  color: var(--gg-text-soft);
  font-size: 13px;
  line-height: 1.55;
}

.maintenance-item :deep(.el-button) {
  justify-self: start;
  min-height: 38px;
  border-radius: 999px;
  font-weight: 800;
  letter-spacing: 0.04em;
}

:global(.shell--immersive) .maintenance-item {
  border-color: rgba(93, 215, 255, 0.18) !important;
  background:
    linear-gradient(180deg, rgba(16, 34, 57, 0.82), rgba(8, 18, 32, 0.78)),
    linear-gradient(90deg, rgba(93, 215, 255, 0.1), transparent) !important;
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.08),
    0 18px 42px rgba(0, 0, 0, 0.2);
}

:global(.shell--immersive) .maintenance-item__desc {
  color: rgba(188, 214, 248, 0.78) !important;
}

:global(.maintenance-dialog) {
  overflow: hidden;
  border: 1px solid rgba(93, 215, 255, 0.22);
  border-radius: 20px;
  background:
    radial-gradient(420px 180px at 100% 0%, rgba(61, 103, 255, 0.18), transparent 72%),
    radial-gradient(320px 160px at 0% 100%, rgba(14, 165, 183, 0.13), transparent 70%),
    linear-gradient(180deg, rgba(15, 31, 52, 0.96), rgba(7, 16, 29, 0.96));
  box-shadow:
    0 28px 80px rgba(0, 0, 0, 0.42),
    0 0 34px rgba(93, 215, 255, 0.12),
    inset 0 1px 0 rgba(255, 255, 255, 0.08);
  backdrop-filter: blur(18px);
}

:global(.maintenance-dialog-modal) {
  background:
    radial-gradient(760px 420px at 50% 42%, rgba(20, 45, 76, 0.28), transparent 68%),
    rgba(2, 7, 13, 0.72);
  backdrop-filter: blur(10px);
}

:global(.maintenance-dialog .el-dialog__header) {
  display: none;
}

:global(.maintenance-dialog .el-dialog__body) {
  padding: 0;
  color: rgba(218, 233, 255, 0.84);
}

:global(.maintenance-dialog .el-dialog__footer) {
  padding: 8px 22px 20px;
}

.maintenance-dialog__head {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 18px 22px 12px;
  border-bottom: 1px solid rgba(93, 215, 255, 0.14);
}

.maintenance-dialog__head::after {
  position: absolute;
  left: 22px;
  bottom: -1px;
  width: 92px;
  height: 1px;
  content: '';
  background: linear-gradient(90deg, rgba(93, 215, 255, 0.92), transparent);
  box-shadow: 0 0 12px rgba(93, 215, 255, 0.45);
}

.maintenance-dialog__title {
  color: #f4f8ff;
  font-family: var(--gg-font-ui);
  font-size: 18px;
  font-weight: 800;
  letter-spacing: 0.06em;
}

.maintenance-dialog__close {
  display: grid;
  place-items: center;
  width: 34px;
  height: 34px;
  border: 1px solid rgba(93, 215, 255, 0.16);
  border-radius: 999px;
  color: rgba(218, 233, 255, 0.82);
  background: rgba(255, 255, 255, 0.06);
  font-size: 20px;
  line-height: 1;
  cursor: pointer;
}

.maintenance-dialog__form {
  padding: 18px 22px 0;
}

.maintenance-dialog__form :deep(.el-form-item) {
  margin-bottom: 18px;
}

.maintenance-dialog__form :deep(.el-form-item__label) {
  color: rgba(188, 214, 248, 0.82);
  font-family: var(--gg-font-ui);
  font-weight: 700;
  letter-spacing: 0.04em;
}

.maintenance-dialog__form :deep(.el-radio) {
  --el-radio-text-color: rgba(218, 233, 255, 0.82);
  --el-radio-input-border-color: rgba(93, 215, 255, 0.36);
  --el-radio-checked-text-color: #f4f8ff;
  margin-right: 18px;
}

.maintenance-dialog__form :deep(.el-radio__inner) {
  background: rgba(6, 16, 30, 0.72);
  border-color: rgba(93, 215, 255, 0.34);
}

.maintenance-dialog__form :deep(.el-radio__input.is-checked .el-radio__inner) {
  border-color: rgba(93, 215, 255, 0.95);
  background: #5dd7ff;
  box-shadow: 0 0 14px rgba(93, 215, 255, 0.45);
}

.maintenance-dialog__form :deep(.el-input__wrapper),
.maintenance-dialog__form :deep(.el-select__wrapper),
.maintenance-dialog__form :deep(.el-input-number),
.maintenance-dialog__form :deep(.el-input-number .el-input__wrapper) {
  border: 1px solid rgba(93, 215, 255, 0.18);
  background: rgba(4, 13, 25, 0.58);
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.06),
    0 0 0 1px rgba(61, 103, 255, 0.08);
}

.maintenance-dialog__form :deep(.el-input__wrapper.is-focus),
.maintenance-dialog__form :deep(.el-select__wrapper.is-focused) {
  border-color: rgba(93, 215, 255, 0.58);
  box-shadow:
    0 0 0 1px rgba(93, 215, 255, 0.2),
    0 0 18px rgba(93, 215, 255, 0.14);
}

.maintenance-dialog__form :deep(.el-input__inner),
.maintenance-dialog__form :deep(.el-select__placeholder),
.maintenance-dialog__form :deep(.el-input-number .el-input__inner) {
  color: #f4f8ff;
}

.maintenance-dialog__form :deep(.el-input__inner::placeholder) {
  color: rgba(188, 214, 248, 0.46);
}

.maintenance-dialog__form :deep(.el-input-number__decrease),
.maintenance-dialog__form :deep(.el-input-number__increase) {
  border-color: rgba(93, 215, 255, 0.16);
  color: rgba(188, 214, 248, 0.78);
  background:
    linear-gradient(180deg, rgba(18, 42, 70, 0.92), rgba(8, 19, 34, 0.92));
}

.maintenance-dialog__form :deep(.el-input-number__decrease:hover),
.maintenance-dialog__form :deep(.el-input-number__increase:hover) {
  color: #5dd7ff;
  background:
    linear-gradient(180deg, rgba(35, 78, 121, 0.92), rgba(13, 35, 59, 0.92));
}

.maintenance-dialog__form :deep(.el-input-number__decrease.is-disabled),
.maintenance-dialog__form :deep(.el-input-number__increase.is-disabled) {
  color: rgba(188, 214, 248, 0.32);
  background: rgba(255, 255, 255, 0.04);
}

.maintenance-dialog__form .dialog-tip {
  color: rgba(188, 214, 248, 0.78);
}

.maintenance-dialog__footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

.maintenance-dialog__footer :deep(.el-button) {
  min-width: 96px;
  min-height: 38px;
  margin-left: 0;
  border-radius: 999px;
  font-family: var(--gg-font-ui);
  font-weight: 800;
  letter-spacing: 0.06em;
}

.maintenance-dialog__cancel {
  border-color: rgba(188, 214, 248, 0.22) !important;
  color: rgba(218, 233, 255, 0.82) !important;
  background: rgba(255, 255, 255, 0.06) !important;
}

.maintenance-dialog__primary {
  border-color: rgba(93, 215, 255, 0.5) !important;
  background: linear-gradient(135deg, rgba(47, 104, 255, 0.92), rgba(14, 165, 183, 0.84)) !important;
  box-shadow: 0 0 22px rgba(93, 215, 255, 0.18);
}

.maintenance-dialog__danger {
  border-color: rgba(255, 99, 125, 0.42) !important;
  background: linear-gradient(135deg, rgba(122, 22, 41, 0.94), rgba(190, 48, 72, 0.78)) !important;
  box-shadow: 0 0 22px rgba(217, 75, 101, 0.18);
}

.alert-card :deep(.el-card__body) {
  padding-top: 8px;
}

.alert-stream {
  display: grid;
  gap: 14px;
}

.alert-item {
  display: flex;
  gap: 14px;
  padding: 16px 4px;
  border-bottom: 1px solid var(--gg-line);
}

.alert-item:last-child {
  border-bottom: none;
}

.alert-item__marker {
  width: 10px;
  min-width: 10px;
  border-radius: 999px;
  background: #8da4bb;
}

.alert-item__marker.severity-critical,
.alert-item__marker.severity-high {
  background: var(--gg-danger);
}

.alert-item__marker.severity-medium {
  background: var(--gg-warning);
}

.alert-item__marker.severity-low {
  background: var(--gg-accent);
}

.alert-item__body {
  flex: 1;
}

.alert-item__meta {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--gg-text-soft);
  font-size: 12px;
}

.alert-item__text {
  margin-top: 8px;
  line-height: 1.7;
}

@media (max-width: 1180px) {
  .console-grid,
  .console-cards,
  .console-summary {
    grid-template-columns: 1fr;
  }
}
</style>
