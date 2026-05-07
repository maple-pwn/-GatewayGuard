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
      <el-card class="panel-card">
        <div class="console-head">
          <div class="panel-header__title">运行控制</div>
          <el-tag :type="wsStateTag" effect="plain">{{ wsStateLabel }}</el-tag>
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
            <div class="console-card__title">检测器</div>
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

        <div v-if="trainingResult" class="console-result">
          <el-alert
            :title="trainingResult.message"
            :type="trainingResult.trained ? 'success' : 'warning'"
            show-icon
            :closable="false"
          />
        </div>

        <div v-if="detectResult" class="console-result">
          <el-alert
            :title="`检测完成，发现 ${detectResult.detected} 个异常`"
            :type="detectResult.detected > 0 ? 'warning' : 'success'"
            show-icon
            :closable="false"
          />
        </div>
      </el-card>

      <el-card class="panel-card">
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

          <div class="maintenance-item">
            <div class="maintenance-item__title">快速清理</div>
            <div class="maintenance-actions">
              <el-button @click="keepRecent(500)">保留最近 500 条</el-button>
              <el-button @click="clearByProtocol('CAN')">删除 CAN</el-button>
              <el-button
                type="danger"
                class="console-action-btn console-action-btn--clear-all"
                @click="clearData"
                :loading="clearLoading"
              >
                清空全部数据
              </el-button>
            </div>
          </div>
        </div>
      </el-card>
    </section>

    <section class="section-block alert-grid">
      <div>
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
      </div>

      <div>
        <div class="section-head">
          <div>
            <div class="section-head__title">最近流量记录</div>
            <div class="section-head__desc">
              最近 50 条记录中有 {{ visibleAttackCount }} 条为模拟攻击流量。
            </div>
          </div>
        </div>

        <el-card class="panel-card table-card">
          <el-table :data="packets" stripe style="width: 100%" max-height="520">
            <el-table-column prop="protocol" label="协议" width="90" />
            <el-table-column label="类型" width="120">
              <template #default="{ row }">
                <el-tag :type="row.is_attack ? 'danger' : 'success'" effect="dark">
                  {{ attackLabel(row) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="source" label="源节点" width="130" />
            <el-table-column prop="destination" label="目标节点" width="130" />
            <el-table-column prop="msg_id" label="消息 ID" width="120" />
            <el-table-column label="时间" width="190">
              <template #default="{ row }">
                {{ new Date(row.timestamp * 1000).toLocaleString() }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </div>
    </section>

    <el-dialog v-model="showPartialClean" title="按条件清理数据" width="480px">
      <el-form label-width="100px">
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
        <el-button @click="showPartialClean = false">取消</el-button>
        <el-button type="danger" @click="doPartialClean">确认清理</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showImportDialog" title="导入抓包文件" width="480px">
      <el-form label-width="100px">
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
        <el-button @click="showImportDialog = false">取消</el-button>
        <el-button type="primary" @click="doImportFile" :loading="importLoading">
          导入
        </el-button>
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
const packets = ref([])
const scenario = ref('mixed')
const simLoading = ref(false)
const trainingLoading = ref(false)
const detectLoading = ref(false)
const clearLoading = ref(false)
const trainingResult = ref(null)
const detectResult = ref(null)
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

const wsStateTag = computed(() => ({
  connected: 'success', connecting: 'warning', disconnected: 'danger',
}[wsState.value] || 'info'))

const wsStateLabel = computed(() => ({
  connected: 'WS 已连接', connecting: 'WS 连接中', disconnected: 'WS 断开',
}[wsState.value] || 'WS 未知'))

const visibleAttackCount = computed(() =>
  packets.value.filter(packet => packet.is_attack).length,
)

const trainingStatus = ref({
  trained: false,
  vehicle_profile: 'default',
  min_train_packets: 10,
})

function severityColor(s) {
  return { critical: 'danger', high: 'warning', medium: '', low: 'info' }[s] || 'info'
}

function attackLabel(row) {
  if (!row?.is_attack) {
    return '正常'
  }
  return row.attack_type ? `恶意 / ${row.attack_type}` : '恶意'
}

async function loadData() {
  try {
    const [s, p, t] = await Promise.all([
      trafficApi.getStats(),
      trafficApi.getPackets({ limit: 50 }),
      anomalyApi.status(),
    ])
    stats.value = s.data
    packets.value = p.data
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
    trainingResult.value = res.data

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
      trainingResult.value = {
        trained: trainingStatus.value.trained,
        message: '当前为正常流量，可直接点击“训练检测器”建立基线。',
      }
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
    detectResult.value = res.data
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

async function clearData() {
  try {
    await ElMessageBox.confirm('确定要清空所有数据吗？此操作不可恢复。', '清空数据', {
      confirmButtonText: '确定清空',
      cancelButtonText: '取消',
      type: 'warning',
    })
  } catch {
    return
  }

  clearLoading.value = true
  try {
    const res = await systemApi.clearData()
    ElMessage.success(`数据已清空: ${JSON.stringify(res.data.cleared)}`)
    detectResult.value = null
    await loadData()
  } catch {
    ElMessage.error('清空数据失败')
  } finally {
    clearLoading.value = false
  }
}

async function keepRecent(n) {
  try {
    const res = await systemApi.clearPackets({ keep_recent: n })
    ElMessage.success(res.data.message)
    await loadData()
  } catch {
    ElMessage.error('清理失败')
  }
}

async function clearByProtocol(proto) {
  try {
    await ElMessageBox.confirm(
      `确定删除所有 ${proto} 报文吗？`,
      '按协议清理',
      { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }

  try {
    const res = await systemApi.clearPackets({ protocol: proto })
    ElMessage.success(res.data.message)
    await loadData()
  } catch {
    ElMessage.error('清理失败')
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

  rtWs.on('alerts', (alerts) => {
    for (const a of alerts) {
      realtimeAlerts.value.unshift(a)
      if (a.severity === 'critical' || a.severity === 'high') {
        ElNotification({
          title: '实时告警',
          message: a.description,
          type: a.severity === 'critical' ? 'error' : 'warning',
          duration: 5000,
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
.console-grid,
.alert-grid {
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

.console-card__title,
.maintenance-item__title {
  font-size: 17px;
  font-weight: 700;
  color: var(--gg-text-strong);
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
  margin-top: 16px;
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

.console-result {
  margin-top: 16px;
}

.maintenance-stack {
  display: grid;
  gap: 16px;
}

.maintenance-item {
  display: grid;
  gap: 10px;
  padding: 16px;
  border-radius: 18px;
  border: 1px solid var(--gg-line);
  background: var(--gg-surface-soft);
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
  .alert-grid,
  .console-cards,
  .console-summary {
    grid-template-columns: 1fr;
  }
}
</style>
