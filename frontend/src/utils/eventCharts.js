const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']
const STATUS_ORDER = ['open', 'investigating', 'resolved']
const PROTOCOL_ORDER = ['CAN', 'ETH', 'V2X']

const SEVERITY_WEIGHT = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

function countBy(rows, key, order = []) {
  const counts = new Map(order.map((name) => [name, 0]))
  for (const row of rows) {
    const name = row?.[key] || 'unknown'
    counts.set(name, (counts.get(name) || 0) + 1)
  }
  return Array.from(counts.entries())
    .filter(([, value]) => value > 0)
    .map(([name, value]) => ({ name, value }))
}

function getTimestamp(row) {
  const timestamp = Number(row?.timestamp || row?.created_at || row?.time)
  return Number.isFinite(timestamp) ? timestamp : 0
}

function minuteStart(timestamp) {
  return Math.floor(timestamp / 60) * 60
}

function formatTrendBucket(timestamp) {
  return new Date(timestamp * 1000).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  })
}

function buildTrend(rows, options = {}) {
  const now = Number.isFinite(Number(options.now)) ? Number(options.now) : Date.now() / 1000
  const windowMinutes = Number.isFinite(Number(options.trendWindowMinutes))
    ? Math.max(1, Number(options.trendWindowMinutes))
    : 60
  const endMinute = minuteStart(now)
  const startMinute = endMinute - windowMinutes * 60
  const buckets = new Map()

  for (let minute = startMinute; minute <= endMinute; minute += 60) {
    buckets.set(minute, {
      timestamp: minute,
      name: formatTrendBucket(minute),
      total: 0,
      highRisk: 0,
    })
  }

  for (const row of rows) {
    const timestamp = getTimestamp(row)
    const bucketMinute = minuteStart(timestamp)
    if (!buckets.has(bucketMinute)) {
      continue
    }
    const existing = buckets.get(bucketMinute)
    existing.total += 1
    if (row?.severity === 'critical' || row?.severity === 'high') {
      existing.highRisk += 1
    }
  }

  return Array.from(buckets.values())
}

function buildRiskSummary(rows) {
  if (!rows.length) {
    return { riskLabel: 'CLEAR', riskScore: 0, riskHint: '暂无异常事件' }
  }

  const score = rows.reduce((sum, row) => sum + (SEVERITY_WEIGHT[row?.severity] || 0), 0)
  const maxScore = rows.length * SEVERITY_WEIGHT.critical
  const riskScore = Math.round((score / maxScore) * 100)

  if (rows.some((row) => row?.severity === 'critical')) {
    return { riskLabel: 'CRITICAL', riskScore, riskHint: '存在严重风险事件，建议立即处置' }
  }
  if (rows.some((row) => row?.severity === 'high')) {
    return { riskLabel: 'HIGH', riskScore, riskHint: '存在高危事件，建议优先调查' }
  }
  if (rows.some((row) => row?.severity === 'medium')) {
    return { riskLabel: 'MEDIUM', riskScore, riskHint: '当前以中低风险事件为主' }
  }
  return { riskLabel: 'LOW', riskScore, riskHint: '当前态势相对平稳' }
}

export function buildEventChartData(rows, options = {}) {
  const safeRows = Array.isArray(rows) ? rows : []
  const typeTop = countBy(safeRows, 'anomaly_type')
    .sort((a, b) => b.value - a.value)
    .slice(0, 5)

  return {
    severity: countBy(safeRows, 'severity', SEVERITY_ORDER),
    protocol: countBy(safeRows, 'protocol', PROTOCOL_ORDER),
    status: countBy(safeRows, 'status', STATUS_ORDER),
    typeTop,
    trend: buildTrend(safeRows, options),
    ...buildRiskSummary(safeRows),
  }
}
