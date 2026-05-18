const TRAFFIC_EXPORT_COLUMNS = [
  ['protocol', '协议'],
  ['type', '类型'],
  ['source', '源节点'],
  ['destination', '目标节点'],
  ['msg_id', '消息 ID'],
  ['timestamp', '时间'],
]

function escapeCell(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

export function trafficAttackLabel(row) {
  if (!row?.is_attack) {
    return '正常'
  }
  return row.attack_type ? `恶意 / ${row.attack_type}` : '恶意'
}

export function formatTrafficTimestamp(timestamp) {
  const numericTimestamp = Number(timestamp)
  if (!Number.isFinite(numericTimestamp)) {
    return ''
  }
  return new Date(numericTimestamp * 1000).toLocaleString()
}

export function buildTrafficExcel(rows, now = new Date()) {
  const safeRows = Array.isArray(rows) ? rows : []
  const dateStamp = now.toISOString().slice(0, 19).replace(/[-:T]/g, '')
  const filename = `gatewayguard-traffic-${dateStamp}.xls`

  const headerCells = TRAFFIC_EXPORT_COLUMNS
    .map(([, label]) => `<th>${escapeCell(label)}</th>`)
    .join('')

  const bodyRows = safeRows
    .map((row) => {
      const values = {
        ...row,
        type: trafficAttackLabel(row),
        timestamp: formatTrafficTimestamp(row?.timestamp),
      }
      const cells = TRAFFIC_EXPORT_COLUMNS
        .map(([key]) => `<td>${escapeCell(values[key])}</td>`)
        .join('')
      return `<tr>${cells}</tr>`
    })
    .join('')

  const content = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <style>
    table { border-collapse: collapse; }
    th, td { border: 1px solid #9aa7b7; padding: 6px 10px; mso-number-format: "\\@"; }
    th { background: #e8eef8; font-weight: 700; }
  </style>
</head>
<body>
  <table>
    <thead><tr>${headerCells}</tr></thead>
    <tbody>${bodyRows}</tbody>
  </table>
</body>
</html>`

  return {
    filename,
    mimeType: 'application/vnd.ms-excel;charset=utf-8',
    content,
  }
}

export function downloadTrafficExcel(rows) {
  const { filename, mimeType, content } = buildTrafficExcel(rows)
  const blob = new Blob([`\ufeff${content}`], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}
