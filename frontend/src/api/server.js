const DEFAULT_SERVER_URL = 'http://114.55.164.250:8000'

function normalizeServerUrl(value) {
  const url = String(value || '').trim()
  if (!url) return ''
  return url.replace(/\/+$/, '')
}

function configuredServerUrl() {
  if (typeof window !== 'undefined') {
    const query = new URLSearchParams(window.location.search)
    const fromQuery = normalizeServerUrl(query.get('server'))
    if (fromQuery) {
      window.localStorage.setItem('gatewayGuardServerUrl', fromQuery)
      return fromQuery
    }

    const fromWindow = normalizeServerUrl(window.GATEWAY_GUARD_CONFIG?.serverUrl)
    if (fromWindow) return fromWindow

    const fromStorage = normalizeServerUrl(
      window.localStorage.getItem('gatewayGuardServerUrl'),
    )
    if (fromStorage) return fromStorage
  }

  return normalizeServerUrl(
    import.meta.env.VITE_GATEWAY_GUARD_SERVER_URL || DEFAULT_SERVER_URL,
  )
}

export const SERVER_URL = configuredServerUrl()
export const API_BASE_URL = `${SERVER_URL}/api`

export function realtimeWsUrl() {
  const base = SERVER_URL.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:')
  return `${base}/ws/realtime`
}
