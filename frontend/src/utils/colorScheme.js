import { computed, ref } from 'vue'

export const COLOR_SCHEME_STORAGE_KEY = 'gg-color-scheme'
export const COLOR_SCHEMES = {
  LIGHT: 'light',
  DARK: 'dark',
}

export function normalizeColorScheme(value) {
  return value === COLOR_SCHEMES.LIGHT ? COLOR_SCHEMES.LIGHT : COLOR_SCHEMES.DARK
}

export function readStoredColorScheme(storage = globalThis.window?.localStorage) {
  return normalizeColorScheme(storage?.getItem?.(COLOR_SCHEME_STORAGE_KEY))
}

export function applyColorScheme(value, root = globalThis.document?.documentElement) {
  const scheme = normalizeColorScheme(value)
  if (!root) return scheme

  root.dataset.theme = scheme
  root.classList.remove('theme--light')
  root.classList.remove('theme--dark')
  root.classList.add(`theme--${scheme}`)
  return scheme
}

function persistColorScheme(value, storage = globalThis.window?.localStorage) {
  storage?.setItem?.(COLOR_SCHEME_STORAGE_KEY, normalizeColorScheme(value))
}

export const colorScheme = ref(readStoredColorScheme())
export const isLightScheme = computed(() => colorScheme.value === COLOR_SCHEMES.LIGHT)
export const isDarkScheme = computed(() => colorScheme.value === COLOR_SCHEMES.DARK)

export function setColorScheme(value) {
  colorScheme.value = normalizeColorScheme(value)
  persistColorScheme(colorScheme.value)
  applyColorScheme(colorScheme.value)
}

export function toggleColorScheme() {
  setColorScheme(isLightScheme.value ? COLOR_SCHEMES.DARK : COLOR_SCHEMES.LIGHT)
}

applyColorScheme(colorScheme.value)
