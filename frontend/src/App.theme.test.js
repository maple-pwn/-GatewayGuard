import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const appVue = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')

const pulseCoreRule = appVue.match(/\.pulse-core\s*\{(?<body>[^}]+display:\s*grid[^}]+)\}/)?.groups?.body || ''
assert.match(pulseCoreRule, /-webkit-text-fill-color:\s*currentColor/)

const pulseTextRule = appVue.match(/\.pulse-core\s+:is\([^}]+?\)\s*\{(?<body>[^}]+)\}/s)?.groups?.body || ''
assert.match(pulseTextRule, /-webkit-text-fill-color:\s*currentColor/)

assert.match(
  appVue,
  /\.shell--immersive\.theme--light\s+\.immersive-topbar__clock\s+strong\s*\{[^}]*color:\s*var\(--gg-text-strong\)[^}]*-webkit-text-fill-color:\s*currentColor/s,
)
