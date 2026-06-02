import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const css = readFileSync(new URL('./theme.css', import.meta.url), 'utf8')
const aboutVue = readFileSync(new URL('../views/About.vue', import.meta.url), 'utf8')
const dashboardVue = readFileSync(new URL('../views/Dashboard.vue', import.meta.url), 'utf8')
const anomalyVue = readFileSync(new URL('../views/Anomaly.vue', import.meta.url), 'utf8')
const chatVue = readFileSync(new URL('../views/Chat.vue', import.meta.url), 'utf8')

const darkTokenBlock = css.match(/\.shell--immersive\.theme--dark\s*\{(?<body>[^}]+)\}/)?.groups?.body || ''

assert.match(darkTokenBlock, /--gg-text:\s*#[0-9a-fA-F]{6}/)
assert.match(darkTokenBlock, /--gg-text-soft:\s*#[0-9a-fA-F]{6}/)
assert.match(darkTokenBlock, /--gg-text-strong:\s*#[0-9a-fA-F]{6}/)
assert.match(darkTokenBlock, /--gg-surface:\s*rgba?\(/)
assert.match(darkTokenBlock, /--gg-surface-soft:\s*rgba?\(/)
assert.match(darkTokenBlock, /--gg-line:\s*rgba?\(/)

const darkReadableTextRule = css.match(/\.shell--immersive\.theme--dark\s+:is\([^}]+?\)\s*\{[^}]+\}/s)?.[0] || ''
assert.match(darkReadableTextRule, /-webkit-text-fill-color:\s*currentColor/)
assert.match(css, /\.immersive-nav/)
assert.match(darkReadableTextRule, /immersive-nav/)
assert.match(darkReadableTextRule, /theme-toggle/)
assert.match(darkReadableTextRule, /immersive-topbar/)
assert.match(darkReadableTextRule, /el-textarea/)
assert.doesNotMatch(darkReadableTextRule, /about-page--immersive/)

const lightReadableTextRule = css.match(/\.shell--immersive\.theme--light\s+:is\([^}]+?\)\s*\{[^}]+\}/s)?.[0] || ''
assert.match(lightReadableTextRule, /-webkit-text-fill-color:\s*currentColor/)
assert.match(lightReadableTextRule, /immersive-nav/)
assert.match(lightReadableTextRule, /el-textarea/)
assert.match(lightReadableTextRule, /table-card/)
assert.doesNotMatch(lightReadableTextRule, /metric-card__value/)

assert.match(
  css,
  /html\.theme--light\s+:is\([^}]+?\.el-overlay[\s\S]+?\.ai-report-dialog[\s\S]+?\)\s*\{[^}]*-webkit-text-fill-color:\s*currentColor/s,
)
assert.match(
  css,
  /\.shell--immersive\.theme--light\s+\.table-card\s+\.el-table\s*\{[^}]*--el-table-header-bg-color:\s*rgba\(230,\s*240,\s*255,\s*0\.94\)/s,
)
assert.match(
  css,
  /\.shell--immersive\.theme--light\s+\.el-button--default[\s\S]+background:\s*linear-gradient\(180deg,\s*rgba\(255,\s*255,\s*255,\s*0\.92\),\s*rgba\(230,\s*240,\s*255,\s*0\.84\)\)/s,
)
assert.match(
  css,
  /\.shell--immersive\.theme--light\s+\.el-input__wrapper[\s\S]+background:\s*rgba\(255,\s*255,\s*255,\s*0\.94\)/s,
)
assert.match(
  css,
  /\.shell--immersive\.theme--light\s+\.message-row--user\s+:is\(\.message-bubble__role,\s*\.message-bubble__text\)\s*\{[^}]*color:\s*#ffffff !important;[^}]*-webkit-text-fill-color:\s*currentColor !important/s,
)
assert.match(
  css,
  /\.shell--immersive\.theme--light\s+\.events-page\s+\.ai-action-btn--clear\.el-button\s*\{[^}]*color:\s*#b4233f !important;[^}]*background:\s*linear-gradient\(180deg,\s*rgba\(255,\s*247,\s*250,\s*0\.96\),\s*rgba\(255,\s*232,\s*238,\s*0\.88\)\)\s*!important/s,
)
assert.match(
  css,
  /html\.theme--light\s+\.el-message\s*\{[^}]*background:\s*linear-gradient\(180deg,\s*rgba\(255,\s*255,\s*255,\s*0\.98\),\s*rgba\(236,\s*245,\s*255,\s*0\.94\)\)\s*!important/s,
)
assert.match(
  css,
  /html\.theme--light\s+\.el-message\.el-message--success\s*\{[^}]*border-color:\s*rgba\(41,\s*178,\s*145,\s*0\.28\)\s*!important/s,
)
assert.match(
  css,
  /\.shell--immersive\.theme--light\s+:is\([^}]+?\.maintenance-item__title[\s\S]+?\.immersive-head__meta h1[\s\S]+?\.panel-card--dark :is\(h1,\s*h2,\s*h3,\s*strong\)[\s\S]+?\)\s*\{[^}]*color:\s*var\(--gg-text-strong\)[^}]*-webkit-text-fill-color:\s*currentColor/s,
)
assert.match(
  css,
  /\.shell--immersive\.theme--light\s+:is\([^}]+?\.maintenance-item__desc[\s\S]+?\.immersive-head__meta p[\s\S]+?\)\s*\{[^}]*color:\s*var\(--gg-text-soft\)/s,
)

const transparentRules = [...`${css}\n${aboutVue}`.matchAll(/(?<selector>[^{}]+)\{(?<body>[^{}]*-webkit-text-fill-color:\s*transparent[^{}]*)\}/g)]
assert.ok(transparentRules.length >= 2)
for (const rule of transparentRules) {
  assert.match(rule.groups.selector, /metric-card__value/)
}

assert.match(css, /\.shell--immersive\.theme--dark\s+\.metric-card__value\s*>\s*\*\s*\{[^}]*-webkit-text-fill-color:\s*currentColor/s)

const aboutStyle = aboutVue.match(/<style scoped>(?<body>[\s\S]+)<\/style>/)?.groups?.body || ''
assert.match(aboutStyle, /\.about-page--immersive\s+\.about-hero__copy/)
assert.match(aboutStyle, /\.about-page--immersive\s+\.metric-card__value\s*\{[^}]*-webkit-text-fill-color:\s*transparent/s)
assert.doesNotMatch(aboutStyle, /:global\(\.shell--immersive\.theme--dark\)\s+\.about-page--immersive/)
assert.match(aboutStyle, /:global\(\.shell--immersive\.theme--light\)\s+\.about-page--immersive\s+\{[^}]*color:\s*#10233d/s)
assert.match(aboutStyle, /button,\s*button \*,\s*a,\s*a \*,\s*div,\s*div \*,\s*span,\s*strong,\s*p,\s*li,\s*label,\s*small/s)
assert.match(aboutStyle, /:global\(\.shell--immersive\.theme--light\)\s+\.about-page--immersive\s+:is\([\s\S]*?color:\s*#10233d !important;[\s\S]*?-webkit-text-fill-color:\s*currentColor/s)
assert.match(aboutStyle, /:global\(\.shell--immersive\.theme--light\)\s+\.about-page--immersive\s+\.metric-card__value\s*\{[^}]*-webkit-text-fill-color:\s*transparent/s)
assert.match(
  aboutStyle,
  /:global\(\.shell--immersive\.theme--light\)\s+\.about-page--immersive\s+\.innovation-card__index\s*\{[^}]*color:\s*#ffffff !important;[^}]*-webkit-text-fill-color:\s*currentColor !important;/s,
)
assert.match(aboutStyle, /:global\(\.shell--immersive\.theme--light\)\s+\.about-page--immersive\s+:is\([^}]+?\.compare-row span[^}]+?\)\s*\{[^}]*-webkit-text-fill-color:\s*currentColor/s)
assert.match(aboutStyle, /:global\(\.shell--immersive\.theme--light\)\s+\.about-page--immersive\s+\.carousel-arrow\s*\{[^}]*color:\s*#10233d[^}]*-webkit-text-fill-color:\s*currentColor/s)
assert.match(aboutStyle, /:global\(\.shell--immersive\.theme--light\)\s+\.about-page--immersive\s+\.carousel-dot\.active\s*\{[^}]*background:\s*#2f68d8/s)
assert.match(
  aboutStyle,
  /\.about-page--immersive\s+\.hero-stats\s+\.metric-card\s*\{[^}]*display:\s*grid;[^}]*place-content:\s*center;[^}]*min-height:\s*204px;/s,
)
assert.match(
  aboutStyle,
  /:global\(\.shell--immersive\.theme--light\)\s+\.about-page--immersive\s+\.carousel-stage,\s*:global\(\.shell--immersive\.theme--light\)\s+\.about-page--immersive\s+\.carousel-panel\s*\{[^}]*background:\s*transparent;[^}]*box-shadow:\s*none;/s,
)
assert.match(
  aboutStyle,
  /:global\(\.shell--immersive\.theme--light\)\s+\.about-page--immersive\s+\.carousel-panel\s+:is\(\.panel-card,\s*\.portal-card,\s*\.metric-card\)\s*\{[^}]*box-shadow:\s*0 10px 28px rgba\(31,\s*58,\s*104,\s*0\.055\) !important;/s,
)
assert.match(
  css,
  /\.shell--immersive\.theme--light\s+\.about-page--immersive\s+:is\(\s*button,\s*button \*,\s*a,\s*a \*,[\s\S]*?th\s*\)\s*\{[^}]*color:\s*#10233d !important;[^}]*-webkit-text-fill-color:\s*currentColor !important;[^}]*text-shadow:\s*none !important;/s,
)
assert.match(
  css,
  /\.shell--immersive\.theme--light\s+\.about-page--immersive\s+\.carousel-arrow,\s*\.shell--immersive\.theme--light\s+\.about-page--immersive\s+\.carousel-arrow \*\s*\{[^}]*color:\s*#10233d !important;[^}]*-webkit-text-fill-color:\s*currentColor !important;[^}]*text-shadow:\s*none !important;/s,
)
assert.match(
  css,
  /\.shell--immersive\.theme--light\s+\.about-page--immersive\s+\.carousel-dot\.active\s*\{[^}]*background:\s*#2f68d8 !important;/s,
)
assert.match(aboutVue, /import\s+\{\s*isDarkScheme\s*\}\s+from\s+'..\/utils\/colorScheme\.js'/)
assert.match(aboutVue, /const\s+useDarkCharts\s*=\s*computed\(\(\)\s*=>\s*isImmersive\.value\s*&&\s*isDarkScheme\.value\)/)
assert.doesNotMatch(aboutVue, /axisLabel:\s*\{\s*interval:\s*0,\s*rotate:\s*28,\s*color:\s*isImmersive\.value\s*\?/)

const dashboardStyle = dashboardVue.match(/<style scoped>(?<body>[\s\S]+)<\/style>/)?.groups?.body || ''
assert.match(dashboardStyle, /:global\(\.maintenance-dialog,\s*\.maintenance-dialog \*\)\s*\{[^}]*-webkit-text-fill-color:\s*currentColor/s)
assert.match(
  dashboardStyle,
  /:global\(\.shell--immersive\.theme--light\)\s+\.ws-state-chip--disconnected\s*\{[^}]*--el-tag-bg-color:\s*rgba\(255,\s*118,\s*132,\s*0\.12\)[^}]*--el-tag-text-color:\s*#b4233f/s,
)
assert.match(
  dashboardStyle,
  /:global\(html\.theme--light\s+\.maintenance-dialog\)\s*\{[^}]*color:\s*#162130 !important;[^}]*background:\s*linear-gradient\(180deg,\s*rgba\(255,\s*255,\s*255,\s*0\.98\),\s*rgba\(236,\s*245,\s*255,\s*0\.94\)\)\s*!important/s,
)
assert.match(
  dashboardStyle,
  /:global\(html\.theme--light\s+\.maintenance-dialog\s+\.el-form-item__label\)[\s\S]+color:\s*#334b68 !important/s,
)
assert.match(
  dashboardStyle,
  /:global\(html\.theme--light\s+\.maintenance-dialog\s+\.el-radio\)[\s\S]+--el-radio-text-color:\s*#334b68/s,
)
assert.match(
  dashboardStyle,
  /:global\(html\.theme--light\s+\.maintenance-dialog\s+\.el-input-number__decrease\),\s*:global\(html\.theme--light\s+\.maintenance-dialog\s+\.el-input-number__increase\)\s*\{[^}]*color:\s*#334b68 !important;[^}]*background:\s*linear-gradient\(180deg,\s*rgba\(255,\s*255,\s*255,\s*0\.96\),\s*rgba\(232,\s*241,\s*255,\s*0\.9\)\)\s*!important/s,
)

const anomalyStyle = anomalyVue.match(/<style scoped>(?<body>[\s\S]+)<\/style>/)?.groups?.body || ''
assert.match(anomalyStyle, /:global\(\.shell--immersive\.theme--dark\)\s+\.events-page\s+:is\([^}]+?\)\s*\{[^}]*-webkit-text-fill-color:\s*currentColor/s)
assert.match(anomalyStyle, /:global\(\.ai-report-dialog,\s*\.ai-report-dialog \*\)\s*\{[^}]*-webkit-text-fill-color:\s*currentColor/s)
assert.match(anomalyStyle, /:global\(html\.theme--dark\s+\.ai-report-dialog\)\s*\{[^}]*--gg-text:\s*#f8fbff/s)
assert.match(anomalyStyle, /:global\(html\.theme--dark\s+\.ai-report-dialog\.el-dialog\)\s*\{[^}]*background:\s*linear-gradient\(135deg,\s*#071a33\s*0%,\s*#06101d\s*48%,\s*#0b0f14\s*100%\)/s)
assert.match(anomalyStyle, /:global\(html\.theme--dark\s+\.ai-report-dialog\)\s+\.report-hero h3[\s\S]+color:\s*#ffffff/s)
assert.match(anomalyStyle, /:global\(html\.theme--dark\s+\.ai-report-dialog\)\s+\.report-hero p[\s\S]+color:\s*#f8fbff/s)
assert.match(anomalyStyle, /:global\(html\.theme--dark\s+\.ai-report-dialog\)\s+\.report-risk-badge[\s\S]+background:\s*linear-gradient\(135deg,\s*rgba\(8,\s*26,\s*51,\s*0\.98\),\s*rgba\(7,\s*14,\s*26,\s*0\.98\)\s*56%,\s*rgba\(11,\s*15,\s*20,\s*0\.98\)\)/s)
assert.match(anomalyStyle, /:global\(html\.theme--dark\s+\.ai-report-dialog\)\s+\.raw-block\s*\{[^}]*background:\s*linear-gradient\(135deg,\s*#071a33\s*0%,\s*#07101c\s*58%,\s*#0b0f14\s*100%\)[^}]*color:\s*#ffffff/s)
assert.match(anomalyStyle, /:global\(html\.theme--dark\s+\.ai-report-dialog\s+\.report-panel\)\s*\{[^}]*background:\s*linear-gradient\(135deg,\s*rgba\(8,\s*26,\s*51,\s*0\.98\),\s*rgba\(7,\s*14,\s*26,\s*0\.98\)\s*56%,\s*rgba\(11,\s*15,\s*20,\s*0\.98\)\)\s*!important/s)
assert.match(anomalyStyle, /:global\(html\.theme--dark\s+\.ai-report-dialog\s+\.report-timeline__item\)\s*\{[^}]*background:\s*linear-gradient\(135deg,\s*rgba\(8,\s*26,\s*51,\s*0\.98\),\s*rgba\(7,\s*14,\s*26,\s*0\.98\)\s*56%,\s*rgba\(11,\s*15,\s*20,\s*0\.98\)\)\s*!important/s)
assert.match(anomalyStyle, /:global\(html\.theme--dark\s+\.ai-report-dialog\s+\.report-conclusion\)\s*\{[^}]*background:\s*linear-gradient\(135deg,\s*rgba\(8,\s*26,\s*51,\s*0\.98\),\s*rgba\(7,\s*14,\s*26,\s*0\.98\)\s*56%,\s*rgba\(11,\s*15,\s*20,\s*0\.98\)\)\s*!important/s)
assert.doesNotMatch(aboutStyle, /:global\(\.shell--immersive\.theme--dark\)\s+\.about-page--immersive\s+:is\([^}]+?\)\s*\{[^}]*-webkit-text-fill-color:\s*currentColor/s)

const chatStyle = chatVue.match(/<style scoped>(?<body>[\s\S]+)<\/style>/)?.groups?.body || ''
assert.match(chatStyle, /:global\(\.shell--immersive\.theme--dark\)\s+\.composer\s+\.el-textarea__inner\s*\{[^}]*-webkit-text-fill-color:\s*currentColor/s)
assert.match(
  chatStyle,
  /:global\(\.shell--immersive\.theme--light\)\s+\.message-row--user\s+:is\(\.message-bubble__role,\s*\.message-bubble__text\)\s*\{[^}]*color:\s*#ffffff !important;[^}]*-webkit-text-fill-color:\s*currentColor !important/s,
)
assert.match(anomalyVue, /const\s+severityPalette\s*=\s*computed/)
assert.match(anomalyVue, /color:\s*severityPalette\.value/s)
assert.match(anomalyVue, /const\s+barGradient\s*=\s*computed/)
assert.match(
  anomalyStyle,
  /:global\(\.shell--immersive\.theme--light\)\s+\.filter-action\s+:deep\(\.ai-action-btn--clear\)\s*\{[^}]*--el-button-bg-color:\s*rgba\(255,\s*247,\s*250,\s*0\.96\)[^}]*--el-button-text-color:\s*#b4233f/s,
)
assert.match(
  anomalyStyle,
  /:global\(\.shell--immersive\.theme--light\)\s+\.severity-chip--critical\s*\{[^}]*--el-tag-text-color:\s*#c22543/s,
)
assert.match(
  anomalyStyle,
  /:global\(\.shell--immersive\.theme--light\)\s+\.table-card\s+:deep\(\.el-table__body\s+td\.el-table__cell\)\s*\{[^}]*color:\s*#10233d !important/s,
)
