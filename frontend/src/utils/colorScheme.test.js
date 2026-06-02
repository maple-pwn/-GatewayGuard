import assert from 'node:assert/strict'
import {
  COLOR_SCHEME_STORAGE_KEY,
  applyColorScheme,
  normalizeColorScheme,
  readStoredColorScheme,
} from './colorScheme.js'

assert.equal(normalizeColorScheme('light'), 'light')
assert.equal(normalizeColorScheme('dark'), 'dark')
assert.equal(normalizeColorScheme('immersive'), 'dark')
assert.equal(normalizeColorScheme(''), 'dark')

const storage = new Map([[COLOR_SCHEME_STORAGE_KEY, 'light']])
assert.equal(readStoredColorScheme({ getItem: (key) => storage.get(key) }), 'light')

const classList = new Set()
const root = {
  dataset: {},
  classList: {
    add: (name) => classList.add(name),
    remove: (name) => classList.delete(name),
  },
}
applyColorScheme('light', root)
assert.equal(root.dataset.theme, 'light')
assert.equal(classList.has('theme--light'), true)
assert.equal(classList.has('theme--dark'), false)

applyColorScheme('unknown', root)
assert.equal(root.dataset.theme, 'dark')
assert.equal(classList.has('theme--dark'), true)
assert.equal(classList.has('theme--light'), false)

applyColorScheme('light', root)
assert.equal(root.dataset.theme, 'light')
assert.equal(classList.has('theme--light'), true)
assert.equal(classList.has('theme--dark'), false)
