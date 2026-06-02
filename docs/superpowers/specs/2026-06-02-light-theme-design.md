# GatewayGuard Light Immersive Theme Design

Date: 2026-06-02
Status: Awaiting user review

## Objective

Implement a readable light/day theme for the current immersive frontend without changing the existing night theme behavior.

The light theme must adapt text, font color, cards, buttons, forms, tables, charts, dialogs, and the About page so day mode is usable. The night theme should remain visually equivalent to the current repository state.

## Non-goals

- Do not modify Android code.
- Do not redesign page layout or component structure.
- Do not replace the current theme system with a full token refactor.
- Do not alter night theme selectors except where a test proves a selector is accidentally leaking into light mode.
- Do not remove the global immersive metric number gradient or the About page immersive metric number gradient.

## Current Findings

- `App.vue` already applies `theme--light` and `theme--dark` to both the immersive shell and `html`.
- `theme.css` already contains partial `.shell--immersive.theme--light` rules, but coverage is incomplete across pages, buttons, cards, tables, and teleported dialogs.
- Night readability fixes rely on scoped dark selectors and `-webkit-text-fill-color: currentColor` resets.
- `About.vue` still contains mostly hardcoded immersive night colors under `.about-page--immersive`, which makes the page unreadable in light mode.
- `Anomaly.vue` already uses theme-aware chart colors through `isDarkScheme`; chart work should reuse this pattern if more chart-specific fixes are needed.
- Element Plus overlays and dialogs need `html.theme--light` rules because they are teleported outside the immersive shell.

## Approved Approach

Use theme isolation as the main architecture:

- Light-only rules are scoped to `.shell--immersive.theme--light` for in-shell content.
- Light-only teleported UI rules are scoped to `html.theme--light`.
- Existing dark rules stay in place and remain the source of truth for night mode.
- About page gets separate light overrides while preserving its original immersive night CSS.

This keeps day and night styles independent and reduces the chance that day-mode cleanup breaks night-mode readability.

## Design Details

### 1. Light Theme Tokens and Fallbacks

Extend the existing light theme surface in `theme.css` with a consistent light-tech palette:

- Page background: pale blue / blue-gray.
- Surfaces: white to very light blue glass.
- Borders: blue-gray with cyan accents.
- Primary text: deep navy.
- Secondary text: slate blue-gray.
- Accent text: blue/cyan.
- Warning and critical text: saturated enough to remain visible on light backgrounds.

Add a light scoped readable fallback:

- Use `-webkit-text-fill-color: currentColor` only under `.shell--immersive.theme--light` and `html.theme--light`.
- Keep metric number gradients by excluding or re-declaring metric value selectors that intentionally use gradient text.
- Avoid broad unscoped resets so night mode and non-immersive pages are not affected.

### 2. Shared Immersive Components

Add or complete light rules for shared UI surfaces:

- `panel-card`, `portal-card`, `metric-card`, status cards, message cards, report sections, and console action panels.
- Primary, ghost, danger, and secondary buttons.
- Inputs, selects, textareas, search boxes, dropdowns, and placeholders.
- Tables, including header, row, zebra, hover, border, and empty states.
- Tags, badges, pills, chips, and timeline markers.

These rules should use existing class names and Element Plus CSS variables where possible, instead of introducing new component APIs.

### 3. Teleported Dialogs and Popovers

Add light rules under `html.theme--light` for UI rendered outside the shell:

- Element Plus overlays, dialogs, popovers, dropdowns, tooltips, and selects.
- Maintenance and import dialogs.
- AI assistant dialog and AI report dialog.

This prevents the recurring issue where dialogs inherit transparent or dark-only text styles.

### 4. About Page Isolation

Keep the existing `.about-page--immersive` night styles intact.

Add only light-scoped overrides:

- `:global(.shell--immersive.theme--light) .about-page--immersive ...`

Cover these areas:

- Hero copy panel.
- Eyebrow, headings, paragraph text, captions, and meta text.
- Metric cards and metric labels.
- Feature, vision, timeline, compare, team, and footer sections.
- Tags, badges, status labels, and icon wells.

Metric values may keep gradient text, but surrounding labels and body copy must use opaque readable colors.

### 5. Charts

Keep the existing theme-aware chart approach in `Anomaly.vue`.

If other pages contain hardcoded night chart colors, add light-aware chart options or CSS variables rather than global overrides. Chart labels, legends, axes, grid lines, and tooltip backgrounds must be readable in light mode.

## Testing Plan

Update focused theme tests before implementation:

- Assert light theme selectors exist for shared cards, buttons, inputs, tables, and teleported dialogs.
- Assert light text-fill resets are scoped to `.theme--light` or `html.theme--light`.
- Assert About has light-scoped overrides.
- Assert About's original night styles remain and are not replaced by broad dark overrides.
- Keep existing dark AI report readability tests.

Run verification after implementation:

- `node frontend/src/styles/themeTokens.test.js`
- `node frontend/src/utils/colorScheme.test.js`
- `node frontend/src/App.theme.test.js`
- `npm run build`

If a dev server is active, also inspect `http://localhost:5173/` in light and dark mode, with attention to About, Event Center, AI Assistant, AI report output, tables, charts, cards, and dialogs.

## Risks and Controls

- Risk: a broad text-fill reset breaks intended metric gradients.
  Control: scope resets and explicitly preserve metric value gradient selectors.

- Risk: light styles leak into night mode.
  Control: every day-mode implementation selector must include `.theme--light` or `html.theme--light`.

- Risk: teleported Element Plus components remain unreadable.
  Control: include `html.theme--light` dialog, popover, dropdown, select, and tooltip rules.

- Risk: About page fixes accidentally rewrite original night styling.
  Control: add light-specific overrides after the original About rules and leave existing night declarations intact.

## Implementation Outline

1. Add failing theme-token tests for the required light selectors and About isolation.
2. Extend `frontend/src/styles/theme.css` with isolated light rules.
3. Add light-scoped overrides in `frontend/src/views/About.vue`.
4. Adjust chart-specific color logic only if tests or inspection show hardcoded night chart colors outside `Anomaly.vue`.
5. Run the verification commands and inspect the app in both modes.
