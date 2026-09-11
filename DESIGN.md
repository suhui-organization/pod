# Design

## Theme

Light, restrained, ledger-like. A local security console read in a normal browser window next to an editor, in daylight, for minutes at a time: the surface stays quiet so the data carries the weight.

Physical scene: *工作日白天，开发者刚跑完 `pod record`，把控制台开在编辑器旁边的浏览器窗口里，逐条核对这个 agent 到底拿了哪些权限。* Daylight + side-by-side reading + a ledger metaphor → light surface, no terminal cosplay (see PRODUCT.md anti-references).

Color strategy: **Restrained** — cool neutral surfaces, white cards, one cobalt primary (seed hue 230°), plus a semantic three-state vocabulary (allow / approve / deny) that is the only other place saturated color is allowed to appear.

## Color

All values OKLCH.

| Token | Value | Use |
|---|---|---|
| `--bg` | `oklch(0.981 0.004 235)` | page background |
| `--surface` | `oklch(1 0 0)` | cards, panels |
| `--surface-2` | `oklch(0.968 0.006 235)` | sidebar, toolbars |
| `--surface-3` | `oklch(0.945 0.008 235)` | hover / pressed neutral |
| `--border` | `oklch(0.902 0.008 235)` | hairlines |
| `--border-strong` | `oklch(0.84 0.012 235)` | emphasized edges |
| `--ink` | `oklch(0.24 0.015 250)` | primary text |
| `--ink-2` | `oklch(0.44 0.018 250)` | secondary text |
| `--ink-3` | `oklch(0.52 0.015 250)` | labels, meta (≥4.5:1 on white **and** on `--surface-2`) |
| `--primary` | `oklch(0.50 0.14 242)` | primary action, selection |
| `--primary-hover` | `oklch(0.44 0.15 242)` | hover |
| `--primary-soft` | `oklch(0.955 0.022 242)` | selected nav, tint |
| `--ok` | `oklch(0.52 0.12 158)` | allow |
| `--ok-soft` | `oklch(0.955 0.03 158)` | allow tint |
| `--warn` | `oklch(0.55 0.13 68)` | approve |
| `--warn-soft` | `oklch(0.96 0.035 68)` | approve tint |
| `--danger` | `oklch(0.52 0.19 27)` | deny, risk |
| `--danger-soft` | `oklch(0.96 0.03 27)` | deny tint |
| `--focus` | `oklch(0.55 0.16 242)` | focus ring (2px offset 2px) |

Rules:
- Body text never below `--ink-2` on white. `--ink-3` is for labels/meta only, never prose.
- The three decision states always ship **label + color** (never color alone): `allow`/`approve`/`deny` appear as words.
- Risk signals use `--danger` for "found" and neutral for "none found" — absence of data is **not** rendered as green.

## Typography

One family, fixed rem scale (product register: no display/body pairing, no fluid clamp).

- UI: `ui-sans-serif, -apple-system, "SF Pro Text", "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif`
- Data: `ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace` — numbers, tool names, paths, hashes, ids only.

| Step | Size | Weight | Use |
|---|---|---|---|
| `--fs-page` | 20px | 600 | page title |
| `--fs-card` | 16px | 600 | agent name |
| `--fs-body` | 14px | 400/500 | body, controls |
| `--fs-sm` | 13px | 400/500 | dense rows, card meta |
| `--fs-xs` | 12px | 500 | labels, badges |

Line height 1.55 body, 1.35 dense. Tabular numerals for every count.

## Layout

- App shell: 236px fixed sidebar (`--surface-2`) + content column, max content width 1200px.
- Responsive is structural: below 900px the sidebar becomes a horizontal nav strip; the grid collapses by `auto-fit`.
- Agent grid: `grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px;` — agents are few, so cards scale up gracefully instead of leaving holes.
- Card radius 10px, panel radius 12px. Nothing above 16px.
- No nested cards. Card interiors use hairlines and spacing, not boxes inside boxes.

## Components

- **Card**: `--surface`, 1px `--border`, radius 10px, **no drop shadow**. Hover raises border to `--border-strong` only.
- **Badge (decision)**: 12px, 500, tinted background (`*-soft`), matching ink, radius 999px, always paired with the word.
- **Status dot**: 8px dot + label ("启用"/"停用"), shape doubled by the label text.
- **Signal chip**: risk findings as chips with leading icon-free glyph and count; "未发现" renders in neutral, not green.
- **Sparkline**: 7 fixed-height bars (CSS only), muted base, `--primary` for the last bar; hidden under `prefers-reduced-motion` collapse rules is unnecessary — it is static markup, no animation.
- **Empty state**: teaches the command that produces data (`pod record`, `pod policy draft`), never says "nothing here".
- **Skeleton**: gray blocks with a 1.2s opacity pulse, disabled under reduced motion.

States required on every interactive element: default, hover, focus-visible, active, disabled.

## Motion

- 150–200ms, `cubic-bezier(0.22, 1, 0.36, 1)` (ease-out-quart). No bounce, no orchestration on load.
- Motion only for state: hover, focus, refresh transition, skeleton fade.
- Every transition wrapped by `@media (prefers-reduced-motion: reduce)` → instant.

## Bans carried from the skill

No side-stripe borders, no gradient text, no glassmorphism, no hero-metric template, no identical icon+title card grids (agent cards lead with data, not icons), no tracked uppercase eyebrows, no `border` + wide `box-shadow` pairing, no radii ≥24px, no sketchy SVG illustration, no striped backgrounds.
