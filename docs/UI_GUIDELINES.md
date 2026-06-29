# Argus Dashboard — UI Guidelines & Design System

The single source of truth for the dashboard's look and feel. Every page must
conform to these tokens and patterns. Implemented as CSS custom properties in
Phase 2 and refined in Phase 7.

---

## 1. Design Philosophy

- **Clarity over decoration.** Data is the hero; chrome stays quiet.
- **Color means something.** Restrained neutral base; color reserved for status,
  risk, and primary actions.
- **Consistency via tokens.** All spacing, color, radius, and type come from the
  tokens below — never ad-hoc values.
- **Generous whitespace**, calm layouts, predictable structure.
- **Enterprise, not hacker.** No neon-on-black, no matrix green, no cyberpunk.

**Inspiration:** Grafana (panels, dark/light theming), Kibana (clean light data UI),
Wazuh (security dashboard cards/badges), PRTG & SolarWinds (dense status tables),
Cisco DNA Center (sidebar + topology). Aim for that calm, professional register.

---

## 2. Color Palette

Light theme is primary; a dark theme is provided as an optional toggle (Phase 7).

### Neutrals / surfaces (light)
| Token | Hex | Use |
|---|---|---|
| `--bg-app` | `#F5F7FA` | App background |
| `--bg-surface` | `#FFFFFF` | Cards, panels, tables |
| `--bg-subtle` | `#F8FAFC` | Table headers, hover wells |
| `--bg-sidebar` | `#111827` | Sidebar (dark slate) |
| `--border` | `#E2E8F0` | Card/table borders, dividers |
| `--text-primary` | `#1E293B` | Headings, primary text |
| `--text-secondary` | `#64748B` | Labels, secondary text |
| `--text-muted` | `#94A3B8` | Captions, placeholders |

### Brand / action
| Token | Hex | Use |
|---|---|---|
| `--primary` | `#2563EB` | Primary buttons, active nav, links |
| `--primary-hover` | `#1D4ED8` | Primary hover |
| `--primary-soft` | `#EFF6FF` | Primary tint backgrounds |
| `--info` | `#0EA5E9` | Informational accents |

### Semantic / status
| Meaning | Solid | Soft bg | Text-on-soft |
|---|---|---|---|
| Success / Open-safe | `#16A34A` | `#DCFCE7` | `#166534` |
| Warning / Medium | `#F59E0B` | `#FEF3C7` | `#92400E` |
| Danger / Critical | `#DC2626` | `#FEE2E2` | `#991B1B` |
| High | `#EA580C` | `#FFEDD5` | `#9A3412` |
| Info | `#0284C7` | `#E0F2FE` | `#075985` |
| Neutral / Closed | `#64748B` | `#F1F5F9` | `#334155` |

### Risk badge mapping
`Critical → Danger` · `High → High` · `Medium → Warning` · `Low → Success` · `Info → Info`.
Badges always pair color **with a text label** (never color alone — see Accessibility).

---

## 3. Typography

- **UI font:** `"Inter", system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif`
- **Mono (banners, raw output, ports):** `"JetBrains Mono", ui-monospace, "Cascadia Code", Consolas, monospace`

| Role | Size | Weight | Line-height |
|---|---|---|---|
| H1 / page title | 28px | 600 | 1.25 |
| H2 / section | 22px | 600 | 1.3 |
| H3 / card title | 16px | 600 | 1.4 |
| Body (base) | 14px | 400 | 1.5 |
| Small / caption | 12px | 500 | 1.4 |
| Table header | 12px | 600 | uppercase, `letter-spacing: .04em` |

Base size is **14px** (dashboard convention). Numerals in stat cards may use `font-variant-numeric: tabular-nums`.

---

## 4. Spacing, Radius, Shadows

**Spacing scale (4px base):** `--space-1:4` `-2:8` `-3:12` `-4:16` `-5:24` `-6:32` `-7:48` `-8:64` (px).
Card padding `--space-5` (24). Page gutter `--space-6` (32) desktop / `--space-4` mobile.

**Radius:** `--radius-sm:4px` · `--radius-md:8px` · `--radius-lg:12px` · `--radius-pill:999px`.
Cards `md`, buttons/inputs `sm–md`, badges `pill`.

**Shadows (subtle, layered):**
- `--shadow-sm: 0 1px 2px rgba(16,24,40,.05)`
- `--shadow-md: 0 2px 8px rgba(16,24,40,.08)`
- `--shadow-lg: 0 8px 24px rgba(16,24,40,.12)`

Cards rest at `sm`, lift to `md` on hover. Modals/popovers use `lg`.

---

## 5. Components

### Buttons
| Variant | Style |
|---|---|
| Primary | `--primary` bg, white text, `--radius-md`, hover `--primary-hover` |
| Secondary | white bg, `--border` outline, `--text-primary` |
| Ghost | transparent, text-colored, hover `--bg-subtle` |
| Danger | `--danger` bg, white text |
Sizes: sm (28px h, 12px), md (36px h, 14px), lg (44px). Icon-left optional.
States: hover (darken/shadow), focus-visible (2px `--primary` ring), disabled (60% opacity, no pointer), loading (spinner + disabled).

### Cards
White surface, 1px `--border`, `--radius-md`, `--shadow-sm`, padding 24. Optional header row: title (H3) left, actions right, 1px divider. **Stat cards:** large tabular number, label above (12px muted), optional trend chip + icon.

### Tables (Tabulator.js)
- Header: `--bg-subtle`, 12px/600 uppercase `--text-secondary`, bottom border `--border`.
- Rows: 44px height, `--text-primary`, bottom border `--border`, hover `--bg-subtle`. Zebra **off** (cleaner).
- Cells: status/risk rendered as badges; banners in mono, truncated with tooltip.
- Sticky header on scroll; pagination footer right-aligned; toolbar (search + filters + export) above table.

### Status badges
Pill, soft bg + on-soft text from §2, 12px/600, dot optional. e.g. `OPEN` (success soft), `CLOSED` (neutral soft), `CRITICAL` (danger soft).

### Progress bar
Track `--border`, 8px height, `--radius-pill`. Fill `--primary` (subtle left-to-right gradient ok), animated width transition. Show `%` and `x/y ports` beside it. Indeterminate variant: animated stripe for "starting".

### Charts (Chart.js)
Categorical palette (max 8, in order):
`#2563EB`, `#0EA5E9`, `#16A34A`, `#F59E0B`, `#DC2626`, `#8B5CF6`, `#14B8A6`, `#EC4899`.
Risk charts use semantic colors (§2). Gridlines `--border` at low opacity; legends 12px `--text-secondary`; no heavy 3D/shadows.

### Icons
**One set: Lucide** (MIT, clean line icons; Bootstrap Icons acceptable fallback for Bootstrap pairing). 16–20px, 1.5–2px stroke, `currentColor`. Icon-only buttons require `aria-label`. Keep metaphors consistent (e.g., shield = vuln, radar/scan = scan, server = host).

---

## 6. Layout & Navigation

### Sidebar
- Dark (`--bg-sidebar`), fixed left. Expanded **248px**, collapsed **64px** (icons only).
- Top: product logo/name. Grouped nav with uppercase 11px muted section labels.
- Item: icon + label, 40px tall. **Active:** 3px left `--primary` bar + soft highlight + white text. Hover: subtle lighten.

### Top bar
- 56–64px tall, white, bottom border. Left: page title / breadcrumb + sidebar toggle.
  Right: global search, **+ New Scan** primary button, theme toggle, (optional) profile.

### Page scaffold
Top bar → page header (title + actions) → content grid (12-col, `--space-5` gutters) →
stat-card row → main panels/tables. Max content width ~1440px, centered on ultra-wide.

---

## 7. States

- **Empty:** centered illustration/icon + title + one-line guidance + primary action
  (e.g., *"No scans yet — Run your first scan"*). Used on History/Reports/Topology before data.
- **Loading:** skeleton loaders for cards/tables (shimmer on `--bg-subtle`), inline spinners
  for small areas, progress bar for active scans. Buttons show inline spinner + disabled.
- **Error:** inline alert (danger soft bg, icon, message, **Retry**) for recoverable;
  full-page error for fatal; toast for transient failures. Always actionable, never a raw stack trace.
- **Success:** toast, top-right, auto-dismiss ~4s, green check icon, title + message, stackable.
  Used for "Scan complete", "Exported CSV", "Scan deleted".

---

## 8. Motion

- Transitions **150–200ms ease**. Card hover: `translateY(-2px)` + `--shadow-md`.
  Buttons: bg/shadow shift. Rows append with a brief fade/slide (live scan).
- **Subtle only** — no bounces, no long/looping animations.
- Honor `prefers-reduced-motion: reduce` → disable non-essential animation.

---

## 9. Responsive Behavior

Breakpoints (Bootstrap): sm 576 · md 768 · lg 992 · xl 1200 · xxl 1400.
- `< lg`: sidebar collapses to off-canvas drawer (hamburger).
- `< md`: stat cards and content panels stack to a single column.
- Tables: horizontal scroll or Tabulator responsive-collapse below md.
- Charts fluid-width; topology canvas fills its container and is pannable/zoomable.

---

## 10. Accessibility

- **Contrast:** meet WCAG **AA** (≥4.5:1 body text, ≥3:1 large text / UI).
- **Focus:** visible `focus-visible` ring (2px `--primary`); full keyboard navigation.
- **Don't rely on color alone:** status/risk badges always carry text (and optional icon/dot).
- **ARIA:** labels on icon-only buttons; `aria-live="polite"` region for the live scan log/toasts.
- **Semantics:** proper headings, `<table>` semantics, `<nav>`, landmarks; alt text on imagery.
- **Motion:** respect `prefers-reduced-motion`.
- Form inputs have associated `<label>`s; error messages linked via `aria-describedby`.
