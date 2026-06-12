# HTML Generation Style Guide

This document captures the visual and structural conventions to follow whenever generating a self-contained `.html` artifact for this project. The style is adapted from [thariqs.github.io/html-effectiveness](https://thariqs.github.io/html-effectiveness/), specifically the editorial document-style pages (e.g. `16-implementation-plan.html`). Decision triggers and universal-artifact rules are adapted from [dogum/html-artifacts](https://github.com/dogum/html-artifacts) (`skill/SKILL.md`).

---

## −1. When to reach for HTML vs. stay in markdown

**Default is markdown.** This project deliberately diverges from the "use HTML aggressively" stance of the source skill. HTML token cost is ~2–4× a markdown equivalent and generation latency is meaningfully higher; for short conversational turns and one-shot judgments the markdown reply is the right move.

**Escalate to HTML when at least one of these is true:**

- **Comparison.** Two or more options/approaches/designs that the reader needs to weigh against each other. Side-by-side beats stacked text.
- **Spatial information.** Diffs, call graphs, module maps, flowcharts, timelines, before/after — anything where position carries meaning.
- **Reference material.** A document the reader will navigate non-linearly: numbered sections, jump links, collapsible details, glossary.
- **Color or hierarchy carries meaning.** Severity tags, status colors, safe/vulnerable profile pairs, design tokens.
- **Length.** Roughly >100 lines as markdown — past that threshold HTML's layout and navigation earn their keep.
- **The reader will share or revisit it.** Plans handed to an implementer, specs going to a collaborator, reports the user will come back to next week.
- **Explicit request.** The user said "doc / writeup / plan / spec / report / explainer / deck / mockup / diagram" — but verify against the criteria above before auto-escalating; the user may just want a concise text answer.

**Stay in markdown for:**

- Short conversational replies inside the chat.
- Code-only or terminal-flavored outputs (a function, a config block, "run this, then that").
- Three-bullet summaries the user will scan once.
- Files that need to be diffed in version control regularly (HTML diffs are noisy).
- Quick judgments and opinions like this paragraph itself — even when the surrounding work involves HTML.

**Heuristic, said another way:** if the user is going to *do* something with the output — read it carefully, share it, refer back to it, hand it to someone else — make it HTML. Otherwise stay in markdown.

---

## 0. Language policy (READ FIRST)

**All user-facing text in the HTML body is written in 中文 (Simplified Chinese).** This includes:

- Headings, section titles, body prose, captions, callouts, labels
- Table content, card descriptions, list items
- Eyebrows, TL;DR boxes, footer text

**Exceptions that stay in English / mono code:**

- Technical identifiers: file paths, type names, function names, config keys, profile names, event type literals (e.g. `auth_by_user_id`, `policy_decision`, `SKILL.md`)
- Code blocks and schema definitions
- Layer labels (`L0`–`L6`) and mono tag chips
- Proper nouns: tool/framework names (Docker, Telegram, MCP, ReAct)

The Chinese-first rule is non-negotiable. Falling back to English prose is a regression — match the user's working language regardless of how the source examples are written.

For font stack, always include both English and Chinese families:

```css
--serif: ui-serif, Georgia, "Times New Roman", "Songti SC", "STSong", serif;
--sans:  system-ui, -apple-system, "Segoe UI", Roboto,
         "PingFang SC", "Microsoft YaHei", sans-serif;
--mono:  ui-monospace, "SF Mono", Menlo, Monaco, Consolas, monospace;
```

### 0.1 Punctuation must follow the surrounding language (MANDATORY)

Within prose, punctuation marks are part of the language of the sentence they appear in. **In Chinese prose, use Chinese (full-width) punctuation; in English prose or inside code, use ASCII (half-width) punctuation.** This is not a stylistic preference — mixing ASCII commas/colons into Chinese sentences breaks the visual rhythm of CJK typography (Chinese readers expect the wider visual breathing room that `，：；。` provide) and signals "machine-translated text" to a careful reader.

| Half-width (use in English / code) | Full-width (use in Chinese prose) |
|---|---|
| `,` comma                          | `，`                              |
| `:` colon                          | `：`                              |
| `;` semicolon                      | `；`                              |
| `.` period (English sentence end)  | `。`                              |
| `?` question mark                  | `？`                              |
| `!` exclamation                    | `！`                              |
| `(` `)` parentheses                | `（` `）`                          |
| `"..."` ASCII double quotes        | `“...”` curly double quotes       |
| `'...'` ASCII single quotes        | `‘...’` curly single quotes       |
| `--` `—` em dash                   | `——` (two em dashes, CJK convention) |

**Exceptions that stay ASCII even inside Chinese prose:**

- Inside `<code>`, `<pre>`, schema definitions, JSON, YAML, file paths, URLs, CSS, command-line examples. Code is code, regardless of the surrounding language.
- HTML attribute values (`class="..."`, `href="..."`, etc.). These are part of the markup, not prose.
- ASCII brackets used as delimiters around mono-font identifiers (e.g. `[L0]`, `(M3)` when M3 is rendered in `<code>`). Use judgement — if the surrounding sentence is Chinese and the brackets feel typographically wrong, switch to full-width.
- Numerical ranges and units (`5h`, `8k–12k`, `30s`). The numeric literal carries the half-width register with it.

**Mixed-language sentences.** When a Chinese sentence contains an English term, the punctuation follows the *outer* sentence's language. Correct: `阶段 1 实现 CLI（M4）与 mock Telegram（M5）。` — the parentheses and period are full-width because the sentence is Chinese, even though the contents are English/mono.

**Quick mental check.** Before declaring a Chinese-prose HTML artifact done, scan the document for ASCII `,`, `:`, `;`, `(`, `)`, `"` appearing immediately adjacent to a CJK character. Every such occurrence is a defect unless the punctuation is inside `<code>` or an HTML attribute.

---

## 1. Color tokens

Lock these as CSS custom properties. Do not invent new colors per page.

| Token        | Hex       | Role                                                            |
|--------------|-----------|-----------------------------------------------------------------|
| `--ivory`    | `#FAF9F5` | Page background. Warm off-white. Never pure white.              |
| `--slate`    | `#141413` | Headings, primary text, code panel background (dark mode use)   |
| `--clay`     | `#D97757` | Single accent color. Used sparingly for emphasis only.          |
| `--olive`    | `#788C5D` | Secondary accent. Often paired with clay for safe/done states.  |
| `--oat`      | `#E3DACC` | Chip backgrounds (section numbers, tags), subtle warm fills     |
| `--plum`     | `#8E6E8A` | Optional tertiary accent. Use only when clay+olive aren't enough.|
| `--gray-150` | `#F0EEE6` | Subtle panel fills, code-block-light, table header rows         |
| `--gray-300` | `#D1CFC5` | Borders. **Always 1.5px**, never 1px.                          |
| `--gray-500` | `#87867F` | Muted text, captions, labels                                    |
| `--gray-700` | `#3D3D3A` | Body text default                                               |
| `--white`    | `#FFFFFF` | Card surfaces only. Body background is ivory, not white.        |

**Accent discipline:** clay is the only "loud" color on the page. Use it for at most: the TL;DR left border, section-number chips' bottom underline, one dot in the milestone timeline, severity-high pills, and the open-question left border. If clay appears in more than 5–6 places per page, you're overusing it.

**Severity palette** (when a table needs HIGH/MED/LOW pills):

```css
.sev.high { background: #F3D9CC; color: #8A3B1E; }
.sev.med  { background: #E3DACC; color: #141413; }  /* oat */
.sev.low  { background: #E4E9DC; color: #4B5C39; }
```

---

## 2. Typography

Three families, used in strict roles:

- **Serif** (`--serif`) — `h1`, `h2`, `h3`, milestone titles, open-question titles. Font weight 500 (not 600 or 700). **No negative letter-spacing when the heading is in Chinese** — serif CJK glyphs are already designed with their own metrics; `-0.01em` looks crisp on Latin titles and crowded on Chinese ones.
- **Sans** (`--sans`) — all body prose, descriptions, table cells.
- **Mono** (`--mono`) — eyebrows, labels, tags, inline `<code>`, schema/code blocks, section numbers, "决定于 · 阶段 X 之前" owner lines, file paths.

Sizes for **Chinese-primary pages** (the default for this project):

| Element             | Size      | Notes                                                                  |
|---------------------|-----------|------------------------------------------------------------------------|
| `h1`                | 36px      | Serif, weight 500, line-height 1.3, **letter-spacing 0**               |
| `h2` (section)      | 26px      | Serif, weight 500, letter-spacing 0                                    |
| `h3` (milestone)    | 19–20px   | Serif, weight 500                                                      |
| Body `p`            | 14.5–15px | Sans, **line-height 1.75**                                             |
| Section intro       | 14.5px    | Sans, color `--gray-500`, line-height 1.8, max-width ~760px            |
| TL;DR prose         | 14.5px    | Sans, line-height 1.8                                                  |
| Eyebrow / label     | 11–12px   | Mono, uppercase, letter-spacing 0.06–0.08em                            |
| Inline `code`       | 13px      | Mono, color `--slate`                                                  |
| Tag chip            | 11.5px    | Mono                                                                   |

### Why Chinese needs different numbers than English

Chinese prose has a higher glyph density per line than English — each character occupies a full em-box, with no inter-word whitespace. The same `line-height: 1.65` that reads airy in English looks claustrophobic in Chinese; **1.75 for body, 1.8 for section intros and TL;DR boxes** is the floor, not a stylistic choice. Likewise `letter-spacing: -0.01em` on `h1`/`h2` is a Latin-typography convention to tighten large Latin glyphs — applied to serif Chinese (Songti / STSong) it eats into the inter-character whitespace that those typefaces are designed around, and the heading reads cramped.

Rule of thumb: when a heading or paragraph is going to be in Chinese, **always set `letter-spacing: 0` explicitly** (don't rely on inheritance) and bump `line-height` by ~0.1 over what you'd use for the same content in English. The previous version of this guide carried English-tuned numbers (`38px / 1.18`, `1.65`) by accident — they're now superseded by the table above.

**Prose has a max-width.** Body paragraphs cap around 680–760px even on a 1120px page. Long lines kill scannability — in both languages, but more so in Chinese where the eye has no word-breaks to anchor on.

---

## 3. Layout

- Page wrapper: `max-width: 1120px; margin: 0 auto;`
- Body padding: `56px 32px 120px` (generous top and bottom)
- Sections: `margin-bottom: 64px`
- Cards/panels: `border-radius: 10–12px`, `border: 1.5px solid var(--gray-300)`, `background: var(--white)`
- Internal padding for cards: `16–22px` depending on density

Responsive breakpoints (only two — keep it simple):

```css
@media (max-width: 900px) { /* collapse 4-col → 2-col, 2-col → 1-col */ }
@media (max-width: 720px) { /* mobile: everything stacks */ }
```

---

## 4. Required structural elements

### 4.0 Universal artifact rules (apply to every `.html` file)

These are non-negotiable, independent of layout or theme:

1. **Single self-contained `.html` file.** No build step, no bundler, no `npm install`. All CSS goes inside a `<style>` block; any JS goes inside a `<script>` block; images are inline SVG or data URIs.
2. **Works offline.** No required network calls at view time. If a CDN is used (font, library), assume the user may want it inlined later — prefer no external dependencies at all unless the artifact genuinely needs them.
3. **Mobile responsive.** Always include `<meta name="viewport" content="width=device-width, initial-scale=1.0">` and a layout that survives a narrow viewport. The artifact may be opened on a phone.
4. **Readable on its own.** Title at the top, a one-paragraph TL;DR or framing sentence immediately below, then the substance. The reader should know what they're looking at within five seconds.
5. **Real layout, not stacked headers.** If the content is a comparison, lay it out in columns. If it's a timeline, draw a timeline. If it's a diff, render a diff. Do not translate markdown structure 1:1 into HTML — that defeats the entire point of escalating to HTML.
6. **Editors export back to text.** If the artifact lets the user manipulate state (drag, toggle, edit, reorder, tune), it **must** end with a "复制为 markdown / JSON / prompt" button that round-trips the UI state into something pasteable. The whole point of a throwaway editor is the round-trip. Non-negotiable.

### 4.1 Document structure

A well-formed document page has, in order:

1. **Eyebrow** — mono uppercase, gray-500. One short line of context (project / document type).
2. **`h1`** — serif, descriptive sentence-form title. Not a label.
3. **TL;DR box** — white card with left clay border, ~16–20px padding. Inside: a small mono "Premise" / "TL;DR" label, then the prose. This is the only place the user is allowed to read just one paragraph and get the point.
4. **Summary strip** — 4-cell grid of key-value cards (`效果` / `层级` / `工具数` / `漏洞 fixture 数` style). 4 columns desktop, 2 on tablet.
5. **Numbered sections** — each headed by `<span class="num">01</span><h2>…</h2>`, followed by a single muted intro paragraph.
6. **Footer** — single italic-leaning paragraph tying the document back to the broader goal. Top border, gray-500 text.

Section content patterns (mix and match):

- **Milestone timeline** — 3-column grid (`when` / dot+line / body). Dots: clay outline default, olive-filled for done, plum-outline for "stretch / optional".
- **SVG diagram** — embedded inline SVG inside a white card. **Diagrams must use SVG**, not ASCII art or HTML/CSS box-drawing. See §6.
- **Mockups** — 2-column grid of mock cards, each with a mono uppercase label header and a body that simulates the real UI.
- **Code block** — slate (`#141413`) background card, mono 12.5px, with token coloring: clay for keywords, olive for strings, gray-500 italic for comments, `#C9B98A` for function names.
- **Risk / depth table** — grid-based, not `<table>`, with `1.5px` borders. Header row in `gray-150`.
- **Open questions** — white cards with 4px clay left border. Serif question title, sans description, mono "决定于 · 阶段 X 之前" owner line.
- **Profile pairs** — side-by-side cards. Safe = olive left border + olive `safe` tag. Vulnerable = clay left border + clay `vulnerable` tag.

---

## 5. Tone and content rules

- **Editorial, not dashboard.** Write in full sentences. Avoid bullet-soup. A section with three substantive paragraphs is usually better than a section with twelve fragmentary bullets.
- **Show, don't list.** When the user gives you a list, ask whether each item deserves a card, a row in a table, or a milestone. Don't auto-render lists as `<ul>`.
- **Numbered section titles do real work.** They let the reader skim and jump. Use sentence-form titles ("八周时间线", not "时间线").
- **Captions on diagrams are mandatory.** Every SVG ends with `<p class="caption">…</p>` explaining what the visual encoding means.
- **No emoji unless the user asks.** Use `✓ ✗ ▸ ·` and Unicode arrows where small glyphs are needed.

### 5.1 The document is not the conversation — never leak the prompt (MANDATORY)

The chat with the user contains two kinds of statements: **(1) what the document should say** — the subject matter, conclusions, facts, decisions; and **(2) how we are discussing it** — the user's feedback, your response to that feedback, and any phrase that points at the chat's shared context. **Only (1) belongs in the artifact. Category (2) must never appear.** The reader receives only the finished document — they have none of the chat history — so any phrase that only makes sense given our conversation lands as a dangling, confusing sentence.

This is a recurring failure: the user pushes back ("you're overrating `scan.py`"), and that correction leaks verbatim into the doc as **"先把 scan.py 的位置摆正"** (let's first set scan.py's position straight). A reader with no chat context reads that and asks: *set it straight from what? where was it wrong before?* The sentence describes the **act of responding to feedback**, not the conclusion. The fix is to state only the conclusion — *"scan.py 不是本项目要对标的基准"* — and delete the corrective framing entirely.

**Signal phrases that indicate leaked prompt / conversational voice — scan for these before declaring done:**

- **Corrective framing** addressed at the reader: "先把 X 摆正 / 澄清一下 / 需要纠正的是 / 要把 X 的位置说清楚". These narrate *your editing process*, not the content.
- **Second person `你`** pointing at the user personally: "你每周五有组会", "这是你最该学的", "你已明确". The user's private context (their schedule, what they just told you) is not the reader's. Restate as an impersonal project fact ("项目设有每周五的组会节点").
- **Echoing the user's just-given answer**: "你已明确…", "按你说的…", "如你所要求". The reader never saw the question, so the answer has nothing to attach to. State the resulting fact flatly ("两项功能均以授权为前提，这一点已定").
- **Meta-narration of the document itself**: "这一节先把…论证清楚", "下表左列是…右列是…", "我来说明". The reader can see the section and the table; don't read the layout aloud to them. Let headings and table headers do that work; introduce with a plain declarative sentence.
- **Pointers into the chat timeline**: "刚才提到", "前面我们说", "如上文对话".

**Legitimate exceptions — these are content, not leakage, and stay:**

- Stating the *cause* of a decision as project background: "与导师讨论后决定改变方向" is the documented rationale for a redirection, the kind any proposal carries. It is third-person, names no `你`, issues no imperative at the reader.
- Referring to the document's own subject when that subject genuinely is a change: a redirection proposal may say "这次方向调整的核心是…" because the redirection *is* what the document is about — that points at the content, not at our chat.

**The test:** read the sentence as a stranger who never saw the chat. If they would ask "*from what?*", "*who said that?*", "*which question?*", or "*you who?*", it is leaked context — rewrite it as a standalone declarative statement of the conclusion.

---

## 6. SVG diagram rules (this is where mistakes happen)

Two recurring failure modes to actively avoid:

### 6.1 Text must fit inside its container

Before committing an SVG, mentally measure the longest text string in each `<rect>`:

- Mono 12px ≈ **7.2px per character** for ASCII
- Mono 12px Chinese ≈ **12–13px per character**

For a 380px-wide rect at 12px mono, the safe character budget is roughly **50 ASCII chars** or **28 Chinese chars**, leaving 20px of padding on each side. If the label exceeds that, **widen the rect, shrink the font, wrap onto two `<text>` lines, or shorten the label** — in that order of preference.

**Never let text run past `x + width` of its rect.** This was the original sin in the L6 row of the previous diagram. If two `<text>` siblings overflow, you almost certainly need to drop the rect into two stacked lines:

```xml
<text x="248" y="474" font-weight="600">Docker workspace · path resolver · shell exec</text>
<text x="248" y="491" fill="#C9B98A" font-size="10.5">per-session FS · network toggle · env allowlist · timeout</text>
```

Use `text-anchor="middle"` only when the rect is wide enough for the longest line. Otherwise left-align with explicit `x` and verify the right edge.

### 6.2 Don't reuse a visual token without re-deriving its semantics

In the source examples, a black-fill rect on an otherwise light diagram means **"this is a persistence terminus — data lands here and is no longer in flight"**. It does **not** mean "this is the bottom of a vertical stack" or "this is the most important node".

Before applying inverted color (slate fill + ivory text + olive/oat secondary text), ask: *what is being claimed by the inversion?* If the answer is "I don't know, it just looked nice", revert to the default white-fill style.

A safer rule: in a stack of 6–8 layered boxes where every layer is research-equivalent, **no box gets inverted**. Reserve inversion for cases where one node is categorically different from its peers (terminal storage, external system boundary, etc.).

### 6.3 SVG sizing checklist

- Set `viewBox` with explicit width/height; never rely on intrinsic SVG sizing.
- Wrap diagrams in `.diagram` cards with `overflow-x: auto` so wide diagrams scroll instead of overflow.
- Set a `min-width` on the SVG (e.g. `min-width: 760px`) so it doesn't squish on mobile.
- Test by mentally rendering at 1120px wide and at 720px wide.

---

## 7. Things to explicitly NOT do

- Don't use a dark-mode (dark gray / GitHub-style) palette. The base style is light, warm, document-like.
- Don't use shadows (`box-shadow`). Borders only.
- Don't use gradients on backgrounds. Solid fills only. (Gradients are acceptable inside SVG illustrations.)
- Don't use emojis as bullets or icons. Use the inline marker pattern: `::before { content: "✓"; color: var(--olive); }`.
- Don't use rounded-pill chips with bright background colors. Chips are mono on oat or gray-150 with subtle gray-300 border.
- Don't generate a sticky navbar, breadcrumb, "back to top" button, or any other web-app chrome. These are documents, not apps.
- Don't add JavaScript unless the page genuinely needs interactivity (a tabbed code block, a collapsible details panel). Static HTML is the default.
- Don't write ASCII flowcharts (`↓ ▼ →`) when an SVG would do. ASCII reads as a fallback and signals lower effort.
- Don't put long line lengths on prose. Cap around 760px.
- Don't use the `<table>` element for layouts that are conceptually grids. Use CSS grid with `.row` / `.cell` class names — it's easier to make responsive.

### 7.1 "AI-default look" smell check — any three of these → restart

A separate-but-related list. These are the things generic LLM-generated HTML defaults to and what makes it look generated rather than read. If the page-in-progress hits three or more, stop and restart from the typography baseline:

- Rounded-corner cards with drop shadows on a plain gray background, used as the page's default container.
- A full-bleed gradient hero banner at the top.
- Emoji as section headers (📊 数据 / 🚀 部署 / 🔒 安全).
- Four shades of indigo, violet, or teal doing no semantic work — just "vibes".
- shadcn-shaped components (rounded button, muted ring, "Card / CardHeader / CardContent" structure) when no shadcn library is involved.
- "Glass morphism" / frosted blur / animated gradient backgrounds.
- Centered everything (centered hero, centered cards, centered text in long-form prose).
- A header bar with a "logo" placeholder square.
- More than two accent colors on the page that aren't doing semantic work.
- Generic stock-illustration SVGs or icon-grid decoration with no informational role.

The reference points for what *good* looks like: Stripe Press long-form pages, Bartosz Ciechanowski's explainers, NYT graphics desk pieces, OEIS reference pages, the source `thariqs.github.io/html-effectiveness` examples. Things that look like *someone read them*, not like they were generated.

---

## 8. Pre-flight checklist

Before declaring an HTML artifact done, verify:

- [ ] The HTML format was justified — §−1 escalation criteria met, not just generated by reflex
- [ ] Single self-contained `.html` file, no external dependencies required at view time (§4.0)
- [ ] `<meta viewport>` present; layout survives a phone-width viewport (§4.0)
- [ ] If the artifact allows manipulation, a "复制为 markdown / JSON / prompt" round-trip button is present (§4.0)
- [ ] All body prose is in 中文; technical identifiers stay in English/mono
- [ ] Chinese font fallbacks present in `--sans` and `--serif`
- [ ] Chinese-tuned typography in use: body `line-height ≥ 1.75`, intros/TL;DR `≥ 1.8`, no negative `letter-spacing` on headings (§2)
- [ ] Punctuation follows the surrounding language: full-width `，：；。？！（）“”` inside Chinese prose; ASCII punctuation stays only in code, attribute values, and English fragments (§0.1)
- [ ] No leaked prompt / conversational voice: no corrective framing at the reader ("先把 X 摆正"), no second-person `你`, no echoing the user's just-given answer ("你已明确"), no meta-narration of layout ("下表左列是…"). Read each sentence as a stranger with no chat history — if they'd ask "from what? / who said? / you who?", rewrite it (§5.1)
- [ ] Color palette uses only the 11 defined tokens
- [ ] Every section has a numbered chip + serif `h2` + muted intro paragraph
- [ ] No text overflows any SVG `<rect>` (mentally measure each label against its container width)
- [ ] Black-fill (inverted) rects are used only for genuine semantic outliers, not for visual flair
- [ ] Every SVG ends with a `<p class="caption">` explaining the visual encoding
- [ ] No emojis, no shadows, no gradients on backgrounds, no JavaScript unless required
- [ ] Run the §7.1 smell check — if three or more "AI-default" markers are present, restart
- [ ] Page renders cleanly at 1120px and degrades gracefully at 720px
- [ ] Footer paragraph ties the document back to the broader research / project goal
