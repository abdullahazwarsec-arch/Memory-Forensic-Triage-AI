"""
Forensic Ops UI theme & components for the Streamlit dashboard.

Dark "digital forensics lab" look: deep slate surfaces, cyan accent,
monospace for evidence data (hashes, offsets, metrics), readable type scale.
All HTML helpers flatten their markup so Markdown never turns indented
lines into code blocks.
"""

import html as _html
import streamlit as st


# ── Design tokens ─────────────────────────────────────────────────────────────
BG          = "#070b10"
SURFACE     = "#0f1720"
SURFACE_2   = "#131d29"
BORDER      = "#1f2b3a"
BORDER_HI   = "#2c3d52"
TEXT        = "#e6edf3"
TEXT_2      = "#a9b6c6"
MUTED       = "#7d8ca0"
ACCENT      = "#22d3ee"
ACCENT_DEEP = "#0891b2"

# Status (always paired with an icon + label, never colour alone)
GOOD     = "#34d399"
WARNING  = "#fab219"
CRITICAL = "#f87171"

# Chart diverging pair (validated: dark surface #0f1720, CVD-safe, >=3:1)
TOWARD_MALWARE = "#e66767"
TOWARD_BENIGN  = "#3987e5"

TONES = {
    "good":     (GOOD,     "rgba(52, 211, 153, 0.10)",  "rgba(52, 211, 153, 0.35)"),
    "warning":  (WARNING,  "rgba(250, 178, 25, 0.10)",  "rgba(250, 178, 25, 0.35)"),
    "critical": (CRITICAL, "rgba(248, 113, 113, 0.10)", "rgba(248, 113, 113, 0.40)"),
    "accent":   (ACCENT,   "rgba(34, 211, 238, 0.10)",  "rgba(34, 211, 238, 0.35)"),
    "neutral":  (TEXT_2,   "rgba(169, 182, 198, 0.08)", "rgba(169, 182, 198, 0.25)"),
}


def esc(value) -> str:
    return _html.escape(str(value) if value is not None else "")


def render_html(markup: str):
    """Render an HTML block; flattened so blank/indented lines never become code blocks."""
    st.markdown("".join(line.strip() for line in markup.strip().splitlines()), unsafe_allow_html=True)


# ── Global stylesheet ─────────────────────────────────────────────────────────
def inject_theme():
    st.markdown(
        f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {{
  --bg: {BG}; --surface: {SURFACE}; --surface-2: {SURFACE_2};
  --border: {BORDER}; --border-hi: {BORDER_HI};
  --text: {TEXT}; --text-2: {TEXT_2}; --muted: {MUTED};
  --accent: {ACCENT}; --accent-deep: {ACCENT_DEEP};
  --good: {GOOD}; --warning: {WARNING}; --critical: {CRITICAL};
  --radius: 14px;
  --mono: 'JetBrains Mono', ui-monospace, monospace;
}}

/* ── Canvas: faint hex-grid "memory map" ── */
.stApp {{
  background-color: var(--bg) !important;
  background-image:
    radial-gradient(ellipse at 85% -10%, rgba(34, 211, 238, 0.10), transparent 55%),
    radial-gradient(ellipse at -10% 110%, rgba(8, 145, 178, 0.10), transparent 50%),
    linear-gradient(rgba(34, 211, 238, 0.025) 1px, transparent 1px),
    linear-gradient(90deg, rgba(34, 211, 238, 0.025) 1px, transparent 1px) !important;
  background-size: auto, auto, 32px 32px, 32px 32px !important;
  background-attachment: fixed !important;
  color: var(--text) !important;
}}

/* ── Typography (larger, readable scale) ── */
/* Spans are deliberately excluded: Streamlit renders Material icons as spans */
html, body, .stApp, p, li, label, div, input, textarea, button {{
  font-family: 'Inter', system-ui, sans-serif !important;
}}
.stApp p, .stApp li {{ font-size: 1rem; line-height: 1.6; }}
code, pre, .mono {{ font-family: var(--mono) !important; }}
:not(pre) > code {{
  background: rgba(34, 211, 238, 0.08) !important; color: #7ee3f5 !important;
  border: 1px solid rgba(34, 211, 238, 0.18) !important; border-radius: 6px !important;
  padding: 0.1rem 0.4rem !important; font-size: 0.88em !important; overflow-wrap: anywhere;
}}
.block-container {{ padding-top: 2.2rem !important; padding-bottom: 4rem !important; max-width: 1320px !important; }}

/* ── Sidebar ── */
[data-testid="stSidebar"] {{
  background: linear-gradient(180deg, #0b121a 0%, #080d13 100%) !important;
  border-right: 1px solid var(--border) !important;
}}
[data-testid="stSidebar"] .block-container {{ padding-top: 1.5rem !important; }}

/* ── Widget labels ── */
[data-testid="stWidgetLabel"] p {{ font-size: 0.95rem !important; font-weight: 600 !important; color: var(--text-2) !important; }}
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p {{ color: var(--muted) !important; font-size: 0.88rem !important; }}

/* ── Buttons ── */
.stButton > button, .stDownloadButton > button {{
  min-height: 3rem !important; border-radius: 10px !important;
  font-size: 1rem !important; font-weight: 600 !important; letter-spacing: 0.01em;
  transition: transform .15s ease, box-shadow .2s ease, border-color .2s ease, background .2s ease !important;
}}
.stButton > button p, .stDownloadButton > button p {{ font-size: 1rem !important; font-weight: 600 !important; }}
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"],
[data-testid="stFormSubmitButton"] > button[kind="primaryFormSubmit"] {{
  background: linear-gradient(135deg, #22d3ee 0%, #0891b2 100%) !important;
  border: 1px solid rgba(34, 211, 238, 0.6) !important; color: #031018 !important;
  box-shadow: 0 6px 22px -6px rgba(34, 211, 238, 0.55) !important;
}}
.stButton > button[kind="primary"] p, .stDownloadButton > button[kind="primary"] p,
[data-testid="stFormSubmitButton"] > button[kind="primaryFormSubmit"] p {{ color: #031018 !important; }}
[data-testid="stFormSubmitButton"] > button {{ min-height: 3rem !important; border-radius: 10px !important; padding: 0 1.4rem !important; }}
[data-testid="stFormSubmitButton"] > button p {{ font-size: 1rem !important; font-weight: 600 !important; }}
.stButton > button[kind="primary"]:hover, .stDownloadButton > button[kind="primary"]:hover {{
  transform: translateY(-1px); box-shadow: 0 10px 28px -6px rgba(34, 211, 238, 0.75) !important;
}}
.stButton > button:not([kind="primary"]), .stDownloadButton > button:not([kind="primary"]) {{
  background: var(--surface-2) !important; border: 1px solid var(--border-hi) !important; color: var(--text) !important;
}}
.stButton > button:not([kind="primary"]):hover, .stDownloadButton > button:not([kind="primary"]):hover {{
  border-color: var(--accent) !important; color: var(--accent) !important; transform: translateY(-1px);
}}
.stButton > button:not([kind="primary"]):hover p {{ color: var(--accent) !important; }}

/* ── Segmented control / pills ── */
[data-testid="stButtonGroup"] button {{ min-height: 2.9rem !important; font-size: 0.98rem !important; padding: 0 1.1rem !important; }}
[data-testid="stButtonGroup"] button p {{ font-size: 0.98rem !important; font-weight: 600 !important; }}

/* ── Inputs ── */
div[data-baseweb="select"] > div, [data-testid="stTextInput"] input {{
  background-color: var(--surface-2) !important; border-color: var(--border-hi) !important;
  border-radius: 10px !important; font-size: 1rem !important; min-height: 2.9rem;
}}
div[data-baseweb="popover"] ul[role="listbox"] {{ background: var(--surface-2) !important; border: 1px solid var(--border-hi) !important; }}
li[role="option"] {{ font-size: 0.98rem !important; }}
li[role="option"]:hover, li[aria-selected="true"] {{ background: rgba(34, 211, 238, 0.12) !important; }}
[data-testid="stFileUploader"] section {{
  background: var(--surface-2) !important; border: 1.5px dashed var(--border-hi) !important; border-radius: var(--radius) !important;
}}
[data-testid="stFileUploader"] section:hover {{ border-color: var(--accent) !important; }}

/* ── Tabs ── */
[data-testid="stTabs"] [role="tablist"] {{ gap: 0.4rem; border-bottom: 1px solid var(--border) !important; }}
[data-testid="stTabs"] button[role="tab"] {{
  padding: 0.75rem 1.1rem !important; border-radius: 10px 10px 0 0 !important;
}}
[data-testid="stTabs"] button[role="tab"] p {{ font-size: 1.02rem !important; font-weight: 600 !important; color: var(--muted) !important; }}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {{ background: rgba(34, 211, 238, 0.07) !important; }}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] p {{ color: var(--accent) !important; }}
[data-testid="stTabs"] [data-baseweb="tab-highlight"] {{ background-color: var(--accent) !important; height: 3px !important; }}

/* ── Expanders, alerts, tables ── */
[data-testid="stExpander"] details {{ background: var(--surface) !important; border: 1px solid var(--border) !important; border-radius: var(--radius) !important; }}
[data-testid="stExpander"] summary p {{ font-size: 1rem !important; font-weight: 600 !important; }}
[data-testid="stExpander"] summary:hover p {{ color: var(--accent) !important; }}
[data-testid="stAlert"] {{ border-radius: 12px !important; }}
[data-testid="stAlert"] p {{ font-size: 0.98rem !important; }}
[data-testid="stDataFrame"] {{ border: 1px solid var(--border) !important; border-radius: 12px !important; overflow: hidden; }}
[data-testid="stVerticalBlockBorderWrapper"] {{ border-color: var(--border) !important; border-radius: var(--radius) !important; }}
header[data-testid="stHeader"] {{ background: transparent !important; }}
footer {{ visibility: hidden !important; }}

/* ── Components ── */
.fx-card {{
  background: linear-gradient(180deg, rgba(19, 29, 41, 0.92), rgba(15, 23, 32, 0.92));
  border: 1px solid var(--border); border-radius: var(--radius); padding: 1.25rem 1.4rem;
  box-shadow: 0 10px 30px -18px rgba(0, 0, 0, 0.8);
}}
.fx-header {{
  display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap;
  padding: 1.1rem 1.4rem; margin-bottom: 1.1rem; border-radius: 16px;
  background: linear-gradient(120deg, rgba(34, 211, 238, 0.10), rgba(15, 23, 32, 0.6) 45%);
  border: 1px solid var(--border);
}}
.fx-brand {{ display: flex; align-items: center; gap: 0.95rem; }}
.fx-logo {{
  width: 52px; height: 52px; border-radius: 12px; display: grid; place-items: center; font-size: 1.6rem;
  background: radial-gradient(circle at 30% 30%, rgba(34, 211, 238, 0.35), rgba(8, 145, 178, 0.15));
  border: 1px solid rgba(34, 211, 238, 0.45); box-shadow: 0 0 24px -6px rgba(34, 211, 238, 0.6);
}}
.fx-title {{ font-size: 1.6rem; font-weight: 800; letter-spacing: -0.02em; color: var(--text); line-height: 1.15; }}
.fx-title span {{ color: var(--accent); }}
.fx-sub {{ font-size: 0.95rem; color: var(--muted); margin-top: 0.15rem; }}
.fx-chips {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}

.fx-pill {{
  display: inline-flex; align-items: center; gap: 0.4rem; white-space: nowrap;
  padding: 0.3rem 0.75rem; border-radius: 999px; font-size: 0.85rem; font-weight: 600;
}}
.fx-dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; box-shadow: 0 0 0 0 currentColor; animation: fx-pulse 2.2s infinite; }}
@keyframes fx-pulse {{ 0% {{ box-shadow: 0 0 0 0 rgba(255,255,255,0.35); }} 70% {{ box-shadow: 0 0 0 7px rgba(255,255,255,0); }} 100% {{ box-shadow: 0 0 0 0 rgba(255,255,255,0); }} }}

.fx-steps {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 0.6rem; margin-bottom: 1.6rem; }}
.fx-step {{
  display: flex; align-items: center; gap: 0.7rem; padding: 0.75rem 0.9rem; border-radius: 12px;
  background: var(--surface); border: 1px solid var(--border); min-width: 0;
}}
.fx-step-num {{
  flex: 0 0 auto; width: 34px; height: 34px; border-radius: 50%; display: grid; place-items: center;
  font-weight: 700; font-size: 0.95rem; border: 1.5px solid var(--border-hi); color: var(--muted);
}}
.fx-step-label {{ font-weight: 600; font-size: 0.98rem; color: var(--text-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.fx-step-sub {{ font-size: 0.8rem; color: var(--muted); }}
.fx-step.done .fx-step-num {{ background: rgba(52, 211, 153, 0.15); border-color: var(--good); color: var(--good); }}
.fx-step.active {{ border-color: rgba(34, 211, 238, 0.55); box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.08); }}
.fx-step.active .fx-step-num {{ background: rgba(34, 211, 238, 0.15); border-color: var(--accent); color: var(--accent); }}
.fx-step.active .fx-step-label {{ color: var(--text); }}
.fx-step.blocked .fx-step-num {{ background: rgba(248, 113, 113, 0.15); border-color: var(--critical); color: var(--critical); }}

.fx-section {{ display: flex; align-items: center; gap: 0.75rem; margin: 2rem 0 0.9rem 0; }}
.fx-section-icon {{
  width: 38px; height: 38px; border-radius: 10px; display: grid; place-items: center; font-size: 1.15rem;
  background: rgba(34, 211, 238, 0.10); border: 1px solid rgba(34, 211, 238, 0.3);
}}
.fx-section-title {{ font-size: 1.4rem; font-weight: 700; color: var(--text); letter-spacing: -0.01em; line-height: 1.2; }}
.fx-section-sub {{ font-size: 0.95rem; color: var(--muted); margin-top: 0.1rem; }}

.fx-kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.8rem; }}
.fx-kpi {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 0.95rem 1.1rem; min-width: 0; }}
.fx-kpi-label {{ font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }}
.fx-kpi-value {{ font-size: 1.3rem; font-weight: 700; color: var(--text); margin-top: 0.25rem; overflow-wrap: anywhere; line-height: 1.25; }}
.fx-kpi-value.mono {{ font-family: var(--mono) !important; font-size: 0.98rem; word-break: break-all; }}
.fx-kpi-value.small {{ font-size: 1.05rem; word-break: break-all; }}
.fx-kpi.wide {{ grid-column: span 2; }}
.fx-verdict .fx-kpis {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
.fx-kpi-sub {{ font-size: 0.85rem; color: var(--muted); margin-top: 0.2rem; overflow-wrap: anywhere; }}

.fx-verdict {{ display: grid; grid-template-columns: 220px 1fr; gap: 1.4rem; align-items: center; }}
.fx-gauge {{
  width: 190px; height: 190px; border-radius: 50%; display: grid; place-items: center; margin: 0 auto;
}}
.fx-gauge-inner {{
  width: 150px; height: 150px; border-radius: 50%; background: var(--surface); display: flex; flex-direction: column;
  align-items: center; justify-content: center; border: 1px solid var(--border);
}}
.fx-gauge-value {{ font-size: 2.3rem; font-weight: 800; letter-spacing: -0.03em; line-height: 1; }}
.fx-gauge-label {{ font-size: 0.82rem; color: var(--muted); margin-top: 0.35rem; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; }}
.fx-banner {{ display: flex; align-items: flex-start; gap: 0.9rem; padding: 1rem 1.2rem; border-radius: 12px; margin-top: 0.9rem; }}
.fx-banner-title {{ font-size: 1.1rem; font-weight: 700; }}
.fx-banner-text {{ font-size: 0.98rem; color: var(--text-2); margin-top: 0.15rem; }}

.fx-hash {{ margin-top: 0.85rem; }}
.fx-hash-label {{ font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }}
.fx-hash-value {{ font-family: var(--mono) !important; font-size: 0.95rem; color: #7ee3f5; overflow-wrap: anywhere; margin-top: 0.15rem; }}

.fx-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 0.9rem; }}
.fx-driver {{ display: flex; flex-direction: column; gap: 0.45rem; height: 100%; box-sizing: border-box; }}
.fx-driver-title {{ font-size: 1.08rem; font-weight: 700; color: var(--text); }}
.fx-driver-text {{ font-size: 0.95rem; color: var(--text-2); line-height: 1.5; }}
.fx-driver-meta {{ margin-top: auto; padding-top: 0.6rem; border-top: 1px solid var(--border); font-size: 0.88rem; color: var(--muted); }}

.fx-action {{ display: flex; align-items: center; gap: 0.85rem; padding: 0.85rem 1.1rem; border-radius: 12px; background: var(--surface); border: 1px solid var(--border); margin-bottom: 0.55rem; }}
.fx-action-num {{ flex: 0 0 auto; width: 30px; height: 30px; border-radius: 8px; display: grid; place-items: center; font-weight: 700; font-size: 0.9rem; }}
.fx-action-text {{ font-size: 1rem; color: var(--text); }}

.fx-empty {{ text-align: center; padding: 2.6rem 1.5rem; }}
.fx-empty-icon {{ font-size: 2.6rem; margin-bottom: 0.6rem; }}
.fx-empty-title {{ font-size: 1.2rem; font-weight: 700; color: var(--text); }}
.fx-empty-text {{ font-size: 0.98rem; color: var(--muted); max-width: 560px; margin: 0.4rem auto 0; }}

.fx-side-label {{ font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin: 1.3rem 0 0.55rem; }}
.fx-side-row {{ display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.6rem 0.75rem; border-radius: 10px; background: var(--surface); border: 1px solid var(--border); margin-bottom: 0.45rem; font-size: 0.92rem; color: var(--text-2); }}
.fx-check {{ display: flex; align-items: center; gap: 0.6rem; font-size: 0.95rem; color: var(--text-2); padding: 0.32rem 0; }}

@media (max-width: 760px) {{
  .fx-kpi.wide {{ grid-column: auto; }}
  .fx-verdict .fx-kpis {{ grid-template-columns: 1fr; }}
  .fx-steps {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
  .fx-verdict {{ grid-template-columns: 1fr; }}
  .fx-title {{ font-size: 1.3rem; }}
}}
</style>
        """,
        unsafe_allow_html=True,
    )


# ── Components ────────────────────────────────────────────────────────────────
def pill(text: str, tone: str = "accent", dot: bool = True) -> str:
    fg, bg, border = TONES.get(tone, TONES["neutral"])
    d = f'<span class="fx-dot" style="background:{fg};"></span>' if dot else ""
    return (f'<span class="fx-pill" style="color:{fg};background:{bg};border:1px solid {border};">'
            f'{d}{esc(text)}</span>')


def page_header(title_main: str, title_accent: str, subtitle: str, chips: list):
    render_html(f"""
    <div class="fx-header">
      <div class="fx-brand">
        <div class="fx-logo">🧬</div>
        <div>
          <div class="fx-title">{esc(title_main)} <span>{esc(title_accent)}</span></div>
          <div class="fx-sub">{esc(subtitle)}</div>
        </div>
      </div>
      <div class="fx-chips">{''.join(chips)}</div>
    </div>
    """)


def stepper(steps: list):
    """steps: list of (label, sub, state) with state in done|active|pending|blocked."""
    items = []
    for i, (label, sub, state) in enumerate(steps, start=1):
        mark = "✓" if state == "done" else ("!" if state == "blocked" else str(i))
        items.append(
            f'<div class="fx-step {state}"><div class="fx-step-num">{mark}</div>'
            f'<div style="min-width:0;"><div class="fx-step-label">{esc(label)}</div>'
            f'<div class="fx-step-sub">{esc(sub)}</div></div></div>'
        )
    render_html(f'<div class="fx-steps">{"".join(items)}</div>')


def section(title: str, subtitle: str = "", icon: str = "◆"):
    sub = f'<div class="fx-section-sub">{esc(subtitle)}</div>' if subtitle else ""
    render_html(f"""
    <div class="fx-section">
      <div class="fx-section-icon">{icon}</div>
      <div><div class="fx-section-title">{esc(title)}</div>{sub}</div>
    </div>
    """)


def kpi(label: str, value: str, sub: str = "", mono: bool = False, color: str = None,
        small: bool = False, wide: bool = False) -> str:
    style = f' style="color:{color};"' if color else ""
    sub_html = f'<div class="fx-kpi-sub">{sub}</div>' if sub else ""
    value_cls = "fx-kpi-value" + (" mono" if mono else "") + (" small" if small else "")
    return (f'<div class="fx-kpi{" wide" if wide else ""}"><div class="fx-kpi-label">{esc(label)}</div>'
            f'<div class="{value_cls}"{style}>{value}</div>{sub_html}</div>')


def kpi_row(tiles: list):
    render_html(f'<div class="fx-kpis">{"".join(tiles)}</div>')


def hash_line(label: str, value: str) -> str:
    return (f'<div class="fx-hash"><div class="fx-hash-label">{esc(label)}</div>'
            f'<div class="fx-hash-value">{esc(value)}</div></div>')


def gauge(pct: float, tone: str, label: str) -> str:
    fg = TONES[tone][0]
    deg = max(0.0, min(100.0, pct)) * 3.6
    return (f'<div class="fx-gauge" style="background: conic-gradient({fg} {deg}deg, {BORDER} {deg}deg);">'
            f'<div class="fx-gauge-inner"><div class="fx-gauge-value" style="color:{fg};">{pct:.1f}%</div>'
            f'<div class="fx-gauge-label">{esc(label)}</div></div></div>')


def banner(icon: str, title: str, text: str, tone: str) -> str:
    fg, bg, border = TONES[tone]
    return (f'<div class="fx-banner" style="background:{bg};border:1px solid {border};">'
            f'<div style="font-size:1.5rem;line-height:1;">{icon}</div>'
            f'<div><div class="fx-banner-title" style="color:{fg};">{esc(title)}</div>'
            f'<div class="fx-banner-text">{text}</div></div></div>')


def empty_state(icon: str, title: str, text: str):
    render_html(f"""
    <div class="fx-card fx-empty">
      <div class="fx-empty-icon">{icon}</div>
      <div class="fx-empty-title">{esc(title)}</div>
      <div class="fx-empty-text">{text}</div>
    </div>
    """)
