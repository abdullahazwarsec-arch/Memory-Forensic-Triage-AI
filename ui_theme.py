"""
Black & Gold UI theme & components for the Streamlit dashboard.

Sleek, minimal look inspired by modern Framer sites: pure-black canvas with a
soft golden glow, translucent glass cards, tight high-contrast typography
(Plus Jakarta Sans), pill-shaped buttons/tabs with a yellow→amber gradient and
Material Symbols icons. Monospace is kept for evidence data (hashes, metrics).
All HTML helpers flatten their markup so Markdown never turns indented lines
into code blocks.
"""

import re
import html as _html
import streamlit as st


# ── Design tokens ─────────────────────────────────────────────────────────────
BG          = "#000000"
SURFACE     = "#0b0b0d"
SURFACE_2   = "#131316"
BORDER      = "#1f1f24"
BORDER_HI   = "#2d2d34"
TEXT        = "#f5f5f5"
TEXT_2      = "#b9b9c4"
MUTED       = "#8a8a99"
ACCENT      = "#fcc21b"     # gold
ACCENT_DEEP = "#e48c15"     # amber
ACCENT_SOFT = "#ffd970"     # pale gold for text on black (hashes, code)

# Status (always paired with an icon + label, never colour alone).
# Warning is orange, not yellow, so it never reads as the brand accent.
GOOD     = "#4ade80"
WARNING  = "#ff8a3d"
CRITICAL = "#ff5f5f"

# Chart diverging pair (CVD-safe, >=3:1 on the black surface)
TOWARD_MALWARE = "#e66767"
TOWARD_BENIGN  = "#3987e5"

TONES = {
    "good":     (GOOD,     "rgba(74, 222, 128, 0.09)",  "rgba(74, 222, 128, 0.32)"),
    "warning":  (WARNING,  "rgba(255, 138, 61, 0.10)",  "rgba(255, 138, 61, 0.36)"),
    "critical": (CRITICAL, "rgba(255, 95, 95, 0.10)",   "rgba(255, 95, 95, 0.40)"),
    "accent":   (ACCENT,   "rgba(252, 194, 27, 0.10)",  "rgba(252, 194, 27, 0.38)"),
    "neutral":  (TEXT_2,   "rgba(255, 255, 255, 0.05)", "rgba(255, 255, 255, 0.14)"),
}

GRADIENT = f"linear-gradient(135deg, #ffe066 0%, {ACCENT} 42%, {ACCENT_DEEP} 100%)"


def esc(value) -> str:
    return _html.escape(str(value) if value is not None else "")


def render_html(markup: str):
    """Render an HTML block; flattened so blank/indented lines never become code blocks."""
    st.markdown("".join(line.strip() for line in markup.strip().splitlines()), unsafe_allow_html=True)


def icon(name: str, size: str = None, color: str = None) -> str:
    """Material Symbols Rounded glyph, e.g. icon('memory')."""
    style = ";".join(s for s in (f"font-size:{size}" if size else "", f"color:{color}" if color else "") if s)
    attr = f' style="{style}"' if style else ""
    return f'<span class="fx-icon"{attr}>{esc(name)}</span>'


def _glyph(value: str, size: str = None) -> str:
    """Material icon name (snake_case) → icon; anything else (emoji/text) is rendered as-is."""
    return icon(value, size) if re.fullmatch(r"[a-z0-9_]+", value or "") else esc(value)


# ── Global stylesheet ─────────────────────────────────────────────────────────
def inject_theme():
    st.markdown(
        f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
@import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,300..600,0..1,0&display=block');

:root {{
  --bg: {BG}; --surface: {SURFACE}; --surface-2: {SURFACE_2};
  --border: {BORDER}; --border-hi: {BORDER_HI};
  --text: {TEXT}; --text-2: {TEXT_2}; --muted: {MUTED};
  --accent: {ACCENT}; --accent-deep: {ACCENT_DEEP}; --accent-soft: {ACCENT_SOFT};
  --good: {GOOD}; --warning: {WARNING}; --critical: {CRITICAL};
  --gradient: {GRADIENT};
  --glass: rgba(255, 255, 255, 0.025); --glass-border: rgba(255, 255, 255, 0.08);
  --radius: 20px; --radius-sm: 14px;
  --mono: 'JetBrains Mono', ui-monospace, monospace;
  --sans: 'Plus Jakarta Sans', 'Inter', system-ui, sans-serif;
}}

/* ── Canvas: black with a soft golden glow and a faint dot grid ── */
.stApp {{
  background-color: var(--bg) !important;
  background-image:
    radial-gradient(ellipse 70% 45% at 50% -12%, rgba(252, 194, 27, 0.13), transparent 70%),
    radial-gradient(ellipse 40% 35% at 100% 100%, rgba(228, 140, 21, 0.06), transparent 70%),
    radial-gradient(rgba(255, 255, 255, 0.045) 1px, transparent 1px) !important;
  background-size: auto, auto, 26px 26px !important;
  background-attachment: fixed !important;
  color: var(--text) !important;
}}
::selection {{ background: var(--accent); color: #000; }}
* {{ scrollbar-width: thin; scrollbar-color: #2a2a30 transparent; }}
::-webkit-scrollbar {{ width: 9px; height: 9px; }}
::-webkit-scrollbar-thumb {{ background: #2a2a30; border-radius: 999px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--accent-deep); }}

/* ── Typography ── */
/* Spans are deliberately excluded: Streamlit renders Material icons as spans */
html, body, .stApp, p, li, label, div, input, textarea, button {{ font-family: var(--sans) !important; }}
.stApp p, .stApp li {{ font-size: 1rem; line-height: 1.6; }}
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5 {{ font-family: var(--sans) !important; letter-spacing: -0.03em !important; font-weight: 800 !important; }}
code, pre, .mono {{ font-family: var(--mono) !important; }}
:not(pre) > code {{
  background: rgba(252, 194, 27, 0.08) !important; color: var(--accent-soft) !important;
  border: 1px solid rgba(252, 194, 27, 0.18) !important; border-radius: 7px !important;
  padding: 0.1rem 0.42rem !important; font-size: 0.86em !important; overflow-wrap: anywhere;
}}
.fx-icon {{
  font-family: 'Material Symbols Rounded' !important; font-weight: normal; font-style: normal;
  font-size: 1.25em; line-height: 1; letter-spacing: normal; text-transform: none; white-space: nowrap;
  display: inline-block; vertical-align: middle; -webkit-font-smoothing: antialiased;
  font-variation-settings: 'FILL' 0, 'wght' 450, 'GRAD' 0, 'opsz' 24;
}}
[data-testid="stMainBlockContainer"], .block-container {{ padding-top: 5.4rem !important; padding-bottom: 4rem !important; max-width: 1320px !important; }}

/* ── Header bar & top navigation (pill links) ── */
header[data-testid="stHeader"] {{
  background: rgba(0, 0, 0, 0.72) !important; backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}}
[data-testid="stTopNavLink"] {{
  border-radius: 999px !important; padding: 0.35rem 1rem !important; border: 1px solid transparent;
  transition: background .2s ease, border-color .2s ease, color .2s ease;
}}
[data-testid="stTopNavLink"] span {{ color: var(--text-2) !important; font-weight: 600 !important; }}
[data-testid="stTopNavLink"]:hover {{ background: rgba(255, 255, 255, 0.05) !important; border-color: rgba(255, 255, 255, 0.10); }}
[data-testid="stTopNavLink"][aria-current="page"] {{
  background: rgba(252, 194, 27, 0.12) !important; border-color: rgba(252, 194, 27, 0.40);
}}
[data-testid="stTopNavLink"][aria-current="page"] span {{ color: var(--accent) !important; }}

/* ── Sidebar ── */
[data-testid="stSidebar"] {{
  background: linear-gradient(180deg, #070708 0%, #000 100%) !important;
  border-right: 1px solid rgba(255, 255, 255, 0.06) !important;
}}
[data-testid="stSidebar"] .block-container {{ padding-top: 1.5rem !important; }}

/* ── Widget labels ── */
[data-testid="stWidgetLabel"] p {{ font-size: 0.93rem !important; font-weight: 600 !important; color: var(--text-2) !important; }}
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p {{ color: var(--muted) !important; font-size: 0.88rem !important; }}

/* ── Buttons: pill shape, gold gradient primary, glass secondary ── */
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button {{
  min-height: 2.95rem !important; border-radius: 999px !important; padding: 0 1.1rem !important; white-space: nowrap;
  font-size: 0.98rem !important; font-weight: 700 !important; letter-spacing: -0.01em;
  transition: transform .18s ease, box-shadow .25s ease, border-color .2s ease, background .2s ease, color .2s ease !important;
}}
.stButton > button p, .stDownloadButton > button p, [data-testid="stFormSubmitButton"] > button p {{
  font-size: 0.98rem !important; font-weight: 700 !important;
}}
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"],
[data-testid="stFormSubmitButton"] > button[kind="primaryFormSubmit"] {{
  background: var(--gradient) !important; border: 1px solid rgba(255, 224, 102, 0.55) !important; color: #0a0a0a !important;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.45), 0 8px 26px -10px rgba(252, 194, 27, 0.75) !important;
}}
.stButton > button[kind="primary"] *, .stDownloadButton > button[kind="primary"] *,
[data-testid="stFormSubmitButton"] > button[kind="primaryFormSubmit"] * {{ color: #0a0a0a !important; }}
.stButton > button[kind="primary"]:hover, .stDownloadButton > button[kind="primary"]:hover,
[data-testid="stFormSubmitButton"] > button[kind="primaryFormSubmit"]:hover {{
  transform: translateY(-2px); filter: brightness(1.05);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.5), 0 14px 34px -10px rgba(252, 194, 27, 0.9) !important;
}}
.stButton > button:not([kind="primary"]), .stDownloadButton > button:not([kind="primary"]),
[data-testid="stFormSubmitButton"] > button:not([kind="primaryFormSubmit"]) {{
  background: rgba(255, 255, 255, 0.04) !important; border: 1px solid rgba(255, 255, 255, 0.12) !important; color: var(--text) !important;
}}
.stButton > button:not([kind="primary"]):hover, .stDownloadButton > button:not([kind="primary"]):hover,
[data-testid="stFormSubmitButton"] > button:not([kind="primaryFormSubmit"]):hover {{
  border-color: var(--accent) !important; background: rgba(252, 194, 27, 0.07) !important; transform: translateY(-2px);
}}
.stButton > button:not([kind="primary"]):hover *, .stDownloadButton > button:not([kind="primary"]):hover * {{ color: var(--accent) !important; }}
.stButton > button:disabled {{ opacity: 0.4 !important; transform: none !important; }}

/* ── Segmented control ── */
[data-testid="stButtonGroup"] button {{
  min-height: 2.8rem !important; font-size: 0.96rem !important; padding: 0 1.15rem !important; border-radius: 999px !important;
}}
[data-testid="stButtonGroup"] button p {{ font-size: 0.96rem !important; font-weight: 600 !important; }}

/* ── Inputs ── */
div[data-baseweb="select"] > div, [data-testid="stTextInput"] input, [data-testid="stDateInput"] input {{
  background-color: #0e0e11 !important; border-color: #26262c !important;
  border-radius: 12px !important; font-size: 1rem !important; min-height: 2.9rem;
}}
[data-testid="stTextInput"] > div > div {{ border-radius: 12px !important; }}
[data-testid="stTextInput"] div:focus-within {{ border-color: var(--accent) !important; }}
div[data-baseweb="popover"] ul[role="listbox"] {{ background: #0e0e11 !important; border: 1px solid #26262c !important; border-radius: 12px !important; }}
li[role="option"] {{ font-size: 0.97rem !important; }}
li[role="option"]:hover, li[aria-selected="true"] {{ background: rgba(252, 194, 27, 0.12) !important; }}
[data-testid="stFileUploader"] section {{
  background: var(--glass) !important; border: 1.5px dashed #34343c !important; border-radius: var(--radius) !important;
  transition: border-color .2s ease, background .2s ease;
}}
[data-testid="stFileUploader"] section:hover {{ border-color: var(--accent) !important; background: rgba(252, 194, 27, 0.04) !important; }}

/* ── Tabs: pill track ── */
[data-testid="stTabs"] [role="tablist"] {{
  gap: 0.3rem; padding: 0.3rem; width: fit-content; max-width: 100%; overflow-x: auto;
  background: rgba(255, 255, 255, 0.035); border: 1px solid rgba(255, 255, 255, 0.08) !important; border-radius: 999px;
}}
[data-testid="stTabs"] [data-baseweb="tab-highlight"], [data-testid="stTabs"] [data-baseweb="tab-border"],
[data-testid="stTabs"] [role="tab"] > div:not([data-testid]) {{ display: none !important; }}
[data-testid="stTabs"] [role="tab"] {{
  padding: 0.55rem 1.15rem !important; border-radius: 999px !important; cursor: pointer; white-space: nowrap;
  transition: background .2s ease, box-shadow .2s ease;
}}
[data-testid="stTabs"] [role="tab"] p {{ font-size: 0.97rem !important; font-weight: 700 !important; color: var(--muted) !important; margin: 0 !important; }}
[data-testid="stTabs"] [role="tab"]:hover {{ background: rgba(255, 255, 255, 0.05); }}
[data-testid="stTabs"] [role="tab"]:hover p {{ color: var(--text) !important; }}
[data-testid="stTabs"] [role="tab"][aria-selected="true"] {{ background: var(--gradient) !important; box-shadow: 0 6px 18px -8px rgba(252, 194, 27, 0.8); }}
[data-testid="stTabs"] [role="tab"][aria-selected="true"] p {{ color: #0a0a0a !important; }}
[data-testid="stTabPanel"] {{ padding-top: 1rem; }}

/* ── Expanders, alerts, tables, containers ── */
[data-testid="stExpander"] details {{ background: var(--glass) !important; border: 1px solid var(--glass-border) !important; border-radius: var(--radius-sm) !important; }}
[data-testid="stExpander"] summary p {{ font-size: 0.98rem !important; font-weight: 700 !important; }}
[data-testid="stExpander"] summary:hover p, [data-testid="stExpander"] summary:hover span {{ color: var(--accent) !important; }}
[data-testid="stAlert"] {{ border-radius: var(--radius-sm) !important; }}
[data-testid="stAlert"] p {{ font-size: 0.97rem !important; }}
[data-testid="stDataFrame"] {{ border: 1px solid var(--glass-border) !important; border-radius: var(--radius-sm) !important; overflow: hidden; }}
[data-testid="stVerticalBlockBorderWrapper"], [data-testid="stForm"] {{
  border-color: var(--glass-border) !important; border-radius: var(--radius) !important;
}}
[data-testid="stVerticalBlockBorderWrapper"]:has(> div > [data-testid="stVerticalBlock"]) {{ background: var(--glass); }}
[data-testid="stCheckbox"] p {{ font-weight: 600 !important; }}
footer {{ visibility: hidden !important; }}

/* ── Components ── */
.fx-card {{
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.045), rgba(255, 255, 255, 0.015));
  border: 1px solid var(--glass-border); border-radius: var(--radius); padding: 1.3rem 1.45rem;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04), 0 20px 40px -24px rgba(0, 0, 0, 0.9);
}}
.fx-header {{
  position: relative; overflow: hidden;
  display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap;
  padding: 1.5rem 1.7rem; margin-bottom: 1.3rem; border-radius: 24px;
  background: linear-gradient(135deg, rgba(252, 194, 27, 0.10), rgba(255, 255, 255, 0.02) 50%);
  border: 1px solid rgba(252, 194, 27, 0.18);
}}
.fx-header::after {{
  content: ""; position: absolute; right: -80px; top: -120px; width: 320px; height: 320px; border-radius: 50%;
  background: radial-gradient(circle, rgba(252, 194, 27, 0.18), transparent 65%); pointer-events: none;
}}
.fx-brand {{ display: flex; align-items: center; gap: 1rem; position: relative; z-index: 1; }}
.fx-logo {{
  width: 54px; height: 54px; border-radius: 16px; display: grid; place-items: center; font-size: 1.7rem; color: #0a0a0a;
  background: var(--gradient); box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.5), 0 10px 30px -10px rgba(252, 194, 27, 0.8);
}}
.fx-logo .fx-icon {{ color: #0a0a0a; font-variation-settings: 'FILL' 1, 'wght' 500, 'GRAD' 0, 'opsz' 24; }}
.fx-eyebrow {{ font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.16em; color: var(--accent); }}
.fx-title {{ font-size: 1.9rem; font-weight: 800; letter-spacing: -0.04em; color: var(--text); line-height: 1.1; }}
.fx-title span {{ background: var(--gradient); -webkit-background-clip: text; background-clip: text; color: transparent; }}
.fx-sub {{ font-size: 0.97rem; color: var(--muted); margin-top: 0.2rem; }}
.fx-chips {{ display: flex; gap: 0.5rem; flex-wrap: wrap; position: relative; z-index: 1; }}

.fx-pill {{
  display: inline-flex; align-items: center; gap: 0.45rem; white-space: nowrap;
  padding: 0.34rem 0.85rem; border-radius: 999px; font-size: 0.84rem; font-weight: 700; letter-spacing: -0.005em;
}}
.fx-dot {{ width: 7px; height: 7px; border-radius: 50%; display: inline-block; animation: fx-pulse 2.2s infinite; }}
@keyframes fx-pulse {{ 0% {{ box-shadow: 0 0 0 0 rgba(255,255,255,0.35); }} 70% {{ box-shadow: 0 0 0 7px rgba(255,255,255,0); }} 100% {{ box-shadow: 0 0 0 0 rgba(255,255,255,0); }} }}

.fx-steps {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 0.6rem; margin-bottom: 1.8rem; }}
.fx-step {{
  display: flex; align-items: center; gap: 0.7rem; padding: 0.6rem 0.8rem 0.6rem 0.6rem; border-radius: 999px;
  background: var(--glass); border: 1px solid var(--glass-border); min-width: 0; transition: border-color .2s ease;
}}
.fx-step-num {{
  flex: 0 0 auto; width: 34px; height: 34px; border-radius: 50%; display: grid; place-items: center;
  font-weight: 800; font-size: 0.92rem; border: 1px solid var(--border-hi); color: var(--muted); background: #0e0e11;
}}
.fx-step-num .fx-icon {{ font-size: 1.15rem; font-variation-settings: 'FILL' 1, 'wght' 600, 'GRAD' 0, 'opsz' 20; }}
.fx-step-label {{ font-weight: 700; font-size: 0.96rem; color: var(--text-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; letter-spacing: -0.01em; }}
.fx-step-sub {{ font-size: 0.78rem; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.fx-step.done .fx-step-num {{ background: rgba(74, 222, 128, 0.12); border-color: rgba(74, 222, 128, 0.5); color: var(--good); }}
.fx-step.active {{ border-color: rgba(252, 194, 27, 0.5); box-shadow: 0 0 0 4px rgba(252, 194, 27, 0.06), 0 10px 30px -18px rgba(252, 194, 27, 0.8); }}
.fx-step.active .fx-step-num {{ background: var(--gradient); border-color: transparent; color: #0a0a0a; }}
.fx-step.active .fx-step-label {{ color: var(--text); }}
.fx-step.blocked {{ border-color: rgba(255, 95, 95, 0.45); }}
.fx-step.blocked .fx-step-num {{ background: rgba(255, 95, 95, 0.14); border-color: var(--critical); color: var(--critical); }}

.fx-section {{ display: flex; align-items: center; gap: 0.85rem; margin: 2.2rem 0 1rem 0; }}
.fx-section-icon {{
  width: 42px; height: 42px; border-radius: 13px; display: grid; place-items: center; font-size: 1.25rem; color: var(--accent);
  background: linear-gradient(135deg, rgba(252, 194, 27, 0.16), rgba(228, 140, 21, 0.06));
  border: 1px solid rgba(252, 194, 27, 0.30);
}}
.fx-section-title {{ font-size: 1.5rem; font-weight: 800; color: var(--text); letter-spacing: -0.035em; line-height: 1.15; }}
.fx-section-sub {{ font-size: 0.95rem; color: var(--muted); margin-top: 0.12rem; }}

.fx-kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.8rem; }}
.fx-kpi {{
  position: relative; overflow: hidden; min-width: 0;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.045), rgba(255, 255, 255, 0.012));
  border: 1px solid var(--glass-border); border-radius: 18px; padding: 1rem 1.15rem;
  transition: border-color .2s ease, transform .2s ease;
}}
.fx-kpi:hover {{ border-color: rgba(252, 194, 27, 0.35); }}
.fx-kpi::before {{
  content: ""; position: absolute; left: 1.15rem; right: 1.15rem; top: 0; height: 1px;
  background: linear-gradient(90deg, transparent, rgba(252, 194, 27, 0.45), transparent);
}}
.fx-kpi-label {{ font-size: 0.74rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); }}
.fx-kpi-value {{ font-size: 1.45rem; font-weight: 800; color: var(--text); margin-top: 0.3rem; overflow-wrap: anywhere; line-height: 1.2; letter-spacing: -0.03em; }}
.fx-kpi-value.mono {{ font-family: var(--mono) !important; font-size: 0.96rem; word-break: break-all; letter-spacing: 0; font-weight: 600; color: var(--accent-soft); }}
.fx-kpi-value .fx-icon {{ font-size: 1.15em; margin-right: 0.15rem; vertical-align: -0.2em; font-variation-settings: 'FILL' 1, 'wght' 500, 'GRAD' 0, 'opsz' 24; }}
.fx-kpi-value.small {{ font-size: 1.05rem; overflow-wrap: anywhere; letter-spacing: -0.015em; }}
.fx-kpi.wide {{ grid-column: span 2; }}
.fx-verdict .fx-kpis {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
.fx-kpi-sub {{ font-size: 0.84rem; color: var(--muted); margin-top: 0.22rem; overflow-wrap: anywhere; }}

.fx-verdict {{ display: grid; grid-template-columns: 220px 1fr; gap: 1.4rem; align-items: center; }}
.fx-gauge {{ width: 192px; height: 192px; border-radius: 50%; display: grid; place-items: center; margin: 0 auto; }}
.fx-gauge-inner {{
  width: 154px; height: 154px; border-radius: 50%; background: radial-gradient(circle at 50% 30%, #121215, #050506);
  display: flex; flex-direction: column; align-items: center; justify-content: center; border: 1px solid var(--border);
}}
.fx-gauge-value {{ font-size: 2.35rem; font-weight: 800; letter-spacing: -0.05em; line-height: 1; }}
.fx-gauge-label {{ font-size: 0.76rem; color: var(--muted); margin-top: 0.4rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; }}
.fx-banner {{ display: flex; align-items: flex-start; gap: 0.9rem; padding: 1rem 1.2rem; border-radius: var(--radius-sm); margin-top: 0.9rem; }}
.fx-banner-icon {{ font-size: 1.5rem; line-height: 1; }}
.fx-banner-title {{ font-size: 1.08rem; font-weight: 800; letter-spacing: -0.02em; }}
.fx-banner-text {{ font-size: 0.96rem; color: var(--text-2); margin-top: 0.15rem; }}

.fx-hash {{ margin-top: 0.85rem; }}
.fx-hash-label {{ font-size: 0.74rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); }}
.fx-hash-value {{ font-family: var(--mono) !important; font-size: 0.93rem; color: var(--accent-soft); overflow-wrap: anywhere; margin-top: 0.15rem; }}

.fx-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 0.9rem; }}
.fx-driver {{ display: flex; flex-direction: column; gap: 0.45rem; height: 100%; box-sizing: border-box; }}
.fx-driver-title {{ font-size: 1.06rem; font-weight: 800; color: var(--text); letter-spacing: -0.02em; }}
.fx-driver-text {{ font-size: 0.95rem; color: var(--text-2); line-height: 1.5; }}
.fx-driver-meta {{ margin-top: auto; padding-top: 0.6rem; border-top: 1px solid var(--glass-border); font-size: 0.88rem; color: var(--muted); }}

.fx-action {{
  display: flex; align-items: center; gap: 0.85rem; padding: 0.8rem 1.1rem; border-radius: var(--radius-sm);
  background: var(--glass); border: 1px solid var(--glass-border); margin-bottom: 0.55rem; transition: border-color .2s ease;
}}
.fx-action:hover {{ border-color: rgba(252, 194, 27, 0.3); }}
.fx-action-num {{ flex: 0 0 auto; width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center; font-weight: 800; font-size: 0.88rem; }}
.fx-action-text {{ font-size: 0.99rem; color: var(--text); }}

.fx-empty {{ text-align: center; padding: 2.8rem 1.5rem; }}
.fx-empty-icon {{
  width: 66px; height: 66px; margin: 0 auto 0.9rem; border-radius: 20px; display: grid; place-items: center;
  font-size: 2rem; color: var(--accent);
  background: linear-gradient(135deg, rgba(252, 194, 27, 0.16), rgba(228, 140, 21, 0.04));
  border: 1px solid rgba(252, 194, 27, 0.28); box-shadow: 0 14px 36px -18px rgba(252, 194, 27, 0.7);
}}
.fx-empty-title {{ font-size: 1.25rem; font-weight: 800; color: var(--text); letter-spacing: -0.03em; }}
.fx-empty-text {{ font-size: 0.97rem; color: var(--muted); max-width: 560px; margin: 0.4rem auto 0; }}

.fx-side-brand {{ display: flex; align-items: center; gap: 0.75rem; }}
.fx-side-brand .fx-logo {{ width: 42px; height: 42px; border-radius: 13px; font-size: 1.3rem; }}
.fx-side-label {{ font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.14em; color: var(--muted); margin: 1.4rem 0 0.55rem; }}
.fx-side-row {{
  display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.58rem 0.85rem;
  border-radius: 12px; background: var(--glass); border: 1px solid var(--glass-border); margin-bottom: 0.42rem;
  font-size: 0.9rem; color: var(--text-2);
}}
.fx-check {{ display: flex; align-items: center; gap: 0.6rem; font-size: 0.94rem; color: var(--text-2); padding: 0.3rem 0; }}

@media (max-width: 760px) {{
  .fx-kpi.wide {{ grid-column: auto; }}
  .fx-verdict .fx-kpis {{ grid-template-columns: 1fr; }}
  .fx-steps {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
  .fx-verdict {{ grid-template-columns: 1fr; }}
  .fx-title {{ font-size: 1.45rem; }}
  .fx-header {{ padding: 1.2rem; }}
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


def logo(size_class: str = "") -> str:
    return f'<div class="fx-logo {size_class}">{icon("memory")}</div>'


def page_header(title_main: str, title_accent: str, subtitle: str, chips: list, eyebrow: str = "Memory forensics lab"):
    render_html(f"""
    <div class="fx-header">
      <div class="fx-brand">
        {logo()}
        <div>
          <div class="fx-eyebrow">{esc(eyebrow)}</div>
          <div class="fx-title">{esc(title_main)} <span>{esc(title_accent)}</span></div>
          <div class="fx-sub">{esc(subtitle)}</div>
        </div>
      </div>
      <div class="fx-chips">{''.join(chips)}</div>
    </div>
    """)


def sidebar_brand():
    render_html(f"""
    <div class="fx-side-brand">
      {logo()}
      <div><div style="font-weight:800;font-size:1.18rem;letter-spacing:-0.03em;">MemTriage&nbsp;<span style="background:{GRADIENT};-webkit-background-clip:text;background-clip:text;color:transparent;">XAI</span></div>
      <div style="color:var(--muted);font-size:0.82rem;">Memory forensics lab</div></div>
    </div>
    """)


def stepper(steps: list):
    """steps: list of (label, sub, state) with state in done|active|pending|blocked."""
    items = []
    for i, (label, sub, state) in enumerate(steps, start=1):
        mark = icon("check") if state == "done" else icon("priority_high") if state == "blocked" else str(i)
        items.append(
            f'<div class="fx-step {state}"><div class="fx-step-num">{mark}</div>'
            f'<div style="min-width:0;"><div class="fx-step-label">{esc(label)}</div>'
            f'<div class="fx-step-sub">{esc(sub)}</div></div></div>'
        )
    render_html(f'<div class="fx-steps">{"".join(items)}</div>')


def section(title: str, subtitle: str = "", icon_name: str = "diamond"):
    sub = f'<div class="fx-section-sub">{esc(subtitle)}</div>' if subtitle else ""
    render_html(f"""
    <div class="fx-section">
      <div class="fx-section-icon">{_glyph(icon_name)}</div>
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
    return (f'<div class="fx-gauge" style="background: conic-gradient({fg} {deg}deg, {BORDER_HI} {deg}deg);'
            f'box-shadow: 0 0 40px -14px {fg};">'
            f'<div class="fx-gauge-inner"><div class="fx-gauge-value" style="color:{fg};">{pct:.1f}%</div>'
            f'<div class="fx-gauge-label">{esc(label)}</div></div></div>')


def banner(icon_name: str, title: str, text: str, tone: str) -> str:
    fg, bg, border = TONES[tone]
    return (f'<div class="fx-banner" style="background:{bg};border:1px solid {border};">'
            f'<div class="fx-banner-icon" style="color:{fg};">{_glyph(icon_name)}</div>'
            f'<div><div class="fx-banner-title" style="color:{fg};">{esc(title)}</div>'
            f'<div class="fx-banner-text">{text}</div></div></div>')


def empty_state(icon_name: str, title: str, text: str):
    render_html(f"""
    <div class="fx-card fx-empty">
      <div class="fx-empty-icon">{_glyph(icon_name)}</div>
      <div class="fx-empty-title">{esc(title)}</div>
      <div class="fx-empty-text">{text}</div>
    </div>
    """)
