"""
"Emerald Forensics" UI theme & components for the Streamlit dashboard.

Green-black canvas with an interactive emerald node-network background
(assets/background.js: parallax with the mouse, cursor links, data pulses,
click ripples), translucent glass cards, tight high-contrast typography
(Plus Jakarta Sans), pill-shaped buttons/tabs in emerald, and macOS-style
app icons: squircle tiles (superellipse mask) with a vertical gradient, glossy
sheen, drop shadow and a filled glyph. Monospace is kept for evidence data (hashes, metrics).
All HTML helpers flatten their markup so Markdown never turns indented lines
into code blocks.
"""

import os
import re
import math
import html as _html
from urllib.parse import quote
import streamlit as st


# ── Design tokens ─────────────────────────────────────────────────────────────
BG          = "#070d0b"
SURFACE     = "#0f1a16"
SURFACE_2   = "#14221d"
BORDER      = "#1c2b25"
BORDER_HI   = "#28403a"
TEXT        = "#e3f2ec"
TEXT_2      = "#a9c1b8"
MUTED       = "#7f978e"
ACCENT      = "#10b981"     # emerald
ACCENT_DEEP = "#059669"     # deep emerald (gradient end)
ACCENT_SOFT = "#6ee7b7"     # mint, for text on dark (hashes, code)
LIME        = "#a3e635"     # highlight
INK         = "#03140d"     # text/glyphs on emerald surfaces

# Status (always paired with an icon + label, never colour alone).
# "Good" is teal, not green, so a benign/verified state never reads as the brand accent.
GOOD     = "#2dd4bf"
WARNING  = "#f5b83d"
CRITICAL = "#f87171"

# Chart diverging pair (CVD-safe, >=3:1 on the dark surface)
TOWARD_MALWARE = "#e66767"
TOWARD_BENIGN  = "#3987e5"

TONES = {
    "good":     (GOOD,     "rgba(45, 212, 191, 0.09)",  "rgba(45, 212, 191, 0.32)"),
    "warning":  (WARNING,  "rgba(245, 184, 61, 0.10)",  "rgba(245, 184, 61, 0.36)"),
    "critical": (CRITICAL, "rgba(248, 113, 113, 0.10)", "rgba(248, 113, 113, 0.40)"),
    "accent":   (ACCENT,   "rgba(16, 185, 129, 0.10)",  "rgba(16, 185, 129, 0.40)"),
    "neutral":  (TEXT_2,   "rgba(255, 255, 255, 0.05)", "rgba(255, 255, 255, 0.14)"),
}

GRADIENT = f"linear-gradient(180deg, #a7f3d0 0%, #6ee7b7 30%, #34d399 60%, {ACCENT_DEEP} 100%)"


def _squircle_mask() -> str:
    """Apple-style continuous-corner tile: superellipse |x|^5 + |y|^5 = 1 as an SVG mask."""
    n, pts = 5, []
    for deg in range(0, 360, 3):
        t = math.radians(deg)
        c, si = math.cos(t), math.sin(t)
        pts.append(f"{50 + 50 * math.copysign(abs(c) ** (2 / n), c):.2f} "
                   f"{50 + 50 * math.copysign(abs(si) ** (2 / n), si):.2f}")
    svg = (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
           f"<path d='M{' L'.join(pts)}Z'/></svg>")
    return f'url("data:image/svg+xml,{quote(svg)}")'


SQUIRCLE = _squircle_mask()


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


def mac_icon(name: str, size: int = 42) -> str:
    """macOS-style app icon: emerald squircle tile with a filled glyph."""
    glyph = icon(name) if re.fullmatch(r"[a-z0-9_]+", name or "") else f'<span class="fx-emoji">{esc(name)}</span>'
    return f'<span class="fx-mac" style="--s:{size}px"><span class="fx-mac-tile">{glyph}</span></span>'


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
  --accent: {ACCENT}; --accent-deep: {ACCENT_DEEP}; --accent-soft: {ACCENT_SOFT}; --ink: {INK};
  --squircle: {SQUIRCLE};
  --good: {GOOD}; --warning: {WARNING}; --critical: {CRITICAL};
  --gradient: {GRADIENT};
  --glass: rgba(255, 255, 255, 0.025); --glass-border: rgba(255, 255, 255, 0.08);
  --radius: 20px; --radius-sm: 14px;
  --mono: 'JetBrains Mono', ui-monospace, monospace;
  --sans: 'Plus Jakarta Sans', 'Inter', system-ui, sans-serif;
}}

/* ── Canvas: interactive background (assets/background.js draws on #mt-bg) ── */
html, body {{ background: var(--bg) !important; }}
.stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"], [data-testid="stBottomBlockContainer"] {{
  background: transparent !important;
}}
.stApp {{ color: var(--text) !important; }}
#mt-bg {{ position: fixed; inset: 0; z-index: -1; pointer-events: none; }}
[data-testid="stElementContainer"]:has(#mt-bg-anchor) {{ display: none !important; }}
::selection {{ background: var(--accent); color: #000; }}
* {{ scrollbar-width: thin; scrollbar-color: #24392f transparent; }}
::-webkit-scrollbar {{ width: 9px; height: 9px; }}
::-webkit-scrollbar-thumb {{ background: #24392f; border-radius: 999px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--accent-deep); }}

/* ── Typography ── */
/* Spans are deliberately excluded: Streamlit renders Material icons as spans */
html, body, .stApp, p, li, label, div, input, textarea, button {{ font-family: var(--sans) !important; }}
.stApp p, .stApp li {{ font-size: 1rem; line-height: 1.6; }}
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5 {{ font-family: var(--sans) !important; letter-spacing: -0.03em !important; font-weight: 800 !important; }}
code, pre, .mono {{ font-family: var(--mono) !important; }}
:not(pre) > code {{
  background: rgba(16, 185, 129, 0.08) !important; color: var(--accent-soft) !important;
  border: 1px solid rgba(16, 185, 129, 0.18) !important; border-radius: 7px !important;
  padding: 0.1rem 0.42rem !important; font-size: 0.86em !important; overflow-wrap: anywhere;
}}
.fx-icon {{
  font-family: 'Material Symbols Rounded' !important; font-weight: normal; font-style: normal;
  font-size: 1.25em; line-height: 1; letter-spacing: normal; text-transform: none; white-space: nowrap;
  display: inline-block; vertical-align: middle; -webkit-font-smoothing: antialiased;
  font-variation-settings: 'FILL' 0, 'wght' 450, 'GRAD' 0, 'opsz' 24;
}}
/* ── macOS-style app icon tiles ── */
.fx-mac {{
  display: inline-grid; flex: 0 0 auto; vertical-align: middle;
  filter: drop-shadow(0 7px 12px rgba(0, 0, 0, 0.6)) drop-shadow(0 1px 1.5px rgba(0, 0, 0, 0.45));
  transition: transform .25s cubic-bezier(.2, .9, .3, 1.4);
}}
.fx-mac:hover {{ transform: translateY(-2px) scale(1.04); }}
.fx-mac-tile {{
  position: relative; width: var(--s, 42px); height: var(--s, 42px); display: grid; place-items: center;
  -webkit-mask: var(--squircle) center / 100% 100% no-repeat; mask: var(--squircle) center / 100% 100% no-repeat;
  background: var(--gradient); color: var(--ink);
  box-shadow: inset 0 calc(var(--s, 42px) * 0.04) 0 rgba(255, 255, 255, 0.9),
              inset 0 calc(var(--s, 42px) * -0.08) calc(var(--s, 42px) * 0.14) rgba(2, 60, 40, 0.28);
}}
.fx-mac-tile::before {{
  content: ""; position: absolute; inset: 0;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.6) 0%, rgba(255, 255, 255, 0.08) 46%, transparent 52%);
}}
.fx-mac-tile .fx-icon {{
  position: relative; font-size: calc(var(--s, 42px) * 0.56); color: var(--ink);
  font-variation-settings: 'FILL' 1, 'wght' 600, 'GRAD' 0, 'opsz' 40;
  text-shadow: 0 1px 0 rgba(255, 255, 255, 0.55);
}}
.fx-mac-tile .fx-emoji {{ position: relative; font-size: calc(var(--s, 42px) * 0.55); }}

/* Streamlit's own Material icons: filled, SF-Symbols-like */
[data-testid="stIconMaterial"] {{ font-variation-settings: 'FILL' 1, 'wght' 500, 'GRAD' 0, 'opsz' 24 !important; }}
/* Top-nav icons as small macOS tiles; the current page lights up */
[data-testid="stTopNavLink"] [data-testid="stIconMaterial"] {{
  display: inline-flex !important; align-items: center; justify-content: center;
  width: 26px !important; min-width: 26px !important; height: 26px !important; flex: 0 0 26px !important;
  font-size: 16px !important; line-height: 1 !important; overflow: hidden;
  border-radius: 8px; color: var(--accent) !important; margin-right: 0.2rem;
  background: linear-gradient(180deg, #2c4a40 0%, #13221d 100%);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.16), 0 2px 6px rgba(0, 0, 0, 0.55);
}}
[data-testid="stTopNavLink"][aria-current="page"] [data-testid="stIconMaterial"] {{
  background: var(--gradient); color: var(--ink) !important;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9), 0 3px 10px -2px rgba(16, 185, 129, 0.55);
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
  background: rgba(16, 185, 129, 0.12) !important; border-color: rgba(16, 185, 129, 0.40);
}}
[data-testid="stTopNavLink"][aria-current="page"] span {{ color: var(--accent) !important; }}

/* ── Sidebar ── */
[data-testid="stSidebar"] {{
  background: linear-gradient(180deg, rgba(7, 14, 12, 0.86) 0%, rgba(0, 0, 0, 0.9) 100%) !important;
  backdrop-filter: blur(18px) saturate(140%); -webkit-backdrop-filter: blur(18px) saturate(140%);
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
  background: var(--gradient) !important; border: 1px solid rgba(110, 231, 183, 0.55) !important; color: var(--ink) !important;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.45), 0 8px 26px -10px rgba(16, 185, 129, 0.75) !important;
}}
.stButton > button[kind="primary"] *, .stDownloadButton > button[kind="primary"] *,
[data-testid="stFormSubmitButton"] > button[kind="primaryFormSubmit"] * {{ color: var(--ink) !important; }}
.stButton > button[kind="primary"]:hover, .stDownloadButton > button[kind="primary"]:hover,
[data-testid="stFormSubmitButton"] > button[kind="primaryFormSubmit"]:hover {{
  transform: translateY(-2px); filter: brightness(1.05);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.5), 0 14px 34px -10px rgba(16, 185, 129, 0.9) !important;
}}
.stButton > button:not([kind="primary"]), .stDownloadButton > button:not([kind="primary"]),
[data-testid="stFormSubmitButton"] > button:not([kind="primaryFormSubmit"]) {{
  background: rgba(255, 255, 255, 0.04) !important; border: 1px solid rgba(255, 255, 255, 0.12) !important; color: var(--text) !important;
}}
.stButton > button:not([kind="primary"]):hover, .stDownloadButton > button:not([kind="primary"]):hover,
[data-testid="stFormSubmitButton"] > button:not([kind="primaryFormSubmit"]):hover {{
  border-color: var(--accent) !important; background: rgba(16, 185, 129, 0.07) !important; transform: translateY(-2px);
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
  background-color: #0b1512 !important; border-color: #1f332c !important;
  border-radius: 12px !important; font-size: 1rem !important; min-height: 2.9rem;
}}
[data-testid="stTextInput"] > div > div {{ border-radius: 12px !important; }}
[data-testid="stTextInput"] div:focus-within {{ border-color: var(--accent) !important; }}
div[data-baseweb="popover"] ul[role="listbox"] {{ background: #0b1512 !important; border: 1px solid #1f332c !important; border-radius: 12px !important; }}
li[role="option"] {{ font-size: 0.97rem !important; }}
li[role="option"]:hover, li[aria-selected="true"] {{ background: rgba(16, 185, 129, 0.12) !important; }}
[data-testid="stFileUploader"] section {{
  background: var(--glass) !important; border: 1.5px dashed #2c4a40 !important; border-radius: var(--radius) !important;
  transition: border-color .2s ease, background .2s ease;
}}
[data-testid="stFileUploader"] section:hover {{ border-color: var(--accent) !important; background: rgba(16, 185, 129, 0.04) !important; }}

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
[data-testid="stTabs"] [role="tab"][aria-selected="true"] {{ background: var(--gradient) !important; box-shadow: 0 6px 18px -8px rgba(16, 185, 129, 0.8); }}
[data-testid="stTabs"] [role="tab"][aria-selected="true"] p {{ color: var(--ink) !important; }}
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
[data-testid="stHeaderActionElements"] {{ display: none !important; }}

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
  background: linear-gradient(135deg, rgba(16, 185, 129, 0.10), rgba(255, 255, 255, 0.02) 50%);
  border: 1px solid rgba(16, 185, 129, 0.18);
}}
.fx-header::after {{
  content: ""; position: absolute; right: -80px; top: -120px; width: 320px; height: 320px; border-radius: 50%;
  background: radial-gradient(circle, rgba(16, 185, 129, 0.18), transparent 65%); pointer-events: none;
}}
.fx-brand {{ display: flex; align-items: center; gap: 1rem; position: relative; z-index: 1; }}
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
  font-weight: 800; font-size: 0.92rem; border: 1px solid var(--border-hi); color: var(--muted); background: #0b1512;
}}
.fx-step-num .fx-icon {{ font-size: 1.15rem; font-variation-settings: 'FILL' 1, 'wght' 600, 'GRAD' 0, 'opsz' 20; }}
.fx-step-label {{ font-weight: 700; font-size: 0.96rem; color: var(--text-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; letter-spacing: -0.01em; }}
.fx-step-sub {{ font-size: 0.78rem; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.fx-step.done .fx-step-num {{ background: rgba(74, 222, 128, 0.12); border-color: rgba(74, 222, 128, 0.5); color: var(--good); }}
.fx-step.active {{ border-color: rgba(16, 185, 129, 0.5); box-shadow: 0 0 0 4px rgba(16, 185, 129, 0.06), 0 10px 30px -18px rgba(16, 185, 129, 0.8); }}
.fx-step.active .fx-step-num {{ background: var(--gradient); border-color: transparent; color: var(--ink); }}
.fx-step.active .fx-step-label {{ color: var(--text); }}
.fx-step.blocked {{ border-color: rgba(255, 95, 95, 0.45); }}
.fx-step.blocked .fx-step-num {{ background: rgba(255, 95, 95, 0.14); border-color: var(--critical); color: var(--critical); }}

.fx-section {{ display: flex; align-items: center; gap: 0.85rem; margin: 2.2rem 0 1rem 0; }}
.fx-section-title {{ font-size: 1.5rem; font-weight: 800; color: var(--text); letter-spacing: -0.035em; line-height: 1.15; }}
.fx-section-sub {{ font-size: 0.95rem; color: var(--muted); margin-top: 0.12rem; }}

.fx-kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.8rem; }}
.fx-kpi {{
  position: relative; overflow: hidden; min-width: 0;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.045), rgba(255, 255, 255, 0.012));
  border: 1px solid var(--glass-border); border-radius: 18px; padding: 1rem 1.15rem;
  transition: border-color .2s ease, transform .2s ease;
}}
.fx-kpi:hover {{ border-color: rgba(16, 185, 129, 0.35); }}
.fx-kpi::before {{
  content: ""; position: absolute; left: 1.15rem; right: 1.15rem; top: 0; height: 1px;
  background: linear-gradient(90deg, transparent, rgba(16, 185, 129, 0.45), transparent);
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
  width: 154px; height: 154px; border-radius: 50%; background: radial-gradient(circle at 50% 30%, #11201b, #050a08);
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
.fx-action:hover {{ border-color: rgba(16, 185, 129, 0.3); }}
.fx-action-num {{ flex: 0 0 auto; width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center; font-weight: 800; font-size: 0.88rem; }}
.fx-action-text {{ font-size: 0.99rem; color: var(--text); }}

.fx-empty {{ text-align: center; padding: 2.8rem 1.5rem; }}
.fx-empty-icon {{ display: flex; justify-content: center; margin-bottom: 1rem; }}
.fx-empty-title {{ font-size: 1.25rem; font-weight: 800; color: var(--text); letter-spacing: -0.03em; }}
.fx-empty-text {{ font-size: 0.97rem; color: var(--muted); max-width: 560px; margin: 0.4rem auto 0; }}

.fx-side-brand {{ display: flex; align-items: center; gap: 0.75rem; }}
.fx-side-label {{ font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.14em; color: var(--muted); margin: 1.4rem 0 0.55rem; }}
.fx-side-row {{
  display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; padding: 0.58rem 0.85rem;
  border-radius: 12px; background: var(--glass); border: 1px solid var(--glass-border); margin-bottom: 0.42rem;
  font-size: 0.9rem; color: var(--text-2);
}}
.fx-prov-head {{ display: flex; align-items: center; gap: 0.75rem; margin: 0.3rem 0 0.85rem; }}
.fx-prov-title {{ font-weight: 800; font-size: 1.12rem; letter-spacing: -0.025em; color: var(--text); }}
.fx-prov-sub {{ color: var(--muted); font-size: 0.85rem; }}
.fx-prov-strip {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.7rem; margin: -0.2rem 0 0.9rem; }}
.fx-prov-strip > div {{
  display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; padding: 0.7rem 1rem; border-radius: 14px;
  background: var(--glass); border: 1px solid var(--glass-border); min-width: 0;
}}
.fx-prov-strip .fx-icon {{ color: var(--accent); font-variation-settings: 'FILL' 1, 'wght' 500, 'GRAD' 0, 'opsz' 24; }}
.fx-prov-strip span {{ font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.12em; color: var(--muted); }}
.fx-prov-strip b {{ color: var(--text); font-weight: 700; overflow-wrap: anywhere; }}
.fx-prov-strip em {{ font-style: normal; color: var(--muted); font-size: 0.86rem; }}
.fx-guide {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.9rem; margin: 0.4rem 0 1rem; }}
.fx-guide-card {{
  position: relative; padding: 1.2rem 1.2rem 1.1rem; border-radius: 20px; min-width: 0;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.045), rgba(255, 255, 255, 0.012));
  border: 1px solid var(--glass-border); transition: transform .2s ease, border-color .2s ease;
}}
.fx-guide-card:hover {{ transform: translateY(-3px); border-color: rgba(16, 185, 129, 0.45); }}
.fx-guide-num {{ position: absolute; top: 1rem; right: 1.1rem; font-weight: 800; font-size: 0.78rem; color: var(--muted); letter-spacing: 0.12em; }}
.fx-guide-title {{ font-weight: 800; font-size: 1.05rem; margin-top: 0.85rem; letter-spacing: -0.02em; color: var(--text); }}
.fx-guide-text {{ color: var(--text-2); font-size: 0.93rem; margin-top: 0.25rem; line-height: 1.5; }}
/* ── Floating assistant ── */
.st-key-assistant_fab {{ position: fixed !important; right: 26px; bottom: 24px; z-index: 999990; width: auto !important; }}
.st-key-assistant_fab [data-testid="stPopover"] > div > button, .st-key-assistant_fab button {{
  min-height: 3.2rem !important; padding: 0 1.3rem !important; border-radius: 999px !important;
  background: var(--gradient) !important; color: var(--ink) !important; border: 1px solid rgba(167, 243, 208, 0.6) !important;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.5), 0 14px 34px -10px rgba(16, 185, 129, 0.85) !important;
  animation: fx-asst-pulse 3.2s ease-in-out infinite;
}}
.st-key-assistant_fab button * {{ color: var(--ink) !important; font-weight: 800 !important; }}
@keyframes fx-asst-pulse {{
  0%, 100% {{ box-shadow: inset 0 1px 0 rgba(255,255,255,.5), 0 14px 34px -10px rgba(16,185,129,.85), 0 0 0 0 rgba(16,185,129,.45); }}
  50%      {{ box-shadow: inset 0 1px 0 rgba(255,255,255,.5), 0 14px 34px -10px rgba(16,185,129,.85), 0 0 0 10px rgba(16,185,129,0); }}
}}
[data-testid="stPopoverBody"]:has(.fx-asst-head) {{
  width: min(440px, calc(100vw - 32px)) !important; max-width: none !important;
  background: rgba(11, 21, 18, 0.96) !important; backdrop-filter: blur(16px);
  border: 1px solid rgba(16, 185, 129, 0.35) !important; border-radius: 20px !important;
}}
[data-testid="stPopoverBody"]:has(.fx-asst-head) button {{ animation: none; }}
[data-testid="stPopoverBody"]:has(.fx-asst-head) [data-testid="stButtonGroup"] button {{
  min-height: 1.9rem !important; padding: 0 0.75rem !important;
}}
[data-testid="stPopoverBody"]:has(.fx-asst-head) [data-testid="stButtonGroup"] button p {{ font-size: 0.82rem !important; }}
[data-testid="stPopoverBody"]:has(.fx-asst-head) [data-testid="stButtonGroup"] {{ gap: 0.35rem !important; }}
.fx-asst-head {{ display: flex; align-items: center; gap: 0.7rem; padding-bottom: 0.6rem; border-bottom: 1px solid var(--glass-border); }}
.fx-asst-title {{ font-weight: 800; font-size: 1.05rem; letter-spacing: -0.02em; color: var(--text); }}
.fx-asst-sub {{ color: var(--muted); font-size: 0.8rem; }}
[data-testid="stPopoverBody"] [data-testid="stChatMessage"] {{ background: var(--glass); border-radius: 14px; padding: 0.6rem 0.8rem; }}
[data-testid="stPopoverBody"] [data-testid="stChatMessage"] p, [data-testid="stPopoverBody"] [data-testid="stChatMessage"] li {{ font-size: 0.93rem; }}
@media (prefers-reduced-motion: reduce) {{ .st-key-assistant_fab button {{ animation: none !important; }} }}
.fx-check {{ display: flex; align-items: center; gap: 0.6rem; font-size: 0.94rem; color: var(--text-2); padding: 0.3rem 0; }}

@media (max-width: 760px) {{
  .fx-kpi.wide {{ grid-column: auto; }}
  .fx-verdict .fx-kpis {{ grid-template-columns: 1fr; }}
  .fx-steps {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
  .fx-verdict {{ grid-template-columns: 1fr; }}
  .fx-title {{ font-size: 1.45rem; }}
  .fx-header {{ padding: 1.2rem; }}
  .fx-prov-strip {{ grid-template-columns: 1fr; }}
}}
</style>
        """,
        unsafe_allow_html=True,
    )


_BG_JS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "background.js")


def inject_background():
    """Interactive canvas background (runs once per browser tab; guarded inside the script)."""
    with open(_BG_JS, "r", encoding="utf-8") as f:
        script = f.read()
    st.html(f'<span id="mt-bg-anchor"></span><script>{script}</script>', unsafe_allow_javascript=True)


# ── Components ────────────────────────────────────────────────────────────────
def pill(text: str, tone: str = "accent", dot: bool = True) -> str:
    fg, bg, border = TONES.get(tone, TONES["neutral"])
    d = f'<span class="fx-dot" style="background:{fg};"></span>' if dot else ""
    return (f'<span class="fx-pill" style="color:{fg};background:{bg};border:1px solid {border};">'
            f'{d}{esc(text)}</span>')


def logo(size: int = 54) -> str:
    return mac_icon("memory", size)


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
      {logo(42)}
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
      {mac_icon(icon_name, 42)}
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


def guide_steps(items: list):
    """Numbered step cards: items = [(icon_name, title, text), ...]."""
    cards = "".join(
        f'<div class="fx-guide-card"><div class="fx-guide-num">STEP {i}</div>{mac_icon(name, 44)}'
        f'<div class="fx-guide-title">{esc(title)}</div><div class="fx-guide-text">{esc(text)}</div></div>'
        for i, (name, title, text) in enumerate(items, start=1))
    render_html(f'<div class="fx-guide">{cards}</div>')


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
      <div class="fx-empty-icon">{mac_icon(icon_name, 68)}</div>
      <div class="fx-empty-title">{esc(title)}</div>
      <div class="fx-empty-text">{text}</div>
    </div>
    """)
