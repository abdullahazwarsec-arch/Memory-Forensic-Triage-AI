"""
Render the project diagrams to PNG.

Each *.html template in this folder is rendered with headless Chromium.
`{{logo:name}}` placeholders are replaced with the matching icons/<name>.svg
(Simple Icons, CC0) coloured in the brand colour given in LOGO_COLOURS.

Usage:  python docs/diagrams/build.py [path/to/chromium]
Output: docs/<template name>.png
"""
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE.parent

LOGO_COLOURS = {
    "python": "#3776AB",
    "streamlit": "#FF4B4B",
    "scikitlearn": "#F7931E",
    "pandas": "#150458",
    "numpy": "#013243",
    "windows": "#0078D6",
}

# template name -> (width, height) in CSS pixels
TEMPLATES = {
    "how_it_works": (1920, 1060),
    "chain_of_custody": (1920, 800),
}

DEFAULT_CHROME = "/opt/pw-browsers/chromium_headless_shell-1194/chrome-linux/headless_shell"


def inline_logos(html: str) -> str:
    def repl(m):
        name = m.group(1)
        svg = (HERE / "icons" / f"{name}.svg").read_text()
        svg = re.sub(r"<title>.*?</title>", "", svg)
        return svg.replace("<svg ", f'<svg class="logo" fill="{LOGO_COLOURS[name]}" ', 1)
    return re.sub(r"\{\{logo:(\w+)\}\}", repl, html)


def main():
    chrome = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CHROME
    build_dir = HERE / "_build"
    build_dir.mkdir(exist_ok=True)
    for name, (w, h) in TEMPLATES.items():
        page = build_dir / f"{name}.html"
        page.write_text(inline_logos((HERE / f"{name}.html").read_text()))
        out = OUT_DIR / f"{name}.png"
        subprocess.run([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
                        f"--window-size={w},{h}", "--force-device-scale-factor=1",
                        f"--screenshot={out}", str(page)],
                       check=True, capture_output=True)
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
