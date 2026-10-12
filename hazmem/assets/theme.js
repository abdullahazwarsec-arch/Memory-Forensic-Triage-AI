/*
 * HazMem light / dark mode.
 *
 * 1. Detection (runs once per tab): reads the text colour Streamlit gives the
 *    page and sets the data-theme attribute ("light" | "dark") on the html element, so the HazMem stylesheet and
 *    the background follow whichever theme is active - however it was chosen.
 * 2. Switching: window.__HAZMEM_THEME_REQUEST ("light" | "dark" | "auto") is
 *    applied through Streamlit's own theme switcher, so Streamlit's widgets,
 *    tables and menus change too, instantly and without a reload (the choice is
 *    remembered by Streamlit in the browser). If that switcher cannot be found
 *    (e.g. after a Streamlit upgrade), the request is ignored and the dashboard
 *    keeps following the system setting.
 */
(() => {
  const html = document.documentElement;

  if (!window.__hazmemThemeWatch) {
    window.__hazmemThemeWatch = true;
    const detect = () => {
      const rgb = (getComputedStyle(document.body).color.match(/\d+/g) || [227, 242, 236]).map(Number);
      const luminance = (0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]) / 255;
      const mode = luminance > 0.5 ? "dark" : "light";        // light text => dark theme
      if (html.dataset.theme !== mode) html.dataset.theme = mode;
    };
    detect();
    setInterval(detect, 400);
  }

  const wanted = window.__HAZMEM_THEME_REQUEST;
  if (!wanted || window.__hazmemThemeApplied === wanted) return;

  const findSwitcher = () => {
    const start = document.querySelector('[data-testid="stApp"]') || document.getElementById("root");
    for (let el = start; el; el = el.firstElementChild) {
      const key = Object.keys(el).find((k) => k.startsWith("__reactFiber"));
      if (!key) continue;
      for (let f = el[key]; f; f = f.return) {
        const v = f.memoizedProps && f.memoizedProps.value;
        if (v && typeof v.setTheme === "function" && Array.isArray(v.availableThemes)) return v;
      }
    }
    return null;
  };

  const apply = (tries) => {
    const ctx = findSwitcher();
    if (!ctx) { if (tries > 0) setTimeout(() => apply(tries - 1), 250); return; }
    const pattern = { light: /light/i, dark: /dark/i, auto: /auto|system/i }[wanted];
    const theme = ctx.availableThemes.find((t) => pattern && pattern.test(t.name));
    if (theme && (!ctx.activeTheme || ctx.activeTheme.name !== theme.name)) ctx.setTheme(theme);
    window.__hazmemThemeApplied = wanted;
  };
  apply(20);
})();
