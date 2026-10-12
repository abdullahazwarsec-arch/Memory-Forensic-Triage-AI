/*
 * HazMem interactive background - "toxic atmosphere", matching the logo.
 * Glowing spores on three depth layers rise and drift like gas; they shift
 * with the mouse (parallax), move away from the cursor and link to it.
 * Green gas clouds drift behind them, a large faint biohazard symbol (the
 * logo's eyes) slowly turns, and a click releases a burst of spores.
 * Pauses in background tabs; draws one still frame when the user prefers
 * reduced motion. Colours follow the light/dark theme and match the logo.
 */
(() => {
  if (window.__mtBackground) return;          // Streamlit reruns re-insert this script
  window.__mtBackground = true;

  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const canvas = document.createElement("canvas");
  canvas.id = "mt-bg";
  canvas.setAttribute("aria-hidden", "true");
  document.body.prepend(canvas);
  const ctx = canvas.getContext("2d");

  // Colours per theme (html[data-theme] is set by theme.js); k scales the glow strength.
  const PALETTES = {
    dark:  { SPORE: "74, 222, 128", LINK: "16, 185, 129", HOT: "163, 230, 53", GAS: "16, 185, 129", GAS2: "5, 150, 105", k: 1, mark: 0.045 },
    light: { SPORE: "5, 150, 105",  LINK: "4, 120, 87",   HOT: "77, 124, 15",  GAS: "16, 185, 129", GAS2: "45, 212, 191", k: 0.55, mark: 0.07 },
  };
  let SPORE, LINK, HOT, GAS, GAS2, K, MARK;
  const usePalette = () => {
    const pal = PALETTES[document.documentElement.dataset.theme === "light" ? "light" : "dark"];
    ({ SPORE, LINK, HOT, GAS, GAS2, k: K, mark: MARK } = pal);
  };
  usePalette();
  const LINK_DIST = 115, MOUSE_DIST = 170, REPEL_DIST = 150;

  let W = 0, H = 0, spores = [], bursts = [], ripples = [], running = true, symbol = null;
  const mouse = { x: -1e4, y: -1e4, tx: -1e4, ty: -1e4, px: 0.5, py: 0.5, tpx: 0.5, tpy: 0.5, on: false };

  function makeSpore(y) {
    const z = [0.4, 0.7, 1][Math.floor(Math.random() * 3)];        // three depth layers
    return {
      x: Math.random() * W, y: y ?? Math.random() * H, z,
      vx: (Math.random() - 0.5) * 0.12 * z, vy: -(0.08 + Math.random() * 0.22) * z,   // gas rises
      r: (1 + Math.random() * 1.6) * (0.6 + z * 0.6), ph: Math.random() * Math.PI * 2,
      wob: 0.15 + Math.random() * 0.35,
    };
  }

  // Biohazard symbol pre-rendered once per size (outer circles minus cut circles, plus the ring)
  function renderSymbol(size) {
    const off = document.createElement("canvas");
    off.width = off.height = size;
    const c = off.getContext("2d"), u = size / 2.4, cx = size / 2, cy = size / 2;
    const at = (d, a) => [cx + d * u * Math.cos(a * Math.PI / 180), cy + d * u * Math.sin(a * Math.PI / 180)];
    c.fillStyle = "rgb(74, 222, 128)";
    for (const a of [-90, 30, 150]) { const [x, y] = at(0.48, a); c.beginPath(); c.arc(x, y, 0.42 * u, 0, 7); c.fill(); }
    c.strokeStyle = "rgb(74, 222, 128)"; c.lineWidth = 0.09 * u;
    c.beginPath(); c.arc(cx, cy, 0.31 * u, 0, 7); c.stroke();
    c.globalCompositeOperation = "destination-out";
    for (const a of [-90, 30, 150]) { const [x, y] = at(0.64, a); c.beginPath(); c.arc(x, y, 0.30 * u, 0, 7); c.fill(); }
    c.beginPath(); c.arc(cx, cy, 0.12 * u, 0, 7); c.fill();
    return off;
  }

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    canvas.style.width = W + "px"; canvas.style.height = H + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const count = Math.max(40, Math.min(115, Math.round((W * H) / 14000)));
    spores = Array.from({ length: count }, () => makeSpore());
    symbol = renderSymbol(Math.round(Math.min(W, H) * 0.62));
    if (reduce) draw(0);
  }

  window.addEventListener("resize", resize, { passive: true });
  if (!reduce) {
    window.addEventListener("pointermove", (e) => {
      mouse.tx = e.clientX; mouse.ty = e.clientY; mouse.tpx = e.clientX / W; mouse.tpy = e.clientY / H;
      if (!mouse.on) { mouse.x = mouse.tx; mouse.y = mouse.ty; mouse.on = true; }
    }, { passive: true });
    document.addEventListener("pointerleave", () => { mouse.on = false; }, { passive: true });
    window.addEventListener("blur", () => { mouse.on = false; });
    window.addEventListener("pointerdown", (e) => {
      const t0 = performance.now();
      ripples.push({ x: e.clientX, y: e.clientY, t0 });
      for (let i = 0; i < 14; i++) {
        const a = (i / 14) * Math.PI * 2 + Math.random() * 0.4, sp = 1.2 + Math.random() * 2.2;
        bursts.push({ x: e.clientX, y: e.clientY, vx: Math.cos(a) * sp, vy: Math.sin(a) * sp, t0, r: 1 + Math.random() * 1.6 });
      }
    }, { passive: true });
    document.addEventListener("visibilitychange", () => {
      running = !document.hidden;
      if (running) requestAnimationFrame(loop);
    });
  }

  function glow(x, y, radius, rgb, alpha) {
    const g = ctx.createRadialGradient(x, y, 0, x, y, radius);
    g.addColorStop(0, `rgba(${rgb}, ${alpha})`);
    g.addColorStop(1, `rgba(${rgb}, 0)`);
    ctx.fillStyle = g;
    ctx.fillRect(x - radius, y - radius, radius * 2, radius * 2);
  }

  function draw(t) {
    usePalette();
    ctx.clearRect(0, 0, W, H);

    // eased pointer + parallax offsets (far layers move less)
    mouse.x += (mouse.tx - mouse.x) * 0.14; mouse.y += (mouse.ty - mouse.y) * 0.14;
    mouse.px += (mouse.tpx - mouse.px) * 0.05; mouse.py += (mouse.tpy - mouse.py) * 0.05;
    const ox = (mouse.px - 0.5) * -60, oy = (mouse.py - 0.5) * -44;
    const big = Math.max(W, H);

    // drifting gas clouds (shift against the mouse for depth)
    glow(W * (0.22 + 0.07 * Math.sin(t / 9000)) + ox * 1.6, H * (0.25 + 0.06 * Math.cos(t / 11000)) + oy * 1.6,
         big * 0.42, GAS, 0.11 * K);
    glow(W * (0.78 + 0.06 * Math.cos(t / 12000)) + ox * 1.2, H * (0.78 + 0.05 * Math.sin(t / 8000)) + oy * 1.2,
         big * 0.38, GAS2, 0.08 * K);
    glow(W * (0.55 + 0.1 * Math.sin(t / 15000)) + ox * 2, H * (0.5 + 0.08 * Math.cos(t / 13000)) + oy * 2,
         big * 0.3, HOT, 0.035 * K);

    // faint biohazard symbol, slowly turning, with parallax
    if (symbol) {
      ctx.save();
      ctx.globalAlpha = MARK;
      ctx.translate(W * 0.62 + ox * 0.8, H * 0.52 + oy * 0.8);
      ctx.rotate(t / 60000);
      ctx.drawImage(symbol, -symbol.width / 2, -symbol.height / 2);
      ctx.restore();
    }

    if (mouse.on) glow(mouse.x, mouse.y, 320, GAS, 0.16 * K);

    // spores: rise, wobble, avoid the cursor
    for (const s of spores) {
      s.x += s.vx + Math.sin(t / 1400 + s.ph) * s.wob * 0.25;
      s.y += s.vy;
      if (s.y < -40) Object.assign(s, makeSpore(H + 30));
      if (s.x < -40) s.x = W + 40; else if (s.x > W + 40) s.x = -40;
      s.sx = s.x + ox * s.z; s.sy = s.y + oy * s.z;
      if (mouse.on) {
        const dx = s.sx - mouse.x, dy = s.sy - mouse.y, d = Math.hypot(dx, dy);
        if (d < REPEL_DIST && d > 0.1) {
          const f = (1 - d / REPEL_DIST) * 2 * s.z;
          s.x += (dx / d) * f; s.y += (dy / d) * f;
        }
        s.md = d;
      } else s.md = 1e9;
    }

    // faint links between nearby spores (brighter near the cursor)
    ctx.lineWidth = 1;
    for (let i = 0; i < spores.length; i++) {
      const a = spores[i];
      for (let j = i + 1; j < spores.length; j++) {
        const b = spores[j], dx = a.sx - b.sx, dy = a.sy - b.sy;
        if (Math.abs(dx) > LINK_DIST || Math.abs(dy) > LINK_DIST) continue;
        const d = Math.hypot(dx, dy);
        if (d > LINK_DIST) continue;
        const hot = Math.min(a.md, b.md) < MOUSE_DIST;
        ctx.strokeStyle = `rgba(${hot ? HOT : LINK}, ${(1 - d / LINK_DIST) * (hot ? 0.5 : 0.14) * Math.min(a.z, b.z)})`;
        ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
      }
    }
    if (mouse.on) {
      for (const s of spores) {
        if (s.md < MOUSE_DIST) {
          ctx.strokeStyle = `rgba(${HOT}, ${(1 - s.md / MOUSE_DIST) * 0.45})`;
          ctx.beginPath(); ctx.moveTo(mouse.x, mouse.y); ctx.lineTo(s.sx, s.sy); ctx.stroke();
        }
      }
    }

    // glowing spores
    for (const s of spores) {
      const near = s.md < MOUSE_DIST ? 1 - s.md / MOUSE_DIST : 0;
      const alpha = (0.35 + 0.3 * Math.sin(t / 900 + s.ph)) * s.z + near * 0.5;
      const rgb = near > 0 ? HOT : SPORE, r = s.r + near * 1.6;
      ctx.fillStyle = `rgba(${rgb}, ${Math.min(alpha, 1) * 0.18})`;
      ctx.beginPath(); ctx.arc(s.sx, s.sy, r * 3.2, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = `rgba(${rgb}, ${Math.min(alpha, 1)})`;
      ctx.beginPath(); ctx.arc(s.sx, s.sy, r, 0, Math.PI * 2); ctx.fill();
    }

    if (reduce) return;

    // click: toxic burst + ring
    bursts = bursts.filter((b) => {
      const age = t - b.t0;
      if (age > 1400) return false;
      b.x += b.vx; b.y += b.vy; b.vx *= 0.96; b.vy = b.vy * 0.96 - 0.03;
      const k = 1 - age / 1400;
      ctx.fillStyle = `rgba(${HOT}, ${k * 0.9})`;
      ctx.beginPath(); ctx.arc(b.x, b.y, b.r, 0, Math.PI * 2); ctx.fill();
      return true;
    });
    ripples = ripples.filter((r) => {
      const age = t - r.t0;
      if (age > 1200) return false;
      const k = age / 1200;
      ctx.strokeStyle = `rgba(${SPORE}, ${(1 - k) * 0.55})`;
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(r.x, r.y, 10 + k * 160, 0, Math.PI * 2); ctx.stroke();
      return true;
    });
  }

  function loop(t) {
    if (!running) return;
    draw(t);
    requestAnimationFrame(loop);
  }

  resize();
  if (!reduce) requestAnimationFrame(loop);
})();
