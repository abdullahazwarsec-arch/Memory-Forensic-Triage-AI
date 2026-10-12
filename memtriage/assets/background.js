/*
 * MemTriage interactive background - "emerald memory network".
 * A canvas behind the dashboard: drifting nodes on three depth layers that
 * shift with the mouse (parallax), move away from the cursor, link to it,
 * carry small data pulses along their links, and ripple on click. A soft
 * spotlight follows the pointer. Pauses in background tabs; draws a single
 * still frame when the user prefers reduced motion. Colours match ui_theme.py.
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

  const NODE = "52, 211, 153", LINK = "16, 185, 129", HOT = "163, 230, 53", GLOW = "16, 185, 129";
  const LINK_DIST = 125, MOUSE_DIST = 170, REPEL_DIST = 150;

  let W = 0, H = 0, nodes = [], links = [], packets = [], ripples = [], running = true, lastPacket = 0;
  const mouse = { x: -1e4, y: -1e4, tx: -1e4, ty: -1e4, px: 0.5, py: 0.5, tpx: 0.5, tpy: 0.5, on: false };

  function seed() {
    const count = Math.max(36, Math.min(110, Math.round((W * H) / 15000)));
    nodes = Array.from({ length: count }, () => {
      const z = [0.4, 0.7, 1][Math.floor(Math.random() * 3)];   // three depth layers
      return {
        x: Math.random() * W, y: Math.random() * H, z,
        vx: (Math.random() - 0.5) * 0.22 * z, vy: (Math.random() - 0.5) * 0.22 * z,
        r: (0.9 + Math.random() * 1.4) * (0.6 + z * 0.6), ph: Math.random() * Math.PI * 2,
      };
    });
  }

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    canvas.style.width = W + "px"; canvas.style.height = H + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    seed();
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
    window.addEventListener("pointerdown", (e) => ripples.push({ x: e.clientX, y: e.clientY, t0: performance.now() }),
                            { passive: true });
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
    ctx.clearRect(0, 0, W, H);

    // ambient aurora: two slow glows drifting on their own
    glow(W * (0.25 + 0.08 * Math.sin(t / 9000)), H * (0.2 + 0.06 * Math.cos(t / 11000)), Math.max(W, H) * 0.45,
         GLOW, 0.10);
    glow(W * (0.8 + 0.06 * Math.cos(t / 12000)), H * (0.85 + 0.05 * Math.sin(t / 8000)), Math.max(W, H) * 0.4,
         "5, 150, 105", 0.07);

    // eased pointer + parallax offset (deeper layers move less)
    mouse.x += (mouse.tx - mouse.x) * 0.14; mouse.y += (mouse.ty - mouse.y) * 0.14;
    mouse.px += (mouse.tpx - mouse.px) * 0.05; mouse.py += (mouse.tpy - mouse.py) * 0.05;
    const ox = (mouse.px - 0.5) * -60, oy = (mouse.py - 0.5) * -44;
    if (mouse.on) glow(mouse.x, mouse.y, 340, GLOW, 0.16);

    // move nodes, keep them away from the cursor, compute screen positions
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy;
      if (n.x < -50) n.x = W + 50; else if (n.x > W + 50) n.x = -50;
      if (n.y < -50) n.y = H + 50; else if (n.y > H + 50) n.y = -50;
      n.sx = n.x + ox * n.z; n.sy = n.y + oy * n.z;
      if (mouse.on) {
        const dx = n.sx - mouse.x, dy = n.sy - mouse.y, d = Math.hypot(dx, dy);
        if (d < REPEL_DIST && d > 0.1) {
          const f = (1 - d / REPEL_DIST) * 1.8 * n.z;
          n.x += (dx / d) * f; n.y += (dy / d) * f;
        }
        n.md = d;
      } else n.md = 1e9;
    }

    // links between nearby nodes (brighter near the cursor)
    links = [];
    ctx.lineWidth = 1;
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        const dx = a.sx - b.sx, dy = a.sy - b.sy;
        if (Math.abs(dx) > LINK_DIST || Math.abs(dy) > LINK_DIST) continue;
        const d = Math.hypot(dx, dy);
        if (d > LINK_DIST) continue;
        const hot = Math.min(a.md, b.md) < MOUSE_DIST;
        const alpha = (1 - d / LINK_DIST) * (hot ? 0.55 : 0.22) * Math.min(a.z, b.z);
        ctx.strokeStyle = `rgba(${hot ? HOT : LINK}, ${alpha})`;
        ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
        links.push([a, b]);
      }
    }

    // lines from the cursor to the closest nodes
    if (mouse.on) {
      for (const n of nodes) {
        if (n.md < MOUSE_DIST) {
          ctx.strokeStyle = `rgba(${HOT}, ${(1 - n.md / MOUSE_DIST) * 0.5})`;
          ctx.beginPath(); ctx.moveTo(mouse.x, mouse.y); ctx.lineTo(n.sx, n.sy); ctx.stroke();
        }
      }
    }

    // nodes (twinkling, larger near the cursor)
    for (const n of nodes) {
      const near = n.md < MOUSE_DIST ? 1 - n.md / MOUSE_DIST : 0;
      const alpha = (0.35 + 0.3 * Math.sin(t / 900 + n.ph)) * n.z + near * 0.5;
      ctx.fillStyle = `rgba(${near > 0 ? HOT : NODE}, ${Math.min(alpha, 1)})`;
      ctx.beginPath(); ctx.arc(n.sx, n.sy, n.r + near * 1.6, 0, Math.PI * 2); ctx.fill();
    }

    if (reduce) return;

    // data pulses travelling along links
    if (t - lastPacket > 380 && links.length && packets.length < 14) {
      const [a, b] = links[Math.floor(Math.random() * links.length)];
      packets.push({ a, b, t0: t, dur: 900 + Math.random() * 700 });
      lastPacket = t;
    }
    packets = packets.filter((p) => {
      const k = (t - p.t0) / p.dur;
      if (k >= 1) return false;
      const x = p.a.sx + (p.b.sx - p.a.sx) * k, y = p.a.sy + (p.b.sy - p.a.sy) * k;
      glow(x, y, 9, HOT, 0.45);
      ctx.fillStyle = `rgba(${HOT}, 0.95)`;
      ctx.beginPath(); ctx.arc(x, y, 1.4, 0, Math.PI * 2); ctx.fill();
      return true;
    });

    // click ripples
    ripples = ripples.filter((r) => {
      const age = t - r.t0;
      if (age > 1200) return false;
      const k = age / 1200;
      ctx.strokeStyle = `rgba(${NODE}, ${(1 - k) * 0.55})`;
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
