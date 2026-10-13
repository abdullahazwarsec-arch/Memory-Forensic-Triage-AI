"""
Time estimates
==============
Estimates how long hashing, memory-dump extraction and an analysis will take,
and turns progress into a live "about N left" countdown.

Defaults are calibrated on real runs of this project (Volatility 3 needs about
160 s per GB with 3 plugins in parallel; the first run of a new Windows version
also downloads symbol tables). Every completed run updates a moving average
stored in <outputs>/timing_stats.json, so estimates adapt to this machine.
"""

import json
import os
import time
import threading

DEFAULTS = {
    "hash_mb_s": 250.0,          # SHA-256 + SHA-1 + MD5 throughput
    "extract_s_per_gb": 160.0,   # Volatility plugins, wall time
    "extract_overhead_s": 15.0,  # windows.info / start-up
    "triage_s": 8.0,             # re-verify + models + SHAP + LIME for one snapshot
}
_ALPHA = 0.4                     # weight of the newest run in the moving average
_lock = threading.Lock()


class Timings:
    def __init__(self, path: str):
        self.path = path
        self.stats = dict(DEFAULTS)
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.stats.update({k: float(v) for k, v in json.load(f).items() if k in DEFAULTS})
        except (OSError, ValueError):
            pass

    # ── estimates (seconds) ──
    def hash_seconds(self, size: int) -> float:
        return size / (self.stats["hash_mb_s"] * 1024 * 1024)

    def extraction_seconds(self, size: int) -> float:
        """Hash before + Volatility + hash after."""
        return (self.stats["extract_overhead_s"] + self.stats["extract_s_per_gb"] * size / 1024 ** 3
                + 2 * self.hash_seconds(size))

    def triage_seconds(self, size: int = 0) -> float:
        return self.stats["triage_s"] + self.hash_seconds(size)

    # ── learning ──
    def _update(self, key: str, value: float):
        if value > 0:
            self.stats[key] = (1 - _ALPHA) * self.stats[key] + _ALPHA * value
            with _lock:
                try:
                    os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                    with open(self.path, "w", encoding="utf-8") as f:
                        json.dump(self.stats, f, indent=2)
                except OSError:
                    pass

    def record_hash(self, size: int, seconds: float):
        if size >= 64 * 1024 * 1024 and seconds > 0.2:          # small files say nothing about throughput
            self._update("hash_mb_s", size / 1024 / 1024 / seconds)

    def record_extraction(self, size: int, seconds: float):
        volatility = seconds - self.stats["extract_overhead_s"] - 2 * self.hash_seconds(size)
        if size >= 64 * 1024 * 1024 and volatility > 0:
            self._update("extract_s_per_gb", volatility / (size / 1024 ** 3))

    def record_triage(self, seconds: float, size: int = 0):
        self._update("triage_s", max(seconds - self.hash_seconds(size), 0.5))


def fmt_duration(seconds: float) -> str:
    """Friendly rounded duration: 'under 5 s', '40 s', '3 min', '1 h 5 min'."""
    seconds = max(0.0, float(seconds))
    if seconds < 5:
        return "under 5 s"
    if seconds < 60:
        return f"{int(round(seconds / 5.0) * 5)} s"
    minutes = int(round(seconds / 60.0))
    if minutes < 60:
        return f"{minutes} min"
    return f"{minutes // 60} h {minutes % 60} min"


def approx(seconds: float) -> str:
    """'under 5 s' or 'about 3 min' - for estimates shown in sentences."""
    text = fmt_duration(seconds)
    return text if text.startswith("under") else f"about {text}"


def remaining(elapsed: float, fraction: float, estimate: float) -> float:
    """
    Seconds left: early on trust the estimate; as progress grows, trust the
    observed rate (elapsed / fraction) more.
    """
    fraction = min(max(fraction, 0.0), 1.0)
    if fraction <= 0.02:
        return max(estimate - elapsed, 0.0)
    observed_total = elapsed / fraction
    weight = min(fraction * 1.5, 1.0)
    total = weight * observed_total + (1 - weight) * max(estimate, elapsed)
    return max(total - elapsed, 0.0)


def eta_text(elapsed: float, fraction: float, estimate: float) -> str:
    left = remaining(elapsed, fraction, estimate)
    return "almost done" if left < 3 else f"about {fmt_duration(left)} left"


class ProgressETA:
    """A Streamlit progress bar whose text ends with a live 'about N left' countdown (updates throttled)."""

    def __init__(self, estimate: float, text: str):
        import streamlit as st
        self.bar, self.estimate, self.t0, self.last = st.progress(0.0, text=text), estimate, time.time(), 0.0

    def update(self, fraction: float, message: str, force: bool = False):
        now = time.time()
        if not force and now - self.last < 0.3:
            return
        self.last = now
        fraction = min(max(fraction, 0.0), 1.0)
        self.bar.progress(fraction, text=f"{message} · {eta_text(now - self.t0, fraction, self.estimate)}")

    @property
    def elapsed(self) -> float:
        return time.time() - self.t0

    def empty(self):
        self.bar.empty()
