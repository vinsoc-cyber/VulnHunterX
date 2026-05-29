"""Thread-safe API-key pool with round-robin selection and per-key cooldown.

Used by ``LLMClient`` to distribute outbound Ollama Cloud calls across
multiple keys (comma-separated ``OLLAMA_API_KEYS``) so a single key's RPM limit doesn't bottleneck
parallel verification runs. When a key returns 429, it is parked for
``Retry-After`` seconds (or a 60s fallback) and skipped on subsequent
acquires; the next available key serves the call instead.

Cooldowns can optionally be persisted to a JSON file so that keys exhausted
in one run aren't re-tested at the start of the next run. Keys are stored as
SHA-256 hashes so the state file is safe to commit / share. Wall-clock
timestamps are used on disk (survives process restarts) and converted to
``time.monotonic()`` deltas in memory.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


def _key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass
class _Entry:
    key: str
    available_at: float = 0.0  # time.monotonic() value


class KeyPool:
    """Thread-safe round-robin pool with per-key cooldown."""

    def __init__(self, keys: list[str], state_path: str | Path | None = None):
        self._entries = [_Entry(k) for k in keys]
        self._lock = threading.Lock()
        self._cursor = 0
        self._state_path = Path(state_path) if state_path else None
        if self._state_path is not None:
            self._load_state()

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)

    def acquire(self) -> str | None:
        """Return the next available key, or ``None`` if the pool is empty.

        If every key is cooling, returns the key with the earliest
        ``available_at`` so the caller still makes progress; that key's
        cooldown can be extended on the next failure.
        """
        with self._lock:
            if not self._entries:
                return None
            now = time.monotonic()
            n = len(self._entries)
            for i in range(n):
                idx = (self._cursor + i) % n
                if self._entries[idx].available_at <= now:
                    self._cursor = (idx + 1) % n
                    return self._entries[idx].key
            soonest_idx = min(range(n), key=lambda i: self._entries[i].available_at)
            self._cursor = (soonest_idx + 1) % n
            return self._entries[soonest_idx].key

    def cooldown(self, key: str, seconds: float) -> bool:
        """Park ``key`` for at least ``seconds`` before it is acquired again.

        Returns ``True`` when the key transitioned from active → parked
        (i.e. a fresh park), ``False`` when it was already cooling. Callers
        use this to dedup log warnings under concurrent failures.
        """
        was_active = False
        with self._lock:
            now = time.monotonic()
            for entry in self._entries:
                if entry.key == key:
                    was_active = entry.available_at <= now
                    entry.available_at = max(entry.available_at, now + max(0.0, seconds))
                    self._save_state_locked()
                    return was_active
        return was_active

    def status(self) -> list[tuple[str, float]]:
        """Snapshot of ``(last4-of-key, seconds-until-available)`` for diagnostics."""
        with self._lock:
            now = time.monotonic()
            return [(e.key[-4:], max(0.0, e.available_at - now)) for e in self._entries]

    def _load_state(self) -> None:
        path = self._state_path
        if path is None or not path.is_file():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read key-pool state from %s: %s", path, exc)
            return
        if not isinstance(data, dict):
            return
        now_wall = time.time()
        now_mono = time.monotonic()
        restored = 0
        for entry in self._entries:
            wall_at = data.get(_key_hash(entry.key))
            if not isinstance(wall_at, (int, float)):
                continue
            remaining = float(wall_at) - now_wall
            if remaining > 0:
                entry.available_at = now_mono + remaining
                restored += 1
        if restored:
            logger.info(
                "Restored %d cooling key(s) from %s — they will be skipped until cooldown expires.",
                restored,
                path,
            )

    def _save_state_locked(self) -> None:
        path = self._state_path
        if path is None:
            return
        now_wall = time.time()
        now_mono = time.monotonic()
        out: dict[str, float] = {}
        for entry in self._entries:
            if entry.available_at > now_mono:
                out[_key_hash(entry.key)] = now_wall + (entry.available_at - now_mono)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(out), encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            logger.warning("Could not persist key-pool state to %s: %s", path, exc)


def extract_retry_after(exc: Exception, default: float = 60.0) -> float:
    """Best-effort parse of a Retry-After value from a LiteLLM ``RateLimitError``.

    LiteLLM surfaces the original response on attributes that vary by version
    (``.response``, ``.headers``, ``.response.headers``). We scan the common
    shapes and fall back to ``default`` when nothing is found or the value
    isn't a parseable float.
    """
    candidates: list[object] = [
        getattr(exc, "response", None),
        getattr(exc, "headers", None),
    ]
    for cand in candidates:
        if cand is None:
            continue
        headers = getattr(cand, "headers", cand)
        getter = getattr(headers, "get", None)
        if not callable(getter):
            continue
        value = getter("retry-after") or getter("Retry-After")
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return default
