"""Thread-safe API-key pool with round-robin selection and per-key cooldown.

Used by ``LLMClient`` to distribute outbound Ollama Cloud calls across
multiple ``OLLAMA_API_KEYS`` so a single key's RPM limit doesn't bottleneck
parallel verification runs. When a key returns 429, it is parked for
``Retry-After`` seconds (or a 60s fallback) and skipped on subsequent
acquires; the next available key serves the call instead.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Entry:
    key: str
    available_at: float = 0.0


class KeyPool:
    """Thread-safe round-robin pool with per-key cooldown."""

    def __init__(self, keys: list[str]):
        self._entries = [_Entry(k) for k in keys]
        self._lock = threading.Lock()
        self._cursor = 0

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

    def cooldown(self, key: str, seconds: float) -> None:
        """Park ``key`` for at least ``seconds`` before it is acquired again."""
        with self._lock:
            now = time.monotonic()
            for entry in self._entries:
                if entry.key == key:
                    entry.available_at = max(entry.available_at, now + max(0.0, seconds))
                    return


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
