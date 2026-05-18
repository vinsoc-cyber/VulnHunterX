# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Unit tests for the thread-safe Ollama API-key pool."""

from __future__ import annotations

import threading
import time
from collections import Counter

import pytest

from vuln_hunter_x.llm.key_pool import KeyPool, extract_retry_after


class TestKeyPoolBasics:
    def test_empty_pool_returns_none(self):
        pool = KeyPool([])
        assert pool.acquire() is None
        assert len(pool) == 0
        assert not bool(pool)

    def test_single_key_always_returned(self):
        pool = KeyPool(["only"])
        for _ in range(5):
            assert pool.acquire() == "only"

    def test_two_keys_round_robin(self):
        pool = KeyPool(["a", "b"])
        first = pool.acquire()
        second = pool.acquire()
        assert {first, second} == {"a", "b"}
        # Third call wraps back to the first one we saw
        assert pool.acquire() == first

    def test_three_keys_round_robin_order_preserved(self):
        pool = KeyPool(["a", "b", "c"])
        sequence = [pool.acquire() for _ in range(6)]
        # Two complete cycles, same ordering
        assert sequence[:3] == sequence[3:]
        assert set(sequence[:3]) == {"a", "b", "c"}


class TestCooldown:
    def test_cooldown_skips_parked_key(self):
        pool = KeyPool(["a", "b"])
        pool.cooldown("a", 60)
        # The cooling key must be skipped on the next acquires
        for _ in range(3):
            assert pool.acquire() == "b"

    def test_all_keys_cooling_returns_soonest_available(self):
        pool = KeyPool(["a", "b"])
        pool.cooldown("a", 120)
        pool.cooldown("b", 5)
        # Both cooling, but "b" comes off cooldown first — must be returned
        assert pool.acquire() == "b"

    def test_cooldown_expires_naturally(self):
        pool = KeyPool(["a", "b"])
        pool.cooldown("a", 0.05)
        # Right after cooldown, "a" is excluded
        assert pool.acquire() == "b"
        time.sleep(0.08)
        # After it expires, "a" becomes available again
        seen = {pool.acquire(), pool.acquire()}
        assert "a" in seen

    def test_cooldown_for_unknown_key_is_noop(self):
        pool = KeyPool(["a"])
        pool.cooldown("does-not-exist", 60)  # must not raise
        assert pool.acquire() == "a"

    def test_cooldown_extends_but_does_not_shrink(self):
        pool = KeyPool(["a", "b"])
        pool.cooldown("a", 60)
        pool.cooldown("a", 0.01)  # shorter cooldown must not override the longer one
        # "a" is still parked for the original 60s window
        for _ in range(3):
            assert pool.acquire() == "b"


class TestThreadSafety:
    def test_concurrent_acquire_distributes_evenly(self):
        keys = ["k1", "k2", "k3", "k4"]
        pool = KeyPool(keys)
        counter: Counter[str] = Counter()
        lock = threading.Lock()

        def worker():
            for _ in range(250):
                k = pool.acquire()
                with lock:
                    counter[k] += 1

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 8 threads × 250 acquires = 2000 total, evenly across 4 keys = 500 each.
        # Allow ±5% drift for scheduler jitter.
        total = sum(counter.values())
        assert total == 2000
        for k in keys:
            assert 475 <= counter[k] <= 525, f"{k} acquired {counter[k]} times"


class TestExtractRetryAfter:
    def test_default_when_no_headers(self):
        assert extract_retry_after(Exception("no headers"), default=30.0) == 30.0

    def test_parses_from_response_headers_attr(self):
        class FakeResp:
            headers = {"Retry-After": "12.5"}

        exc = Exception("rate-limited")
        exc.response = FakeResp()  # type: ignore[attr-defined]
        assert extract_retry_after(exc) == pytest.approx(12.5)

    def test_parses_from_headers_attr_directly(self):
        exc = Exception("rate-limited")
        exc.headers = {"retry-after": "7"}  # type: ignore[attr-defined]
        assert extract_retry_after(exc) == 7.0

    def test_non_numeric_falls_back_to_default(self):
        exc = Exception("rate-limited")
        exc.headers = {"retry-after": "Tue, 01 Jan 2030 00:00:00 GMT"}  # type: ignore[attr-defined]
        # HTTP-date format is not numeric — we fall back to the default.
        assert extract_retry_after(exc, default=42.0) == 42.0
