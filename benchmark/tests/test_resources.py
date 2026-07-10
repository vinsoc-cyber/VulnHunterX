from modes import version_ab as v


def _rf(verdict, inp, out, cached, elapsed, iters):
    return {"verdict": verdict, "truth": "real", "input_tokens": inp,
            "output_tokens": out, "cached_input_tokens": cached,
            "elapsed_seconds": elapsed, "iterations": iters}


def test_summarize_resources_sums_all_but_iters_over_completed():
    findings = [
        _rf("TP", 1000, 100, 800, 12.0, 3),
        _rf("NMD", 500, 50, 250, 4.0, 2),
        _rf("ERROR", 200, 0, 0, 1.0, 9),   # error: tokens/time counted, iterations NOT
    ]
    r = v.summarize_resources(findings)
    assert r["input_tokens"] == 1700
    assert r["output_tokens"] == 150
    assert r["cached_input_tokens"] == 1050
    assert r["cache_hit_ratio"] == round(1050 / 1700, 4)
    assert r["elapsed_seconds"] == 17.0
    assert r["iterations_total"] == 5      # 3 + 2; error's 9 excluded
    assert r["iterations_mean"] == 2.5     # 5 / 2 completed


def test_summarize_resources_zero_guards():
    r = v.summarize_resources([])
    assert r["cache_hit_ratio"] == 0.0 and r["iterations_mean"] == 0.0
    assert r["input_tokens"] == 0 and r["iterations_total"] == 0
