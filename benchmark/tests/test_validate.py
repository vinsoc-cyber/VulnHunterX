import json
from pathlib import Path
import pytest
from modes import version_ab as v

REAL_PANELS = ["dvcp", "nodegoat", "insecure-coding-examples", "dvwa"]


def _panel(tc, sarif_results, oracle):
    (tc / "scanner_result").mkdir(parents=True)
    runs = [{"results": [
        {"ruleId": rid, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri}, "region": {"startLine": line}}}]}
        for (rid, uri, line) in sarif_results]}]
    (tc / "scanner_result" / f"{tc.name}.sarif").write_text(json.dumps({"runs": runs}))
    (tc / "ground_truth.json").write_text(json.dumps(oracle))


def test_sarif_result_keys(tmp_path):
    tc = tmp_path / "app"
    _panel(tc, [("r1", "a.c", 5), ("r2", "b.c", 9)], [])
    assert v.sarif_result_keys(tc / "scanner_result" / "app.sarif") == {
        ("r1", "a.c", 5), ("r2", "b.c", 9)}


def test_sarif_result_keys_skips_locationless(tmp_path):
    tc = tmp_path / "app"
    (tc / "scanner_result").mkdir(parents=True)
    (tc / "scanner_result" / "app.sarif").write_text(json.dumps({"runs": [{"results": [
        {"ruleId": "r1", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "a.c"}, "region": {"startLine": 5}}}]},
        {"ruleId": "r2"},  # no location → skipped
        {"ruleId": "r3", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "c.c"}}}]},  # no region → skipped
    ]}]}))
    assert v.sarif_result_keys(tc / "scanner_result" / "app.sarif") == {("r1", "a.c", 5)}


def test_validate_panel_subset_relative_passes(tmp_path):
    tc = tmp_path / "app"
    _panel(tc, [("r", "src/x.c", 5), ("r2", "y.c", 1)], ["r@src/x.c:5"])
    v.validate_panel(tc)  # no raise


def test_validate_panel_missing_oracle_key_fails(tmp_path):
    tc = tmp_path / "app"
    _panel(tc, [("r", "src/x.c", 5)], ["r@src/x.c:5", "r@nope.c:9"])
    with pytest.raises(SystemExit):
        v.validate_panel(tc)


def test_validate_panel_absolute_path_fails(tmp_path):
    tc = tmp_path / "app"
    _panel(tc, [("r", "/abs/x.c", 5)], ["r@/abs/x.c:5"])  # in-SARIF but absolute
    with pytest.raises(SystemExit):
        v.validate_panel(tc)


@pytest.mark.parametrize("app", REAL_PANELS)
def test_real_panels_validate(app):
    v.validate_panel(Path("benchmark/test_case") / app)  # no raise
