import json
from pathlib import Path
import pytest

APPS = ["dvcp", "nodegoat", "insecure-coding-examples", "dvwa"]


@pytest.mark.parametrize("app", APPS)
def test_test_case_complete(app):
    d = Path("benchmark/test_case") / app
    m = json.loads((d / "metadata.json").read_text())
    assert {"repo_url", "sha", "lang", "name", "scanner"} <= set(m)
    assert (d / "ground_truth.json").exists()
    assert json.loads((d / "ground_truth.json").read_text())  # non-empty real-only list
    assert (d / "scanner_result" / f"{app}.sarif").exists()
