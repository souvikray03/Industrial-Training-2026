from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_dir() -> Path:
    return FIXTURE_DIR


@pytest.fixture
def clean_snapshot_dict() -> dict:
    return json.loads((FIXTURE_DIR / "clean_snapshot.json").read_text(encoding="utf-8"))


@pytest.fixture
def violations_snapshot_dict() -> dict:
    return json.loads((FIXTURE_DIR / "violations_snapshot.json").read_text(encoding="utf-8"))


@pytest.fixture
def test_rules_path() -> Path:
    return FIXTURE_DIR / "rules.json"


@pytest.fixture
def test_rules(test_rules_path: Path):
    from gcp_compliance_auditor.rules import load_rules

    return load_rules(test_rules_path)
