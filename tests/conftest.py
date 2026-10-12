"""
Test isolation: every test session uses a throw-away ledger key, account store,
audit log and output folder, so the real evidence, accounts and logs on this
machine are never touched. Must run before any hazmem module is imported.
"""
import os
import sys
import secrets
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = Path(tempfile.mkdtemp(prefix="hazmem-tests-"))
os.environ["FORENSICS_LEDGER_KEY"] = secrets.token_hex(32)
os.environ["HAZMEM_USERS_FILE"] = str(_TMP / "users.json")
os.environ["HAZMEM_AUDIT_LOG"] = str(_TMP / "logs" / "audit.log")
os.environ["HAZMEM_OUTPUT_DIR"] = str(_TMP / "outputs")

import pytest  # noqa: E402

SAMPLES = ROOT / "data" / "test_samples"


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def model_features() -> list:
    import joblib
    return list(joblib.load(ROOT / "models" / "random_forest_model.pkl").feature_names_in_)


@pytest.fixture
def fresh_users(tmp_path, monkeypatch):
    """An empty account store for one test."""
    from hazmem import auth
    monkeypatch.setattr(auth, "USERS_PATH", str(tmp_path / "users.json"))
    return auth
