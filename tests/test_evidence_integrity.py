"""Custody ledger (HMAC links), manifest verification and model hash pinning."""
import hashlib
import json
import os
import shutil

import pytest

from memtriage import evidence_integrity as ei

FIELDS = ["seq", "timestamp", "stage", "analyst", "action", "artifact", "role", "sha256", "md5", "size",
          "expected_sha256", "status", "details", "prev_link"]


@pytest.fixture
def manifest(tmp_path):
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"evidence" * 1000)
    chain = ei.CustodyChain("MF-1", "evidence.bin", "test", evidence_id="EV-1", analyst="Tester")
    chain.record("Acquisition", "received", "evidence.bin", ei.hash_file(str(evidence)), role="evidence")
    chain.verify_file("Pre-Analysis", "re-hashed", str(evidence), role="evidence")
    return chain, chain.save_manifest(str(tmp_path / "case" / "custody_manifest.json"))


def test_chain_and_manifest_verify(manifest):
    chain, path = manifest
    assert chain.is_intact
    assert ei.verify_manifest(path)["verified"]
    data = json.load(open(path))
    assert data["link_algorithm"] == "HMAC-SHA256" and data["ledger_key_id"] == ei.ledger_key_id()


def test_rechained_forgery_without_key_is_detected(manifest, tmp_path):
    _, path = manifest
    data, prev = json.load(open(path)), ei.GENESIS_LINK
    data["events"][0]["analyst"] = "Mallory"
    for e in data["events"]:                      # attacker re-chains with plain SHA-256
        e["prev_link"] = prev
        e["link_hash"] = hashlib.sha256("|".join(str(e.get(k, "")) for k in FIELDS).encode()).hexdigest()
        prev = e["link_hash"]
    data["head_link_hash"] = prev
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(data))
    assert not ei.verify_manifest(str(forged))["verified"]


def test_truncation_and_wrong_key_are_detected(manifest, tmp_path):
    _, path = manifest
    data = json.load(open(path))
    data["events"].pop()
    truncated = tmp_path / "truncated.json"
    truncated.write_text(json.dumps(data))
    assert not ei.verify_manifest(str(truncated))["verified"]
    assert not ei.verify_manifest(path, key=os.urandom(32))["verified"]


def test_in_memory_edit_breaks_ledger(manifest):
    chain, _ = manifest
    chain.events[0]["details"] = "edited"
    assert not chain.ledger_intact()


def test_hash_mismatch_marks_chain_compromised(tmp_path):
    evidence = tmp_path / "e.bin"
    evidence.write_bytes(b"original")
    chain = ei.CustodyChain("MF-2", "e.bin", "test")
    chain.record("Acquisition", "received", "e.bin", ei.hash_file(str(evidence)), role="evidence")
    os.chmod(evidence, 0o666)
    evidence.write_bytes(b"modified")
    chain.verify_file("Pre-Analysis", "re-hashed", str(evidence), role="evidence")
    assert chain.mismatches and not chain.is_intact


def test_pinned_model_loads(root):
    model, sha = ei.load_verified_model(str(root / "models" / "random_forest_model.pkl"))
    assert hasattr(model, "predict_proba") and len(sha) == 64


def test_tampered_or_unpinned_model_is_refused(root, tmp_path):
    tampered = tmp_path / "random_forest_model.pkl"
    shutil.copy(root / "models" / "random_forest_model.pkl", tampered)
    with open(tampered, "ab") as f:
        f.write(b"\x00")
    with pytest.raises(ei.ModelIntegrityError):
        ei.load_verified_model(str(tampered))
    unknown = tmp_path / "unknown.pkl"
    shutil.copy(tampered, unknown)
    with pytest.raises(ei.ModelIntegrityError):
        ei.load_verified_model(str(unknown))
