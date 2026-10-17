"""Hash checker, hash parsing and time estimates."""

import pytest
from streamlit.testing.v1 import AppTest

from hazmem import evidence_integrity as ei
from hazmem import hash_checker, timing

ABC = {"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
       "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d", "md5": "900150983cd24fb0d6963f7d28e17f72"}


def test_known_digests_and_progress(tmp_path):
    f = tmp_path / "abc.bin"
    f.write_bytes(b"abc")
    calls = []
    h = ei.hash_file(str(f), progress=lambda done, total: calls.append((done, total)))
    assert {k: h[k] for k in ABC} == ABC and h["size"] == 3 and calls[-1] == (3, 3)


@pytest.mark.parametrize("text,expected", [
    (f"{ABC['sha256']}  memory.raw", [(ABC["sha256"], "memory.raw")]),
    (f"{ABC['md5']} *memory.raw", [(ABC["md5"], "memory.raw")]),
    (f"SHA256 hash of memory.raw:\n{ABC['sha256'].upper()}\nCertUtil: -hashfile command completed successfully.",
     [(ABC["sha256"], None)]),
    (f"MD5: {ABC['md5']}\nSHA1: {ABC['sha1']}", [(ABC["md5"], None), (ABC["sha1"], None)]),
    ("no hash here", []),
])
def test_parse_hash_text(text, expected):
    assert ei.parse_hash_text(text) == expected


def test_detect_algorithm():
    assert [ei.detect_algorithm(ABC[k]) for k in ("md5", "sha1", "sha256")] == ["md5", "sha1", "sha256"]
    assert ei.detect_algorithm("xyz") is None and ei.detect_algorithm("a" * 50) is None


def test_compare_match_and_mismatch():
    rows = hash_checker.compare(ABC, [(ABC["sha1"], None), ("f" * 64, "other.raw")])
    assert rows[0][:2] == ("sha1", ABC["sha1"]) and rows[0][3] is True
    assert rows[1][0] == "sha256" and rows[1][3] is False and rows[1][4] == "other.raw"


def _report(image="a" * 64, after=None, csv="c" * 64):
    return {"integrity": {"pre_extraction": {"sha256": image}, "post_extraction": {"sha256": after or image},
                          "derived_csv": {"sha256": csv, "file": "dump_features.csv"}}}


def test_conversion_chain_verified():
    checks = hash_checker.conversion_checks(_report(), "c" * 64, "dump_features.csv", dump_sha256="a" * 64)
    assert [c[0] for c in checks] == [True, True, True]


@pytest.mark.parametrize("report,csv,dump,failing", [
    (_report(after="b" * 64), "c" * 64, None, 0),     # image changed during conversion
    (_report(), "d" * 64, None, 1),                    # different CSV
    (_report(), "c" * 64, "e" * 64, 2),                # different memory image
    (_report(), "c" * 64, "", 2),                      # image not found
])
def test_conversion_chain_failures(report, csv, dump, failing):
    checks = hash_checker.conversion_checks(report, csv, "dump_features.csv", dump_sha256=dump)
    assert checks[failing][0] is False


def test_conversion_with_sealed_manifest(tmp_path):
    chain = ei.CustodyChain("MF-9", "dump.raw", "memory-dump")
    chain.record("Acquisition", "received", "dump.raw", {"sha256": "a" * 64, "md5": "m", "size": 1}, role="evidence")
    chain.record("Derived Data", "csv", "dump_features.csv", {"sha256": "c" * 64, "md5": "m", "size": 1}, role="csv")
    manifest = chain.to_dict()
    ok = hash_checker.conversion_checks(_report(), "c" * 64, manifest=manifest)
    assert ok[-1][0] is True
    manifest["events"][0]["artifact"] = "edited.raw"                       # tampered ledger
    assert hash_checker.conversion_checks(_report(), "c" * 64, manifest=manifest)[-1][0] is False


def test_time_estimates_and_learning(tmp_path):
    t = timing.Timings(str(tmp_path / "timing_stats.json"))
    small, big = t.extraction_seconds(512 * 1024 ** 2), t.extraction_seconds(2 * 1024 ** 3)
    assert 0 < small < big and 4 * 60 < big < 10 * 60                     # 2 GB ≈ 5-8 min observed
    assert timing.fmt_duration(3) == "under 5 s" and timing.fmt_duration(180) == "3 min"
    assert timing.remaining(10, 0.0, 60) == 50 and timing.remaining(50, 0.5, 60) < 60
    t.record_hash(1024 ** 3, 2.0)                                          # 512 MB/s measured
    assert timing.Timings(str(tmp_path / "timing_stats.json")).stats["hash_mb_s"] > 250


def _page(path, expected):
    import streamlit as st
    from hazmem import hash_checker as hc
    st.session_state.setdefault("hc_source", "path")
    st.session_state.setdefault("hc_path", path)
    st.session_state.setdefault("hc_expected", expected)
    hc.render_hash_checker_page()


@pytest.mark.parametrize("expected,verdict", [(ABC["sha256"], "MATCH"), ("0" * 64, "MISMATCH"),
                                              ("", "Fingerprint computed")])
def test_hash_checker_page(tmp_path, expected, verdict):
    f = tmp_path / "abc.csv"
    f.write_bytes(b"abc")
    hash_checker.OUTPUT_DIR = str(tmp_path)
    at = AppTest.from_function(_page, args=(str(f), expected), default_timeout=60).run()
    next(b for b in at.button if b.label == "Compute & verify").click().run()
    assert not at.exception
    assert verdict in " ".join(str(m.value) for m in at.markdown)


@pytest.mark.parametrize("probability,risk,label", [
    (0.10, "NORMAL", "BENIGN"), (0.399, "NORMAL", "BENIGN"), (0.40, "SUSPICIOUS", "UNCERTAIN"),
    (0.60, "SUSPICIOUS", "UNCERTAIN"), (0.749, "SUSPICIOUS", "UNCERTAIN"), (0.75, "HIGH RISK", "MALWARE"),
    (0.99, "HIGH RISK", "MALWARE"),
])
def test_classification_always_matches_risk(probability, risk, label):
    from hazmem.knowledge import CLASSIFICATION, risk_tier
    assert risk_tier(probability) == risk and CLASSIFICATION[risk] == label
