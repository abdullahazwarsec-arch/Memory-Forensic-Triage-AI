"""Intake gates (CSV, memory images, disk space) and the 55-feature gate."""
import io
import tempfile

import numpy as np
import pandas as pd
import pytest

from memtriage import input_validation as iv
from memtriage.memdump_extractor import DUMP_EXTENSIONS

BIG = 512 * 1024 * 1024


@pytest.fixture(scope="module")
def sample(root):
    return pd.read_csv(root / "data" / "test_samples" / "guaranteed_malware.csv")


def severity(df, cols):
    return iv.check_features(df, cols)["severity"]


def test_complete_profile_passes_and_labels_are_ignored(sample, model_features):
    assert severity(sample, model_features) == "ok"
    assert severity(sample.assign(Class="Malware"), model_features) == "ok"


def test_missing_features_warn_then_block(sample, model_features):
    report = iv.check_features(sample.drop(columns=model_features[:3]), model_features)
    assert report["severity"] == "warn" and len(report["missing"]) == 3
    assert severity(sample.drop(columns=model_features[:20]), model_features) == "block"


@pytest.mark.parametrize("value", [np.inf, -4.0])
def test_infinite_or_negative_values_block(sample, model_features, value):
    bad = sample.astype({c: float for c in model_features})
    bad.loc[0, model_features[5]] = value
    assert severity(bad, model_features) == "block"


def test_text_and_empty_cells_are_counted(sample, model_features):
    two = pd.concat([sample, sample], ignore_index=True).astype(object)
    two.loc[0, model_features[5]] = "abc"
    two.loc[1, model_features[6]] = np.nan
    report = iv.check_features(two, model_features)
    assert report["severity"] == "warn" and report["invalid_cells"] == 1 and report["empty_cells"] == 1


def test_feature_matrix_is_ordered_and_zero_filled(sample, model_features):
    matrix = iv.feature_matrix(sample.drop(columns=model_features[:2]).assign(Class="x"), model_features)
    assert list(matrix.columns) == model_features
    assert (matrix[model_features[0]] == 0).all() and matrix.dtypes.eq(float).all()


def test_csv_upload_gate(root, model_features):
    good = (root / "data" / "test_samples" / "guaranteed_malware.csv").read_bytes()
    iv.check_csv_upload(io.BytesIO(good), len(good), model_features)
    for data, size in [(b"MZ\x00\x00" * 50, 200), (good, 60 * 1024 * 1024),
                       (b"name,age\nbob,3\n", 16), (b"", 0)]:
        with pytest.raises(iv.UploadRejected):
            iv.check_csv_upload(io.BytesIO(data), size, model_features)


@pytest.mark.parametrize("head,name", [(b"\0" * 64, "a.raw"), (b"PAGEDU64" + b"\0" * 64, "a.dmp"),
                                       (b"EMiL" + b"\0" * 64, "a.lime")])
def test_memory_images_accepted(head, name):
    iv.check_memory_image(io.BytesIO(head), BIG, name, DUMP_EXTENSIONS)


@pytest.mark.parametrize("head,name,size", [
    (b"PK\x03\x04" + b"\0" * 64, "a.raw", BIG),     # zip renamed
    (b"MZ\x90\x00", "a.mem", BIG),                 # executable renamed
    (b"\0" * 64, "a.dmp", BIG),                    # .dmp without its signature
    (b"\0" * 64, "a.raw", 10 * 1024 * 1024),       # too small
    (b"\0" * 64, "a.exe", BIG),                    # unsupported extension
])
def test_memory_images_rejected(head, name, size):
    with pytest.raises(iv.UploadRejected):
        iv.check_memory_image(io.BytesIO(head), size, name, DUMP_EXTENSIONS)


def test_disk_space_guard():
    with pytest.raises(iv.UploadRejected):
        iv.check_disk_space(tempfile.gettempdir(), 10 ** 15)
