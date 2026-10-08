"""
Pin the SHA-256 of every trained model in models/ to models/model_hashes.json.
The dashboard refuses to unpickle a model whose hash is not pinned or differs.
Run this after (re)training a model, review the diff and commit it.
"""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

import evidence_integrity as ei

pins = ei.pin_model_hashes()
for name, sha256 in pins.items():
    print(f"{sha256}  {name}")
print(f"Pinned {len(pins)} model(s) -> {ei.MODEL_HASHES_PATH}")
