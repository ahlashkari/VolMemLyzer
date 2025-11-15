#!/usr/bin/env python3
"""
api_example_features.py — Minimal "features mode"
Extract one FeatureRow (one image → one row) and print a few fields.
"""

from dataclasses import asdict
import os
from volmemlyzer.runner import VolRunner
from volmemlyzer.plugins import build_registry
from volmemlyzer.pipeline import Pipeline
from volmemlyzer.utilities import _flatten_dict


# --- fill these in ---
VOL_PATH = "/opt/volatility3/vol.py"
IMAGE    = "/cases/win10.raw"
OUTDIR   = "/cases/.volmemlyzer"

runner = VolRunner(vol_path=VOL_PATH, default_renderer="json", default_timeout_s=600)
registry = build_registry()
pipe = Pipeline(runner, registry)

row = pipe.run_extract_features(
    image_path=IMAGE,
    enable=None,   # or a set like {"pslist","malfind"}
    drop=None,     # or {"netscan"} to exclude
    concurrency=max(1, os.cpu_count() or 1),
    artifacts_dir=OUTDIR,
    use_cache=True,
)

row_dict = _flatten_dict(asdict(row))

# Show a few representative fields
for k in sorted(list(row_dict.keys()))[:15]:
    print(f"{k}: {row_dict[k]}")
print(f"[+] Total features (flattened): {len(row_dict)}")
