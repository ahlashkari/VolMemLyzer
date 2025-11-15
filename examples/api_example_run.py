#!/usr/bin/env python3
"""
api_example_run.py — Minimal "run mode"
Run a few Volatility plugins and print the artifact paths.
"""

import os
from volmemlyzer.runner import VolRunner
from volmemlyzer.plugins import build_registry
from volmemlyzer.pipeline import Pipeline


# --- fill these in ---
VOL_PATH = "/opt/volatility3/vol.py"
IMAGE    = "/cases/win10.raw"
OUTDIR   = "/cases/.volmemlyzer"

runner = VolRunner(vol_path=VOL_PATH, default_renderer="json", default_timeout_s=600)
registry = build_registry()
pipe = Pipeline(runner, registry)

result = pipe.run_plugin_raw(
    image_path=IMAGE,
    enable={"pslist"}, #"pstree", "psscan"},   # choose any subset
    drop=None,
    renderer="json",
    outdir=OUTDIR,
    concurrency=max(1, os.cpu_count() or 1),
    use_cache=True,
)

print("[+] raw artifacts directory:", result.artifacts.get("raw_dir"))
for name, path in (result.artifacts.get("plugins") or {}).items():
    print(f"  - {name:<20} → {path}")

