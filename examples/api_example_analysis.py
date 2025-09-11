#!/usr/bin/env python3
# Run DFIR overview steps and inspect the returned summary dict.

import os
from volmemlyzer.runner import VolRunner
from volmemlyzer.plugins import build_registry
from volmemlyzer.pipeline import Pipeline
from volmemlyzer.analysis import OverviewAnalysis


# --- fill these in ---
VOL_PATH = "/opt/volatility3/vol.py"
IMAGE    = "/cases/win10.raw"
OUTDIR   = "/cases/.volmemlyzer"

runner = VolRunner(vol_path=VOL_PATH, default_renderer="json", default_timeout_s=600)
pipe = Pipeline(runner, build_registry())

analysis = OverviewAnalysis()
summary = analysis.run_steps(
    pipe=pipe,
    image_path=IMAGE,
    artifacts_dir=OUTDIR,
    steps=[0, 1, 2, 3, 6],   # bearings, processes, injections, network, report
    use_cache=True,
    high_level=False,
)

# print("[+] Summary keys:", ", ".join(sorted(summary.keys())))
# for step, data in summary.items():
#     print(f"\n=== {step} ===")
#     if isinstance(data, dict):
#         for k, v in list(data.items())[:10]:
#             print(f"{k}: {v}")
#     else:
#         print(repr(data))
