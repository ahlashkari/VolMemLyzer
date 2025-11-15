#!/usr/bin/env python3
"""
VolMemLyzer compatibility shim (legacy main.py)

Preferred interface: the packaged CLI `volmemlyzer` (see README).
This script keeps the old "python main.py -f ... -o ... -V ..." workflow alive and
writes ONE aggregated features file per run:
  - <outdir>/features/output.csv  (default)
  - <outdir>/features/output.json

Flags (legacy-compatible):
  -f, --memdump     Path to a memory image OR a folder of images          (required)
  -o, --output      Output directory for artifacts & features              (required)
  -V, --volatility  Path to Volatility3's vol.py                           (required)
  -D, --drop        Comma-separated plugin list to skip (optional)
  -P, --plugins     Comma-separated plugin list to include (optional)
  -F, --format      csv|json (default: csv)
  -j, --jobs        Parallel workers (default: CPU count)
      --no-cache    Ignore cached plugin outputs

The logic here calls the library directly to avoid CLI drift and aggregates into
a single output file per run.
"""
from __future__ import annotations
import argparse, os, sys, json
from dataclasses import asdict
from typing import List, Dict

try:
    # 1) Preferred: installed package (pip install -e .)
    from volmemlyzer.runner import VolRunner
    from volmemlyzer.extractor_registry import ExtractorRegistry
    from volmemlyzer.plugins import build_registry
    from volmemlyzer.pipeline import Pipeline
except ImportError:
    import sys, pathlib
    repo_root = pathlib.Path(__file__).resolve().parent
    src_dir = repo_root / "src"
    # 2) Dev clone with src/ layout
    if (src_dir / "volmemlyzer").exists():
        sys.path.insert(0, str(src_dir))
        from volmemlyzer.runner import VolRunner
        from volmemlyzer.extractor_registry import ExtractorRegistry
        from volmemlyzer.plugins import build_registry
        from volmemlyzer.pipeline import Pipeline


SUPPORTED_EXTS = {".vmem", ".raw", ".dmp", ".bin", ".mem"}

def find_images(path: str) -> List[str]:
    if os.path.isfile(path):
        return [path]
    found = []
    for root, _, files in os.walk(path):
        for name in files:
            if os.path.splitext(name)[1].lower() in SUPPORTED_EXTS:
                found.append(os.path.join(root, name))
    return sorted(found)

def flatten_feature_row(row: Dict) -> Dict:
    # bring nested 'features' dict to top level
    flat = dict(row)
    feats = flat.pop("features", {}) or {}
    for k, v in feats.items():
        flat[k] = v
    return flat

def write_csv_aggregated(rows: List[Dict], csv_path: str) -> None:
    import csv
    os.makedirs(os.path.dirname(os.path.abspath(csv_path)), exist_ok=True)
    # union of all keys
    keys = []
    seen = set()
    for r in rows:
        for k in r.keys():
            if k not in seen:
                seen.add(k)
                keys.append(k)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="VolMemLyzer legacy entry point (aggregated features output)."
    )
    p.add_argument("-f", "--memdump", required=True, help="Memory image file or directory")
    p.add_argument("-o", "--output", required=True, help="Artifacts/output directory")
    p.add_argument("-V", "--volatility", required=True, help="Path to Volatility3 vol.py")
    p.add_argument("-D", "--drop", default=None, help="Comma-separated plugins to skip")
    p.add_argument("-P", "--plugins", default=None, help="Comma-separated plugins to include")
    p.add_argument("-F", "--format", default="csv", choices=["csv","json"], help="Aggregated features format")
    p.add_argument("-j", "--jobs", type=int, default=max(1, os.cpu_count() or 1), help="Parallel workers")
    p.add_argument("--no-cache", action="store_true", help="Ignore cached plugin outputs")
    args = p.parse_args(argv)

    print("[DEPRECATION] main.py is a compatibility shim. Prefer `volmemlyzer ...` CLI.", file=sys.stderr)

    # Build pipeline
    runner = VolRunner(vol_path=args.volatility, default_renderer="json", default_timeout_s=None)
    registry: ExtractorRegistry = build_registry()
    pipe = Pipeline(runner, registry)

    images = find_images(args.memdump)
    if not images:
        p.error(f"No supported memory images found under: {args.memdump}")

    outdir = args.output
    feat_dir = os.path.join(outdir, "features")
    os.makedirs(feat_dir, exist_ok=True)
    aggregated_rows = []

    enable = set(x.strip() for x in (args.plugins or "").split(",") if x.strip()) or None
    drop = set(x.strip() for x in (args.drop or "").split(",") if x.strip()) or None

    for img in images:
        row = pipe.run_extract_features(
            image_path=img,
            enable=enable,
            drop=drop,
            concurrency=args.jobs,
            artifacts_dir=outdir,
            use_cache=(not args.no_cache),
        )
        flat = flatten_feature_row(asdict(row))
        aggregated_rows.append(flat)

    if args.format == "csv":
        out_path = os.path.join(feat_dir, "output.csv")
        write_csv_aggregated(aggregated_rows, out_path)
    else:
        out_path = os.path.join(feat_dir, "output.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(aggregated_rows, f, ensure_ascii=False, indent=2)

    print(f"[+] Wrote aggregated features → {out_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
