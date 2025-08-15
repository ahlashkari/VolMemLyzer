# VolMemLyzer (Volatile Memory Analyzer)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-yellow.svg)](https://opensource.org/licenses/)
![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Volatility](https://img.shields.io/badge/Volatility-3.x-black)

VolMemLyzer is a **memory forensics** toolkit that extracts **500+ engineered features** from Windows memory snapshots to help analysts detect malware, rootkits, fileless attacks, and system tampering faster and more reliably. It builds on the **Volatility3** framework and focuses on stable CSV outputs, analyst‑friendly signal naming, and ML‑ready features.

---

## Table of Contents

- [Why VolMemLyzer‑V3](#why-volmemlyzer-v3)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Line Options](#command-line-options)
- [Output](#output)
- [Feature Catalog (Index)](#feature-catalog-index)
- [Performance Tips](#performance-tips)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [License](#license)
- [Citation](#citation)
- [Team](#team)
- [Acknowledgement](#acknowledgement)

---

## Why VolMemLyzer‑V3

VolMemLyzer‑V3 is a major upgrade over V2 (~220 → **500+** features):

- **Broader coverage**: new extractors for consoles, amcache, callbacks, VADs, window stations, bigpools, unloaded modules, virtmap, windows/GUI objects, and registry stores.
- **Richer signals**: ratios, entropies, timestamp sanity checks, cross‑plugin consistency checks, and outlier detectors (e.g., duplicate callback addresses, non‑paged pool bursts, “future” compile times, orphan desktops/windows).
- **Cleaner interface**: consistent `plugin.metric` naming, robust null handling, and CSV with **stable columns across images**.
- **Analyst/ML friendly**: clear provenance for each signal; features map back to their source plugin for explainability (e.g., SHAP/LIME).

---

## How It Works

1. **Run Volatility3 plugins** against a memory image.
2. **Parse JSON** outputs and compute engineered features (counts, ratios, entropies, outlier flags, cross‑checks).
3. **Aggregate to one row per image** and write a CSV (one column per feature).
4. **Optionally skip slow/noisy plugins** to trade feature counts for speed via `--drop`.

Each feature is prefixed with its source plugin (e.g., `pslist.nproc`, `malfind.exec_ratio`) for end‑to‑end traceability.

---

## Installation

> Requires **Python 3.9+** and **Volatility3**.

```bash
# 1) Clone VolMemLyzer
git clone https://github.com/<org>/VolMemLyzer.git
cd VolMemLyzer

# 2) (Recommended) Create & activate a virtual env
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# macOS/Linux
source .venv/bin/activate

# 3) Install Python deps
pip install -r requirements.txt  # or: pip install pandas numpy

# 4) Get Volatility3 (if not already available)
git clone https://github.com/volatilityfoundation/volatility3.git
# optional: pip install -e volatility3/
```

---

## Quick Start

Use the **V3 entrypoint** (`main.py`).

```bash
# Single image
python main.py \
  -f /path/to/images/IMAGE.mem \
  -o ./out \
  -V /path/to/volatility3/vol.py

# Batch a folder of dumps
python main.py \
  -f /path/to/images/ \
  -o ./out \
  -V /path/to/volatility3/vol.py
```

The tool writes **`out/output.csv`** with **one row per image**.

**Speed up triage** by skipping heavy plugins (example):  
```bash
python main.py -f ./mem -o ./out -V ./volatility3/vol.py \
  -D "dumpfiles,filescan,mftscan,driverscan,mutantscan,modscan,netscan,poolscanner,symlinkscan,callbacks,deskscan,devicetree,driverirp,drivermodule,windowstations"
```

---

## Command Line Options

```text
-f, --memdump     Path to a memory image OR a folder of images          (required)
-o, --output      Output directory for CSV and logs                      (required)
-V, --volatility  Path to Volatility3's vol.py                           (required)
-D, --drop        Comma-separated plugin list to skip (e.g., "filescan,modscan")
-h, --help        Show help
```

**Examples**
```bash
# Process a single file
python main.py -f ./mem/host01.mem -o ./out -V ./volatility3/vol.py

# Skip heavy plugins to speed up triage
python main.py -f ./mem -o ./out -V ./volatility3/vol.py \
  -D "filescan,mftscan,driverscan,modscan,netscan"
```

---

## Output

- **File**: `out/output.csv`  
- **Row**: one memory image  
- **Columns**: `mem.name_extn` + `plugin.metric` engineered features

Example feature names:
```
pslist.nproc, dlllist.avg_dllPerProc, handles.nTypeToken,
malfind.exec_ratio, vadinfo.large_commit_count, vadwalk.max_vad_size,
callbacks.distinctModules, bigpools.tagEntropyMean, unloaded.repeated_driver_ratio,
amcache.nonMicrosoftRatio, consoles.histBufOverflow, cmdline.urlInArgs,
virtmap.unused_size_ratio, windows.station_mismatch_count, windowstations.custom_station_count,
registry.hivescan.orphan_offset_count, registry.certificates.disallowed_count
```

Columns are stable across runs; missing data → `null`/`NaN` (safe defaults for pandas/ML tooling).

---

## Feature Catalog (Index)

> The full enumerated list is long. Below is a compact index by category with representative examples. Each bullet maps to multiple concrete CSV columns.

<details>
<summary><b>System & OS</b></summary>

- `info.Is64`, `info.winBuild`, `info.IsPAE`, `info.SystemTime`

</details>

<details>
<summary><b>Processes, Threads & Trees</b></summary>

- `pslist.nproc`, `pslist.avg_threads`, `pslist.wow64_ratio`, `pslist.zombie_count`  
- `pstree.max_depth`, `pstree.avg_branching_factor`, `pstree.cross_session_edges`  
- `threads.nThreads`, `threads.kernel_startaddr_ratio`

</details>

<details>
<summary><b>Modules & DLL Loading</b></summary>

- `dlllist.ndlls`, `dlllist.avg_dllPerProc`, `dlllist.maxLoadDelaySec`  
- `ldrmodules.not_in_load`, `ldrmodules.memOnlyRatio`  
- `modules.nModules`, `modules.largeModuleRatio`

</details>

<details>
<summary><b>Handles (type mix & access patterns)</b></summary>

- `handles.nHandles`, `handles.nTypeToken`, `handles.privHighAccessPct`, `handles.maxHandlesOneProc`

</details>

<details>
<summary><b>Code Injection & VADs</b></summary>

- `malfind.ninjections`, `malfind.RWXratio`, `malfind.maxVADsize`  
- `vadinfo.exec_ratio`, `vadinfo.large_commit_count`, `vadwalk.max_vad_size`

</details>

<details>
<summary><b>Kernel Callbacks, Drivers & Pools</b></summary>

- `callbacks.ncallbacks`, `callbacks.distinctModules`, `callbacks.noSymbol`  
- `bigpools.nAllocs`, `bigpools.nonPagedRatio`, `bigpools.tagEntropyMean`  
- `unloaded.n_entries`, `unloaded.repeated_driver_ratio`

</details>

<details>
<summary><b>Network & Sockets</b></summary>

- `netscan.nConn`, `netscan.publicEstablished`, `netscan.duplicateListen`  
- `netstat.nConn`, `netstat.nEstablished`

</details>

<details>
<summary><b>Registry & Services</b></summary>

- `registry.hivescan.orphan_offset_count`, `registry.hivelist.user_hive_count`  
- `registry.certificates.disallowed_count`, `registry.userassist.avg_focus_count`  
- `svclist.running_services_count`, `svcscan.Start_Auto`

</details>

<details>
<summary><b>Command History & Consoles</b></summary>

- `cmdline.urlInArgs`, `cmdline.scriptExec`, `cmdscan.maxCmds`  
- `consoles.nConhost`, `consoles.histBufOverflow`, `consoles.dumpIoC`

</details>

<details>
<summary><b>GUI Objects (Windows, Desktops, WindowStations)</b></summary>

- `windows.total_window_objs`, `windows.null_title_ratio`, `windows.station_mismatch_count`  
- `deskscan.uniqueDesktops`, `deskscan.session0GuiCount`  
- `winsta.custom_station_count`, `winsta.service_station_ratio`

</details>

<details>
<summary><b>Memory Mapping & Statistics</b></summary>

- `virtmap.unused_size_ratio`, `virtmap.max_region_size_mb`, `virtmap.pagedpool_fragmentation`  
- `statistics.invalid_page_ratio`, `statistics.swapped_page_count`

</details>

<details>
<summary><b>Version Info / PE Metadata</b></summary>

- `verinfo.valid_version_ratio`, `verinfo.dup_base_count`  
- `amcache.future_compile_ratio`, `amcache.nonMicrosoftRatio`

</details>

> Need a full column list? Generate `docs/FEATURES.md` from the CSV header or the feature dictionary at build time.

---

## Performance Tips

- Use `--drop` to skip known heavy plugins for quick triage.
- Run from SSDs; avoid slow network shares for large dumps.
- Pre‑warm Volatility3 caches and ensure symbols are available.
- Pin Python/deps to keep schemas reproducible.

---

## Troubleshooting & FAQ

- **Volatility3 not found** → pass `-V /path/to/volatility3/vol.py`.
- **Many nulls for a plugin** → some fields are OS/build‑specific; extractors return safe nulls to keep schemas stable.
- **Slow on huge dumps** → use `--drop`, run fewer plugins, or parallelize at the image level.
- **Which features matter most?** → use SHAP/LIME on your model; feature names map back to plugins for explanations.

---

## License

GPLv3. See `LICENSE`.

---

## Citation

If you use VolMemLyzer in academic work, please cite the project/publications as appropriate.

```bibtex
@INPROCEEDINGS{9452028,
  author={Lashkari, Arash Habibi and Li, Beiqi and Carrier, Tristan Lucas and Kaur, Gurdip},
  booktitle={2021 Reconciling Data Analytics, Automation, Privacy, and Security: A Big Data Challenge (RDAAPS)}, 
  title={VolMemLyzer: Volatile Memory Analyzer for Malware Classification using Feature Engineering}, 
  year={2021},
  pages={1-8},
  doi={10.1109/RDAAPS48126.2021.9452028}}
```

---

## Team

- **Arash Habibi Lashkari** — Founder and Project Owner  
- **Yassin Dehfuli** — Researcher & Developer (Python 3, VolMemLyzer‑V3)  
- **Abhay Pratap Singh** — Researcher & Developer (Python 3, VolMemLyzer‑V2)  
- **Beiqi Li** — Developer (Python 2.7, VolMemLyzer‑V1)  
- **Tristan Carrier** — Researcher & Developer (Python 2.7, VolMemLyzer‑V1)  
- **Gurdip Kaur** — Postdoctoral Fellow Researcher (VolMemLyzer‑V1)

---

## Acknowledgement

This project has been made possible through funding from the **Natural Sciences and Engineering Research Council of Canada** — NSERC (Grant **#RGPIN‑2020‑04701**) to **Arash Habibi Lashkari** and the **Mitacs Global Research Internship (GRI)**.
