# VolMemLyzer (Volatile Memory Analyzer)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Volatility](https://img.shields.io/badge/Volatility-3.x-black)

**VolMemLyzer** is a modular memory forensics toolkit that wraps **Volatility 3** with three complementary workflows:

1) **Run mode** – ergonomic “Volatility-as-a-service”: run plugins in parallel, cache outputs, and keep artifact naming/dirs predictable for downstream code.  
2) **Extract mode** – registry-driven **feature extraction** from plugin outputs, flattened and stable (CSV/JSON) for ML pipelines.  
3) **Analyze mode** – a stepwise **DFIR triage** workflow (bearings → processes → injections → network → persistence) with clear, Rich-rendered tables.

VolMemLyzer aims to unlock Volatility’s full potential for **researchers** and **analysts** who want frictionless runs inside their own codebases—not just from Volatility’s CLI.

---



## Table of contents

- [Quickstart (Compatibility Shim)](#quickstart-compatibility-shim)
- [Why v3 (at a glance)](#why-v3-at-a-glance)
- [Key capabilities](#key-capabilities)
- [How it fits together](#how-it-fits-together)
- [Requirements](#requirements)
- [Installation](#installation)
- [CLI usage (volmemlyzer)](#cli-usage-volmemlyzer)
  - [Global options](#global-options)
  - [analyze](#analyze)
  - [run](#run)
  - [extract](#extract)
  - [Feature Catalog (Index)](#feature-catalog-index)
  - [list](#list)
- [Python API](#python-api)
- [Artifacts, formats & caching](#artifacts-formats--caching)
- [Performance tips](#performance-tips)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [License](#license)
- [Team Members](#team-members)
- [Acknowledgement](#acknowledgement)


---

## Quickstart (Compatibility Shim)
Heads up about `main.py` (compatibility shim): A small `main.py` is included **only** for backward compatibility with older docs/scripts. It accepts the legacy flags and produces a **single aggregated features file** per run.
If you don't need this legacy entry point, you can remove `main.py`. Keeping it won't cause drift because it calls the library directly.

**Preferred interface:** use the packaged CLI command `volmemlyzer` (see below).  
- CSV → `<outdir>/features/output.csv` (one row per image)  
- JSON → `<outdir>/features/output.json`

### Quickstart with `main.py`

**Process a single dump**
```bash
python main.py \
  -f /path/to/images/IMAGE.mem \
  -o ./out \
  -V /path/to/volatility3/vol.py
```

**Batch a folder of dumps (recursive)**
```bash
python main.py \
  -f /path/to/images/ \
  -o ./out \
  -V /path/to/volatility3/vol.py
```

The tool writes **`out/features/output.csv`** with **one row per image**.

**Speed up triage** by skipping heavy plugins (Not using the --drop or --plugins will result in running all plugins in the plugins.py). example: 
```bash
python main.py -f ./mem -o ./out -V ./volatility3/vol.py \
  -D "dumpfiles,filescan,mftscan,driverscan,mutantscan,modscan,netscan,poolscanner,symlinkscan,callbacks,deskscan,devicetree,driverirp,drivermodule,windowstations"
```

**Legacy options (main.py)**
```text
-f, --memdump     Path to a memory image OR a folder of images          (required)
-o, --output      Output directory for artifacts & features              (required)
-V, --volatility  Path to Volatility3's vol.py                           (required)
-D, --drop        Comma-separated plugin list to skip (e.g., "filescan,modscan")
-P, --plugins     Comma-separated plugin list to include
-F, --format      csv|json (default: csv)
-j, --jobs        Parallel workers
    --no-cache    Ignore cached plugin outputs
```

---
## Why v3 (at a glance)

- **Modular architecture** (Runner → Registry → Pipeline → Analysis/TUI → CLI) so you can import only the pieces you need.  
- **Research-friendly UX**: parallel plugin execution, caching & (where possible) output conversion to avoid reruns, stable artifact naming, and one-row-per-image **FeatureRow** for ML.  
- **DFIR triage workflow**: opinionated but explainable steps with clean tables (thanks to **Rich**).  
- **Stable, flat features**: consistent columns across images, robust null handling, clear `plugin.metric` naming.

---

## Key capabilities

- **Run Volatility 3 plugins** with:
  - parallelism (`-j/--jobs`),
  - per-plugin timeouts,
  - per-run renderer choice,
  - cache reuse with optional conversion to the needed format (see notes below).
  - Complete end-to-end pipeline capable of automatic resolving of the volatility path (Runs as service)

- **Extract features** from selected plugins via a **registry** of extractor functions:
  - flatten to a single **CSV/JSON** file per run (**one row per image**),
  - ML-ready features with consistent naming,
  - dependency-aware scheduling of plugins.

- **Perform an analysis** as a **multi-step** DFIR overview (which can  be outputted in json):
  - 0 Bearings (`windows.info`)
  - 1 Processes (`pslist`+ `psscan`+ `psxview`+ `pstree` + cross-checks)
  - 2 Injections (`malfind`)
  - 3 Network (`netscan`)
  - 4 Persistence (registry/tasks : `scheduled_tasks` + `userassist` +`hivelist/hivescan`)

---

## How it fits together

```
CLI ──► Pipeline ──► VolRunner (vol.py) ──► artifacts/*.json|jsonl|csv|txt
                    │
                    ├─► Extractors (registry) ──► FeatureRow rows → output.csv
                    │
                    └─► OverviewAnalysis (steps) ──► Rich tables / JSON summary
```

- **VolRunner** builds/executes `vol.py` commands and names outputs predictably:  
  `<outdir>/<imagebase>_<plugin>.<ext>` plus `<…>.stderr.txt` on errors.
- **Pipeline** orchestrates parallel runs, caching, and (when supported) format conversion to avoid re-running a plugin just to change formats.
- **ExtractorRegistry** binds a plugin spec (`windows.pslist`, deps, default renderer/timeout) to a Python extractor function. All available    volatility plugins are added by default 
- **OverviewAnalysis** implements the triage steps; **TerminalUI** (Rich) prints academic-style tables with a tasteful left accent bar.

---

## Requirements

- Python **3.9+**
- A local checkout/installation of **Volatility 3**; you will point VolMemLyzer at `vol.py` using `--vol-path` (or `VOL_PATH` env).  
  VolMemLyzer **does not import** Volatility; it **invokes** it as a subprocess.
- Python packages (installed automatically if you use `pip install`):
  - `pandas`, `numpy`, `python-dateutil`, `tqdm`, `rich`

> Tested primarily with Windows images (e.g., `.vmem`, `.raw`, `.dmp`, `.bin`). Other OSes may work where Volatility supports them.

**Zero-friction Volatility path (no --vol-path needed):** 
In v3, if you don’t pass --vol-path, VolMemLyzer automatically resolves Volatility 3 in this order: (1) any explicit hint you provided (--vol-path or the VOL_PATH env var); (2) an importable module in the current environment — it launches python -m volatility3; (3) the vol console script on your PATH; and (4) a few common local vol.py locations. This removes path-hunting and venv confusion, so most users can run one-line commands with sane defaults, while power users can still pin a specific checkout by supplying --vol-path. The result is a cleaner, faster CLI with fewer errors and zero reliance on hard-coded filesystem paths.

---

## Installation

### From PyPI (recommended once published)
```bash
pip install volmemlyzer
# then the CLI is available as:
volmemlyzer --help
```

<!-- you should see the help page like this: ![alt text](image.png) -->

### From source (develop/editable)
```bash
git clone https://github.com/<you>/volmemlyzer.git
cd volmemlyzer
pip install -e .
# or, without packaging:
pip install -r requirements.txt
python -m volmemlyzer.cli --help or volmemlyzer --help
```

<!-- **Environment knobs (optional):**

- `VOL_PATH` – default path to `vol.py`
- `VMY_RENDERER` – default renderer (e.g., `json`)
- `VMY_TIMEOUT` – default timeout in seconds (0 disables)
- `VMY_LOG` – log level (`INFO`, `DEBUG`, …) -->

---
<!-- 
## CLI usage (volmemlyzer)

The packaged CLI exposes **analysis**, **run**, **features**, and **list** subcommands.

### Global options
```
--vol-path PATH     Path to volatility3 vol.py  Optional(env: VOL_PATH) except when no vol.py is detected by volmemlyzer
--renderer NAME     Volatility output renderer format (json/jsonl/csv/pretty/quick/none : **json default**)
--timeout SECONDS   Per-plugin timeout (default : 0 disables)
-j, --jobs N        Parallel workers (default : 0.5 * of available CPUs)
--log-level LEVEL   CRITICAL|ERROR|WARNING|INFO|DEBUG
```

### `analysis`
Run DFIR triage steps over one image. 

```bash
volmemlyzer \
  --vol-path "C:\tools\volatility3\vol.py" --renderer json --timeout 600 -j 4 \
  analysis -i "D:\dumps\host.vmem" -o "D:\dumps\.volmemlyzer" \
  --steps 0,1,2,3,4,5,6 --json "D:\dumps\reports\host.overview.json" \
  --no-cache
```

Options:
- `-i/--image` (required): memory image file
- `-o/--outdir`: artifacts directory (default is created near the image)
- `--steps` (comma list or aliases: `bearings|info`, `processes|proc|ps`, `injections|malfind`, `network|net|netscan`, `persistence|reg|tasks`, `kernel`, `report`)
- `--json`: write the step summary to a JSON file
- `--high-level`: when supported, show only the highest-risk findings
- `--no-cache`: ignore cached plugin outputs

### `run`
Run raw Volatility plugins (parallel, cached, selected renderer).

```bash
volmemlyzer \
  --vol-path /opt/volatility3/vol.py --renderer json -j 6 \
  run -i /cases/win10.raw -o /cases/.volmemlyzer \
  --plugins pslist,pstree,psscan --no-cache
```

Options:
- `-i/--image` (required): memory image file
- `-o/--outdir`: artifacts directory (default near the image)
- `--renderer`: renderer for this run (`json|jsonl|csv|pretty|quick|none`)
- `--plugins`: comma list to include
- `--drop`: comma list to exclude
- `--no-cache`: ignore cached outputs

**Output:**  
The CLI prints the artifacts directory and each plugin’s output path:
```
[+] raw artifacts directory: /cases/.volmemlyzer
  - pslist              → /cases/.volmemlyzer/win10.raw_pslist.json
  - pstree              → /cases/.volmemlyzer/win10.raw_pstree.json
  ...
```

### `features`
Extract features for a single image **or an entire directory (recursively)**, and write a **single aggregated file** (one row per image).

```bash
# Single file → append/update one row in <outdir>/features/output.csv
volmemlyzer \
  --vol-path /opt/volatility3/vol.py -j 4 \
  features -i /cases/win10.raw -o /cases/.volmemlyzer \
  -f csv --plugins pslist,malfind
```


```bash
# Directory (recursive) → creates one file per dump into the <outdir>/features folder 
# Use main.py (Fall-Back Version v2) for aggregating one row per dump into a single output.csv 
volmemlyzer \
  --vol-path /opt/volatility3/vol.py -j 4 \
  features -i /cases/ -o /cases/.volmemlyzer -f csv
```

Options:
- `-i/--image` (required): **file or directory**. Directories are scanned for `*.vmem, *.raw, *.dmp, *.bin` recursively.
- `-o/--outdir`: artifacts directory (default near each image)
- `-f/--format`: `json` or `csv` (required)
- `--plugins`: comma list to **restrict** extraction
- `--drop`: comma list to **exclude**
- `--no-cache`: ignore cached outputs

**Output:**  
Features are written to a **single file** per run under `<outdir>/features/`:  
- CSV → `<outdir>/features/output.csv`  
- JSON → `<outdir>/features/output.json` -->


## CLI usage (volmemlyzer)

To make the CLI easy to grasp, **each mode below shows two examples**:
- **Simple** — the cleanest command that relies on smart defaults (no friction).
- **Complete** — the fully flexible form with all commonly used arguments shown.

The packaged CLI exposes **analyze**, **run**, **extract**, and **list** subcommands.

### Global options
```
--vol-path PATH     Path to 'vol' or 'vol.py'  (optional; auto-detected if omitted, env: VOL_PATH)
--renderer NAME     Volatility renderer: json | jsonl | csv | pretty | quick | none   (default: json)
--timeout SECONDS   Per-plugin timeout in seconds (default: 0 = disabled)
-j, --jobs N        Parallel workers (default: CPU count)
--log-level LEVEL   CRITICAL | ERROR | WARNING | INFO | DEBUG
```

#### Defaults (when omitted)
- **Volatility**: auto-detected (prefer `python -m volatility3`, then `vol` on PATH).
- **Outdir**: `<image_dir>/.volmemlyzer` (created if missing).
- **Renderer**: `json`.
- **Timeout**: `0` (disabled).
- **Jobs**: 1 (No paralellism unless user incerements the jobs).
- **Caching**: enabled (omit `--no-cache` to reuse artifacts).

---

### `analyze`
Run DFIR triage steps over one image.

**Simple (all defaults)**
```bash
volmemlyzer analyze -i "D:\dumps\host.vmem"
```
_Runs steps **0–4** (bearings → persistance), writes artifacts to `D:\dumps\.volmemlyzer`, renderer `json`, no parallelization in plugin runs, caching on._

**Complete (all key flags)**
```bash
# PowerShell line continuations shown with ^
volmemlyzer ^
  --vol-path "C:\tools\volatility3\vol.py" --renderer json --timeout 600 -j 4 ^
  analyze -i "D:\dumps\host.vmem" -o "D:\dumps\.volmemlyzer" ^
  --steps 0,1,2 --json ^
  --no-cache
```
_Runs steps **0–2** (bearings → Injections), all plugin runs have 10 minute timeouts, using four jobs for paralellization, writes artifacts to `D:\dumps\.volmemlyzer`_, _and an output file to`/cases/.volmemlyzer/analysis/win10.raw.json` (outdir inferred), caching off._

Options:
- `-i/--image` (required): memory image file  
- `-o/--outdir`: artifacts directory (default near the image, as shown above)  
- `--steps` (comma list or aliases: `bearings|info`, `processes|proc|ps`, `injections|malfind`, `network|net|netscan`, `persistence|reg|tasks`, `kernel`, `report`)  
- `--json`: write the step summary to a JSON file   
- `--high-level`: when supported, show only the highest-risk findings  
- `--no-cache`: ignore cached plugin outputs  

---

### `run`
Run raw Volatility plugins (parallel, cached, selected renderer).

**Simple (defaults + pick plugins to run)**
```bash
volmemlyzer run -i /cases/win10.raw --plugins pslist,pstree,psscan
```
_Writes artifacts to `/cases/.volmemlyzer`, renderer `json`, no parallelization in plugin runs, caching on._

**Complete (all key flags)**
```bash
volmemlyzer  --vol-path /opt/volatility3/vol.py --renderer json -j 6   run -i /cases/win10.raw -o /cases/.volmemlyzer (--plugins pslist,pstree,psscan or --drop netscan) --no-cache
```
**Note that the drop and plugins should not be used together**

Options:
- `-i/--image` (required): memory image file  
- `-o/--outdir`: artifacts directory (default near the image)  
- `--renderer`: renderer for this run (`json|jsonl|csv|pretty|quick|none`)  
- `--plugins`: comma list to include  
- `--drop`: comma list to exclude  
- `--no-cache`: ignore cached outputs  

**Output:**  
The CLI prints the artifacts directory and each plugin’s output path:
```
[+] raw artifacts directory: /cases/.volmemlyzer
  - pslist              → /cases/.volmemlyzer/win10.raw_pslist.json
  - pstree              → /cases/.volmemlyzer/win10.raw_pstree.json
  ...
```

---

### `extract`
Extract ML-ready features for a single image **or an entire directory (recursive)**.

**Simple (single file; choose output format)**
```bash
volmemlyzer extract -i /cases/win10.raw -f csv
```
_Writes to `/cases/.volmemlyzer/features/win10.raw.csv` (outdir inferred), no parallelization in plugin runs, caching on._

**Simple (directory, recursive)**
```bash
volmemlyzer extract -i /cases/ -f csv
```
_Writes **one features file per dump** under `/cases/.volmemlyzer/features/`._

> Prefer a **single aggregated file** (one row per image)? Use the legacy compatibility shim `python main.py -f /cases -F csv`, which produces `<outdir>/features/output.csv`.

**Complete (all key flags)**
```bash
volmemlyzer   --vol-path /opt/volatility3/vol.py -j 4   extract -i /cases/ -o /cases/.volmemlyzer -f csv  (--plugins pslist,malfind or --drop netscan) --no-cache
```
**Note that the drop and plugins should not be used together**

Options:
- `-i/--image` (required): **file or directory**. Directories are scanned for `*.vmem, *.raw, *.dmp, *.bin` recursively.  
- `-o/--outdir`: artifacts directory (default near the image or directory)  
- `-f/--format`: `json` or `csv` (required)  
- `--plugins`: comma list to **restrict** extraction  
- `--drop`: comma list to **exclude**  
- `--no-cache`: ignore cached outputs  


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

> Need a full column list? See the `FEATURES.md`.

---

### `list`
List available building blocks: **Volatility 3 plugins** and **extractor-backed plugins**.

**Synopsis**
```bash
volmemlyzer list [--vol]/[--registry] [--grep STR] [--max N] [--json]
```

**Does**
- `--vol` Show Volatility 3 plugin names (parsed from `vol.py -h` or `python -m volatility3 -h`).
- `--registry` Show extractor-backed plugins in VolMemLyzer’s registry.
- If neither flag is given, shows **both**.

**Options**
- `--grep STR` Case-insensitive substring filter.
- `--max N` Limit items per list (`0` = unlimited).

**Notes**
- Pass `--vol-path` globally if `vol.py` isn’t on PATH. Exits `0` even when lists are empty.

**Examples**
```bash
# Show both sources (default)
volmemlyzer list

# Only registry extractors
volmemlyzer list --registry

# All available volatility plugins
volmemlyzer list --vol

# Only Volatility plugins, filter all regisrtry-based plugins, cap output
volmemlyzer list --vol --grep "windows.registry" --max 50

```

---

## Python API

> You can import individual layers in notebooks or other tools.

### Build a pipeline
```python
from volmemlyzer.runner import VolRunner
from volmemlyzer.extractor_registry import ExtractorRegistry
from volmemlyzer.plugins import build_registry
from volmemlyzer.pipeline import Pipeline

runner = VolRunner(vol_path="/opt/volatility3/vol.py",
                   default_renderer="json", default_timeout_s=600)
registry: ExtractorRegistry = build_registry()
pipe = Pipeline(runner, registry)
```

### Run plugins programmatically
```python
res = pipe.run_plugin_raw(
    image_path="/cases/win10.raw",
    enable={"pslist", "pstree"},
    renderer="json",
    outdir="/cases/.volmemlyzer",
    concurrency=4,
    use_cache=True,
)
print(res.artifacts["plugins"]["pslist"])  # → path to JSON output
```

### Extract one **FeatureRow**
```python
from dataclasses import asdict

row = pipe.run_extract_features(
    image_path="/cases/win10.raw",
    enable={"pslist", "malfind"},
    concurrency=4,
    artifacts_dir="/cases/.volmemlyzer",
    use_cache=True,
)
print(asdict(row))
```

### Drive the DFIR **analysis** steps
```python
from volmemlyzer.analysis import OverviewAnalysis

analysis = OverviewAnalysis()
summary = analysis.run_steps(
    pipe=pipe,
    image_path="/cases/win10.raw",
    artifacts_dir="/cases/.volmemlyzer",
    steps=[0,1,2,3,4,6],   # bearings → report
    use_cache=True,
    high_level=False,
)
# 'summary' is a dict you can also persist as JSON
```

---

## Artifacts, formats & caching

- **Artifacts directory**: defaults to `<imagebase>.artifacts/` created next to the image (or pass `-o/--outdir`).  
- **File naming**: `<outdir>/<imagebase>_<plugin>.<ext>` and `<…>.stderr.txt` on errors.  
- **Renderers**: `json | jsonl | csv | pretty | quick | none`.  
- **Caching**: If an artifact already exists, VolMemLyzer will reuse it. Where supported, it will convert to the desired format to avoid rerunning the plugin; if not convertible, it will rerun with the requested renderer.  
- **Features**: aggregated into **one file per run** under `<outdir>/features/` → `output.csv` or `output.json` (**one row per image**).

> Tip: Prefer `json` for downstream extractors; it’s the most consistently supported by extractors.

---

## Performance tips

- Increase `-j/--jobs` to match your CPU cores.  
- Use `--no-cache` only when you genuinely need fresh plugin runs.  
- Set `--timeout` to bound misbehaving plugins.

---

## Troubleshooting

- **“Permission denied” writing artifacts**  
  Ensure `-o/--outdir` points to a **directory** (not an existing file). VolMemLyzer will create `<outdir>` and `<outdir>/features/` as needed.

- **vol.py not found / wrong Python**  
  Use `--vol-path` (or `VOL_PATH`) to point at the actual `vol.py`. The Runner uses your current interpreter (`sys.executable`) to launch it.

- **Weird paths on Windows**  
  Quote paths with spaces. Both `C:\` and `\\?\` long paths work if your Python is configured for them.

- **Renderer conversion**  
  If a cached artifact isn’t convertible to the required format, VolMemLyzer will rerun that plugin with the requested renderer.

---

## Roadmap

- More extractors (registry/artifacts/GUI objects)
- Additional kernel and persistence checks in `analysis`
- Optional HTML report backend
- Unit tests and example datasets

---

### License  
This package is using [**Volatility**](https://github.com/volatilityfoundation/volatility) and following their LICENSE. 

## Copyright (c) 2020 and Citation
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (VolMemLyzer), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


For citation VolMemLyzer V1.0.0, V2.0.0, or V3.0.0 in your works and also understanding it completely, you can find below published papers:

```
@INPROCEEDINGS{9452028,
  author={Lashkari, Arash Habibi and Li, Beiqi and Carrier, Tristan Lucas and Kaur, Gurdip},
  booktitle={2021 Reconciling Data Analytics, Automation, Privacy, and Security: A Big Data Challenge (RDAAPS)}, 
  title={VolMemLyzer: Volatile Memory Analyzer for Malware Classification using Feature Engineering}, 
  year={2021},
  volume={},
  number={},
  pages={1-8},
  doi={10.1109/RDAAPS48126.2021.9452028}}
```

### Team Members 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and Project Owner
* [**Yasin Dehfouli:**](https://github.com/YaCnDehfuli) Master Student, Researcher and Developer (Python 3.0 - VolMemLyzer-V3.0.0) 
* [**Abhay Pratap Singh:**](https://github.com/Abhay-Sengar) Undergraduate Student, Researcher and Developer (Python 3.0 - VolMemLyzer-V2.0.0)
* [**Beiqi Li:**](https://github.com/beiqil) Undergraduate Student, Developer (Python 2.7 - VolMemLyzer V1.0.0)
* [**Tristan Carrier:**](https://github.com/TristanCarrier) Master Student, Researcher, and developer (Python 2.7 - VolMemLyzer V1.0.0)
* [**Gurdip Kaur:**](https://www.linkedin.com/in/gurdip-kaur-738062164/) Postdoctorall Fellow Researcher (Python 2.0 - VolMemLyzer V1.0.0)


### Acknowledgement 
This project has been made possible through funding from the Natural Sciences and Engineering Research Council grant from Canada—NSERC (\#RGPIN-2020-04701)—to Arash Habibi Lashkari and Mitacs Global Research Internship (GRI) for the researchers. 
