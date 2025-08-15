
<!-- 
<!-- VolMemLyzer (Volatile Memory Analyzer) -->
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/)


### Overview

VolMemLyzer-V3 is a memory forensics tool designed to help analysts and investigators identify and analyze malware, suspicious activities, and potential system compromises by extracting 500+ features from volatile memory dumps. As memory forensics has become increasingly vital for cybersecurity, VolMemLyzer-V3 provides the much-needed tools to automate the extraction of key behavioral features from memory dumps, speeding up investigations and improving detection accuracy. It is built upon the robust Volatility3 Framework, the de facto standard for memory forensics, and offers a comprehensive suite of features aimed at detecting advanced memory-based attacks like fileless malware, rootkits, and kernel exploits.



### What’s New in V3?
V3 is a substantial upgrade over V2 (~220 features → 500+ features):

Broader coverage: added extractors for many plugins (e.g., consoles, amcache, callbacks, vad*, windowstations, bigpools, unloadedmodules, virtmap, windows, registry stores).

Richer signals: ratios, entropies, timestamp sanity checks, cross-plugin consistency checks, and outlier detectors (e.g., duplicate callback addresses, non-paged pool bursts, future compile-times, orphan desktops/windows).

Cleaner interface: consistent naming (plugin.metric), robust null handling, and CSV with stable columns across images.

Analyst-friendly: clear provenance for each signal, easier SHAP/LIME interpretation in ML workflows


### Architecture (How it Works)

Run Volatility3 plugins against a memory image.

Parse each plugin’s JSON and compute engineered features (counts, ratios, entropies, outlier flags, cross-checks).

Aggregate to one row per image and write CSV (one column per feature).

Optionally drop slow/noisy plugins to trade accuracy for speed.

Every feature is prefixed with its source plugin (e.g., pslist.nproc, malfind.exec_ratio) for easy traceability.


### Installation
# 1) Clone
git clone https://github.com/<org>/VolMemLyzer.git
cd VolMemLyzer

# 2) (Recommended) Create & activate venv
python3 -m venv .venv
source .venv/bin/activate     # Windows: .\.venv\Scripts\Activate.ps1

# 3) Install dependencies
pip install -r requirements.txt

# 4) Get Volatility3 (if not already available)
git clone https://github.com/volatilityfoundation/volatility3.git
# optional: pip install -e volatility3/


### Quick Start
# Single image
python VolMemLyzer-V3.py \
  -f /path/to/memdumps/IMAGE.mem \
  -o ./out \
  -V /path/to/volatility3/vol.py

# Batch a folder of dumps
python VolMemLyzer-V3.py \
  -f /path/to/memdumps/ \
  -o ./out \
  -V /path/to/volatility3/vol.py


The tool writes a CSV (e.g., out/volmemlyzer_features.csv) with one row per image.


### Command-Line Options
-f, --filedir      Path to a memory image OR a folder of images
-o, --outdir       Output directory (CSV and logs will be written here)
-V, --volpy        Path to Volatility3's vol.py
-D, --drop         Comma-separated plugin list to skip (e.g., "dumpfiles,filescan,mftscan")
-h, --help         Show help


Examples

# Skip heavy plugins to speed up triage
python VolMemLyzer-V3.py -f ./mem/ -o ./out -V ./volatility3/vol.py \
  -D "dumpfiles,filescan,mftscan"

# Process a single file
python VolMemLyzer-V3.py -f ./mem/host01.mem -o ./out -V ./volatility3/vol.py


### Output Schema

mem.name_extn — image filename (identifier)

<plugin>.<metric> — engineered features

### Examples

pslist.nproc, dlllist.avg_dllPerProc, handles.nTypeToken

malfind.exec_ratio, vadinfo.large_commit_count, vadwalk.max_vad_size

callbacks.distinctModules, bigpools.tagEntropyMean, unloaded.repeated_driver_ratio

amcache.nonMicrosoftRatio, consoles.histBufOverflow, cmdline.urlInArgs

virtmap.unused_size_ratio, windows.station_mismatch_count, windowstations.custom_station_count

registry.hivescan.orphan_offset_count, certs.disallowed_count

All columns are stable across runs; missing data → null/NaN (safe defaults for pandas/ML tooling).


Feature Catalog (500+ columns)

The full, enumerated list is long. Below is a compact index by category with representative examples.
Each bullet corresponds to multiple concrete columns in the CSV.

<details> <summary><b>System & OS</b></summary>

info.Is64, info.winBuild, info.IsPAE

</details> <details> <summary><b>Processes, Threads & Trees</b></summary>

pslist.nproc, pslist.avg_threads, pslist.avg_handlers

pstree.nChildren, pstree.nWow64, pstree.maxHandles

</details> <details> <summary><b>Modules & DLL Loading</b></summary>

dlllist.ndlls, dlllist.avg_dllPerProc, dlllist.avgSize

ldrmodules.not_in_load, ldrmodules.not_in_init, ldrmodules.not_in_mem

modules.nmodules, modules.avgSize, modules.fo_enabled

</details> <details> <summary><b>Handles (type mix & access patterns)</b></summary>

handles.nHandles, handles.distinctHandles, handles.avgHandles_per_proc

Per-type counts: handles.nTypeFile, nTypeToken, nTypeMutant, nTypePort, …

</details> <details> <summary><b>Code Injection & VADs</b></summary>

malfind.ninjections, malfind.uniqueInjections, malfind.commitCharge, malfind.exec_ratio

vadinfo.exec_ratio, vadinfo.large_commit_count, vadinfo.susp_ext_count

vadwalk.total_vads, vadwalk.max_vad_size, vadwalk.std_vad_size

</details> <details> <summary><b>Kernel Callbacks, Drivers & Pools</b></summary>

callbacks.ncallbacks, callbacks.distinctModules, callbacks.noSymbol, callbacks.highAltitude

driverscan.nscan, drivermodule.nModules, ssdt.nModules

bigpools.nAllocs, bigpools.sumBytes, bigpools.tagEntropyMean, bigpools.nonPagedRatio

unloaded.n_entries, unloaded.repeated_driver_ratio

</details> <details> <summary><b>Network & Sockets</b></summary>

netscan.nConn, netscan.nListening, netscan.addrDiversity

netstat.stateCounts.*, netstat.unexpectedAddrCount

</details> <details> <summary><b>Registry & Services</b></summary>

registry.hivescan.orphan_offset_count, hivelist.user_hive_count

registry.certificates.disallowed_count, certs.null_name_root_ratio

svcscan.pct_autostart, svcscan.type_distribution.*

</details> <details> <summary><b>Command History & Consoles</b></summary>

cmdline.urlInArgs, cmdline.scriptExec, cmdline.netPath, cmdline.argsNull

consoles.nConhost, consoles.histBufOverflow, consoles.dumpIoC

cmdscan.nHistories, cmdscan.maxCmds, cmdscan.nonZeroHist

</details> <details> <summary><b>GUI Objects (Windows, Desktops, WindowStations)</b></summary>

windows.total_window_objs, windows.null_title_ratio, windows.station_mismatch_count

deskscan.uniqueDesktops, deskscan.session0GuiCount

windowstations.total_stations, winsta.custom_station_count

</details> <details> <summary><b>Memory Mapping & Statistics</b></summary>

virtmap.nEntries, virtmap.unused_size_ratio, virtmap.pagedpool_fragmentation

statistics.validPages, statistics.swapPages, virtmap.max_region_size_mb

</details> <details> <summary><b>Version Info / PE Metadata</b></summary>

verinfo.valid_version_ratio, verinfo.null_name_ratio, verinfo.dup_base_count

amcache.nonMicrosoftRatio, amcache.future_compile_ratio, amcache.outsideSystem32

</details>

If you’d like a full, enumerated list in a separate doc, consider generating docs/FEATURES.md from the CSV header or the feature dictionary at build time.

### Upgrading from V2

Schema: column names keep the plugin.metric convention; existing pipelines generally work as-is.

New metrics: expect many additional columns (500+ total). Update downstream feature-selection as needed.

Performance: if runtime matters, use --drop to skip heavy plugins (e.g., dumpfiles, filescan, mftscan).


### Performance Tips

Drop heavy plugins for quick triage: --drop "dumpfiles,filescan,mftscan"

Run from SSDs; avoid slow network shares for large dumps.

Pre-warm Volatility3 caches and ensure symbols are available for better module/PE context.

Pin Python & deps via requirements.txt to keep schemas reproducible.

### Troubleshooting & FAQ

Volatility3 not found → pass -V /path/to/volatility3/vol.py.

CSV shows many nulls for a plugin → some fields are OS/build-specific; extractors return safe nulls to keep schemas stable.

Slow on huge dumps → use --drop, run fewer plugins, or parallelize at the image level.

Which features matter most? → use SHAP/LIME on your model; names map back to plugins for analyst-friendly explanations.

### License

This project is licensed under GPLv3. See LICENSE.


### Acknowledgement 
This project has been made possible through funding from the Natural Sciences and Engineering Research Council grant from Canada—NSERC (\#RGPIN-2020-04701)—to Arash Habibi Lashkari and Mitacs Global Research Internship (GRI) for the researchers.  -->