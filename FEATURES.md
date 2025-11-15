# VolMemLyzer Feature Catalog (Semantic)

As requested, this catalog **describes each feature by its** and *intended nature* such as: type, domain, unit, aggregation, and a heuristic interpretation. Use this as documentation—not as statistics about any particular run.

---

## Table of Contents
- [amcache (14)](#amcache)
- [bigpools (8)](#bigpools)
- [callbacks (12)](#callbacks)
- [cmdline (10)](#cmdline)
- [cmdscan (5)](#cmdscan)
- [consoles (7)](#consoles)
- [deskscan (7)](#deskscan)
- [devicetree (10)](#devicetree)
- [dlllist (12)](#dlllist)
- [driverirp (8)](#driverirp)
- [drivermodule (4)](#drivermodule)
- [driverscan (9)](#driverscan)
- [envars (10)](#envars)
- [filescan (8)](#filescan)
- [getsids (10)](#getsids)
- [handles (30)](#handles)
- [hivescan (3)](#hivescan)
- [info (7)](#info)
- [joblinks (5)](#joblinks)
- [ldrmodules (11)](#ldrmodules)
- [malfind (13)](#malfind)
- [mbrscan (9)](#mbrscan)
- [mem (1)](#mem)
- [misc (9)](#misc)
- [modscan (14)](#modscan)
- [modules (9)](#modules)
- [mutantscan (12)](#mutantscan)
- [netscan (19)](#netscan)
- [poolscanner (7)](#poolscanner)
- [privileges (13)](#privileges)
- [pslist (10)](#pslist)
- [psscan (14)](#psscan)
- [pstree (11)](#pstree)
- [psxview (14)](#psxview)
- [registry (40)](#registry)
- [servicesids (8)](#servicesids)
- [shimcache (6)](#shimcache)
- [skeleton_key (5)](#skeleton_key)
- [ssdt (8)](#ssdt)
- [statistics (9)](#statistics)
- [svclist (6)](#svclist)
- [svcscan (14)](#svcscan)
- [symlinkscan (9)](#symlinkscan)
- [threads (4)](#threads)
- [timers (10)](#timers)
- [vadinfo (22)](#vadinfo)
- [vadwalk (6)](#vadwalk)
- [verinfo (9)](#verinfo)
- [virtmap (8)](#virtmap)
- [windows (6)](#windows)
- [winsta (5)](#winsta)


## amcache (14)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `amcache.CompileAfterDump` | string / categorical | — | — | Compile After Dump (amcache). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.InstallAfterDump` | string / categorical | — | — | Install After Dump (amcache). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.LastModifyAfterDump` | string / categorical | — | — | Last Modify After Dump (amcache). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.fileAgeDays_mean` | float (aggregate) | non‑negative | — | File Age Days average (amcache). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.future_compile_ratio` | float (ratio) | [0,1] | ratio | Future compile ratio (amcache). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Derived from PE version metadata / Amcache. |
| `amcache.nDistinctCompanies` | integer (count) | non‑negative | count | Count Distinct Companies (amcache). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.nEntries` | integer (count) | non‑negative | count | Count Entries (amcache). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.nUniqueSHA1` | integer (count) | non‑negative | count | Count Unique S H A1 (amcache). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.nonMicrosoftRatio` | float (ratio) | [0,1] | ratio | Non Microsoft ratio (amcache). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Derived from PE version metadata / Amcache. |
| `amcache.non_ms_driver_entropy` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | milliseconds | Non ms driver entropy (amcache). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.null_install_time_count` | datetime / timestamp | non‑negative | timestamp | Null install time count (amcache). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.outsideSystem32` | string / categorical | — | — | Outside System32 (amcache). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.service_name_entropy` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Service name entropy (amcache). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `amcache.unsigned_product_ratio` | float (ratio) | [0,1] | ratio | Unsigned product ratio (amcache). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Derived from PE version metadata / Amcache. |


## bigpools (8)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `bigpools.avgBytes` | float (size / memory) | non‑negative | bytes | Average Bytes (bigpools). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |
| `bigpools.largeAllocs` | string / categorical | — | — | Large Allocs (bigpools). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |
| `bigpools.maxBytes` | float (size / memory) | non‑negative | bytes | Maximum Bytes (bigpools). Aggregation: extreme across entities. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |
| `bigpools.nAllocs` | integer (count) | non‑negative | count | Count Allocs (bigpools). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |
| `bigpools.nonPagedRatio` | float (ratio) | [0,1] | ratio | Non Paged ratio (bigpools). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel pool allocation patterns. |
| `bigpools.sumBytes` | float (size / memory) | non‑negative | bytes | Sum Bytes (bigpools). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |
| `bigpools.tagEntropyMean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Tag entropy average (bigpools). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |
| `bigpools.tagRare` | string / categorical | — | — | Tag Rare (bigpools). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |


## callbacks (12)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `callbacks.distinctModules` | integer (count) | non‑negative | — | Distinct Modules (callbacks). Aggregation: unique count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.genericKernel` | string / categorical | — | — | Generic Kernel (callbacks). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.maxPerModule` | float (extreme) | — | — | Maximum Per Module (callbacks). Aggregation: extreme across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.nBugCheck` | integer (count) | non‑negative | count | Count Bug Check (callbacks). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.nBugCheckReason` | integer (count) | non‑negative | count | Count Bug Check Reason (callbacks). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.nCreateProc` | integer (count) | non‑negative | count | Count Create Proc (callbacks). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.nCreateThread` | integer (count) | non‑negative | count | Count Create Thread (callbacks). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.nLoadImg` | integer (count) | non‑negative | count | Count Load Img (callbacks). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.nNoDetail` | integer (count) | non‑negative | count | Count No Detail (callbacks). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.nRegisterCB` | integer (count) | non‑negative | count | Count Register C B (callbacks). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.ncallbacks` | integer (count) | non‑negative | count | Ncallbacks (callbacks). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |
| `callbacks.noSymbol` | float (size / memory) | non‑negative | MB | No Symbol (callbacks). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Kernel/user callbacks; watch for duplicates/unknowns. |


## cmdline (10)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `cmdline.argsNull` | string / categorical | — | — | Args Null (cmdline). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `cmdline.avgArgLen` | float (aggregate) | — | — | Average Arg Len (cmdline). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `cmdline.distinctProcesses` | integer (count) | non‑negative | — | Distinct Processes (cmdline). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `cmdline.nLine` | integer (count) | non‑negative | count | Count Line (cmdline). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `cmdline.n_bin` | string / categorical | — | — | Count bin (cmdline). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `cmdline.n_exe` | string / categorical | — | — | Count exe (cmdline). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `cmdline.netPath` | integer (count) | non‑negative | count | Net Path (cmdline). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `cmdline.not_in_C` | integer (count) | non‑negative | count | Not in C (cmdline). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `cmdline.scriptExec` | string / categorical | — | — | Script Exec (cmdline). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Interactive command history / consoles. |
| `cmdline.urlInArgs` | string / categorical | — | — | Url In Args (cmdline). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |


## cmdscan (5)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `cmdscan.appMismatch` | boolean flag | — | — | App Mismatch (cmdscan). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Interactive command history / consoles. |
| `cmdscan.cmdCountRatio` | float (ratio) | [0,1] | ratio | Cmd Count ratio (cmdscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Interactive command history / consoles. |
| `cmdscan.maxCmds` | float (extreme) | — | — | Maximum Cmds (cmdscan). Aggregation: extreme across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `cmdscan.nHistories` | integer (count) | non‑negative | count | Count Histories (cmdscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `cmdscan.nonZeroHist` | integer (count) | non‑negative | count | Non Zero Hist (cmdscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |


## consoles (7)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `consoles.avgProcPerConsole` | float (aggregate) | — | — | Average Proc Per Console (consoles). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `consoles.dumpIoC` | boolean flag | — | — | Dump Io C (consoles). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Interactive command history / consoles. |
| `consoles.emptyHistoryRatio` | float (ratio) | [0,1] | ratio | Empty History ratio (consoles). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Interactive command history / consoles. |
| `consoles.histBufOverflow` | boolean flag | — | — | Hist Buf Overflow (consoles). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Interactive command history / consoles. |
| `consoles.maxProcPerConsole` | float (extreme) | — | — | Maximum Proc Per Console (consoles). Aggregation: extreme across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `consoles.nConhost` | integer (count) | non‑negative | count | Count Conhost (consoles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Interactive command history / consoles. |
| `consoles.titleSuspicious` | boolean flag | — | — | Title Suspicious (consoles). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Interactive command history / consoles. |


## deskscan (7)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `deskscan.nOrphanDesktops` | boolean flag | non‑negative | count | Count Orphan Desktops (deskscan). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: GUI objects (windows/desktops/window stations). |
| `deskscan.nondefaultdesktops` | integer (count) | non‑negative | count | Nondefaultdesktops (deskscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |
| `deskscan.session0GuiCount` | integer (count) | non‑negative | count | Session0 Gui Count (deskscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |
| `deskscan.topProcDesktopRatio` | float (ratio) | [0,1] | ratio | Top Proc Desktop ratio (deskscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: GUI objects (windows/desktops/window stations). |
| `deskscan.totalEntries` | integer (count) | non‑negative | count | Total Entries (deskscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |
| `deskscan.uniqueDesktops` | integer (count) | non‑negative | — | Unique Desktops (deskscan). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |
| `deskscan.uniqueWinStations` | integer (count) | non‑negative | — | Unique Win Stations (deskscan). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |


## devicetree (10)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `devicetree.attToNullDriver` | string / categorical | — | — | Att To Null Driver (devicetree). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `devicetree.avgChildrenPerDRV` | float (aggregate) | — | — | Average Children Per D R V (devicetree). Aggregation: average across entities. Interpretation: Context-dependent. |
| `devicetree.busExtenderRatio` | float (ratio) | [0,1] | ratio | Bus Extender ratio (devicetree). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `devicetree.diskDevRatio` | float (ratio) | [0,1] | ratio | Disk Dev ratio (devicetree). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `devicetree.driverEntropy` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Driver entropy (devicetree). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `devicetree.maxDepth` | float (extreme) | — | — | Maximum Depth (devicetree). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `devicetree.nTypeNotDRV` | integer (count) | non‑negative | count | Count Type Not D R V (devicetree). Aggregation: count across entities. Interpretation: Context-dependent. |
| `devicetree.ndevice` | integer (count) | non‑negative | count | Ndevice (devicetree). Aggregation: count across entities. Interpretation: Context-dependent. |
| `devicetree.nonDrvAttachRatio` | float (ratio) | [0,1] | ratio | Non Drv Attach ratio (devicetree). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `devicetree.uniqueDrivers` | integer (count) | non‑negative | — | Unique Drivers (devicetree). Aggregation: unique count across entities. Interpretation: Context-dependent. |


## dlllist (12)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `dlllist.avgSize` | float (size / memory) | non‑negative | — | Average Size (dlllist). Aggregation: average across entities. Interpretation: Context-dependent. |
| `dlllist.avg_dllPerProc` | float (aggregate) | — | — | Average dll Per Proc (dlllist). Aggregation: average across entities. Interpretation: Context-dependent. |
| `dlllist.globalSharedDlls` | string / categorical | — | — | Global Shared Dlls (dlllist). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `dlllist.hugeDllCount` | integer (count) | non‑negative | count | Huge Dll Count (dlllist). Aggregation: count across entities. Interpretation: Context-dependent. |
| `dlllist.maxLoadDelaySec` | float (extreme) | non‑negative | seconds | Maximum Load Delay Sec (dlllist). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `dlllist.ndlls` | integer (count) | non‑negative | count | Ndlls (dlllist). Aggregation: count across entities. Interpretation: Context-dependent. |
| `dlllist.nonSystemPathRatio` | float (ratio) | [0,1] | ratio | Non System Path ratio (dlllist). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `dlllist.nproc_dll` | integer (count) | non‑negative | count | Nproc dll (dlllist). Aggregation: count across entities. Interpretation: Context-dependent. |
| `dlllist.outfile` | string / categorical | — | — | Outfile (dlllist). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `dlllist.smallDllCount` | integer (count) | non‑negative | count | Small Dll Count (dlllist). Aggregation: count across entities. Interpretation: Context-dependent. |
| `dlllist.tempDirDlls` | string / categorical | — | — | Temp Dir Dlls (dlllist). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `dlllist.uniqueDllRatio` | float (ratio) | [0,1] | ratio | Unique Dll ratio (dlllist). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |


## driverirp (8)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `driverirp.entropyIRPTypes` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Entropy I R P Types (driverirp). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `driverirp.invalidHandlerRatio` | float (ratio) | [0,1] | ratio | Invalid Handler ratio (driverirp). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `driverirp.nIRP` | integer (count) | non‑negative | count | Count I R P (driverirp). Aggregation: count across entities. Interpretation: Context-dependent. |
| `driverirp.nModules` | integer (count) | non‑negative | count | Count Modules (driverirp). Aggregation: count across entities. Interpretation: Context-dependent. |
| `driverirp.nSymbols` | float (size / memory) | non‑negative | MB | Count Symbols (driverirp). Aggregation: count across entities. Interpretation: Context-dependent. |
| `driverirp.n_diff_add` | string / categorical | — | — | Count diff add (driverirp). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `driverirp.nullSymbolCount` | float (size / memory) | non‑negative | MB | Null Symbol Count (driverirp). Aggregation: count across entities. Interpretation: Context-dependent. |
| `driverirp.sameAddressMultiDriver` | string / categorical | — | — | Same Address Multi Driver (driverirp). Aggregation: image-level aggregate. Interpretation: Context-dependent. |


## drivermodule (4)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `drivermodule.altNameMismatch` | boolean flag | — | — | Alt Name Mismatch (drivermodule). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `drivermodule.knownExceptionRatio` | float (ratio) | [0,1] | ratio | Known Exception ratio (drivermodule). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `drivermodule.nModules` | integer (count) | non‑negative | count | Count Modules (drivermodule). Aggregation: count across entities. Interpretation: Context-dependent. |
| `drivermodule.noServiceKeyCount` | integer (count) | non‑negative | count | No Service Key Count (drivermodule). Aggregation: count across entities. Interpretation: Context-dependent. |


## driverscan (9)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `driverscan.avgSize` | float (size / memory) | non‑negative | — | Average Size (driverscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `driverscan.duplicateStartAddr` | string / categorical | — | — | Duplicate Start Addr (driverscan). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `driverscan.largeDriverCount` | integer (count) | non‑negative | count | Large Driver Count (driverscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `driverscan.miniDriverCount` | integer (count) | non‑negative | count | Mini Driver Count (driverscan). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `driverscan.nameEntropyMean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Name entropy average (driverscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `driverscan.nonAsciiNameCount` | integer (count) | non‑negative | count | Non Ascii Name Count (driverscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `driverscan.nscan` | integer (count) | non‑negative | count | Nscan (driverscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `driverscan.nullServiceKeyRatio` | float (ratio) | [0,1] | ratio | Null Service Key ratio (driverscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `driverscan.sizeZeroCount` | float (size / memory) | non‑negative | count | Size Zero Count (driverscan). Aggregation: count across entities. Interpretation: Context-dependent. |


## envars (10)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `envars.cmdExeComSpecMismatch` | boolean flag | non‑negative | milliseconds | Cmd Exe Com Spec Mismatch (envars). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Interactive command history / consoles. |
| `envars.dupBlockCount` | integer (count) | non‑negative | count | Dup Block Count (envars). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `envars.has_PSModulePathUser` | string / categorical | — | — | Has P S Module Path User (envars). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `envars.nBlock` | integer (count) | non‑negative | count | Count Block (envars). Aggregation: count across entities. Interpretation: Context-dependent. |
| `envars.nProc` | integer (count) | non‑negative | count | Count Proc (envars). Aggregation: count across entities. Interpretation: Context-dependent. |
| `envars.nValue` | integer (count) | non‑negative | count | Count Value (envars). Aggregation: count across entities. Interpretation: Context-dependent. |
| `envars.nVars` | integer (count) | non‑negative | count | Count Vars (envars). Aggregation: count across entities. Interpretation: Context-dependent. |
| `envars.n_diff_var` | string / categorical | — | — | Count diff var (envars). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `envars.pathEntropyMean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Path entropy average (envars). Aggregation: average across entities. Interpretation: Context-dependent. |
| `envars.tempPathOutsideWinRatio` | float (ratio) | [0,1] | ratio | Temp Path Outside Win ratio (envars). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |


## filescan (8)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `filescan.adsCount` | integer (count) | non‑negative | count | Ads Count (filescan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `filescan.metaFileRatio` | float (ratio) | [0,1] | ratio | Meta File ratio (filescan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `filescan.nFiles` | integer (count) | non‑negative | count | Count Files (filescan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `filescan.n_diff_file` | string / categorical | — | — | Count diff file (filescan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `filescan.nameEntropyMean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Name entropy average (filescan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `filescan.nonAsciiNameCount` | integer (count) | non‑negative | count | Non Ascii Name Count (filescan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `filescan.sysUnderSystem32Ratio` | float (ratio) | [0,1] | ratio | Sys Under System32 ratio (filescan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `filescan.userProfileFileCount` | integer (count) | non‑negative | count | User Profile File Count (filescan). Aggregation: count across entities. Interpretation: Context-dependent. |


## getsids (10)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `getsids.adminSidInUserPID` | float (extreme) | — | — | Admin Sid In User P I D (getsids). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `getsids.avgSIDperProc` | float (aggregate) | — | — | Average S I Dper Proc (getsids). Aggregation: average per-proc. Interpretation: Context-dependent. |
| `getsids.foreignAuthorityPct` | float (ratio) | [0,1] | ratio | Foreign Authority percentage (getsids). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `getsids.maxSidsSingleProc` | float (extreme) | — | — | Maximum Sids Single Proc (getsids). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `getsids.nDiffName` | integer (count) | non‑negative | count | Count Diff Name (getsids). Aggregation: count across entities. Interpretation: Context-dependent. |
| `getsids.nProc` | integer (count) | non‑negative | count | Count Proc (getsids). Aggregation: count across entities. Interpretation: Context-dependent. |
| `getsids.nSIDcalls` | integer (count) | non‑negative | count | Count S I Dcalls (getsids). Aggregation: count across entities. Interpretation: Context-dependent. |
| `getsids.n_diff_sids` | string / categorical | — | — | Count diff sids (getsids). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `getsids.nullNameRatio` | float (ratio) | [0,1] | ratio | Null Name ratio (getsids). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `getsids.serviceSidCount` | integer (count) | non‑negative | count | Service Sid Count (getsids). Aggregation: count across entities. Interpretation: Context-dependent. |


## handles (30)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `handles.avgHandles_per_proc` | float (aggregate) | — | — | Average Handles per proc (handles). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.distinctHandles` | integer (count) | non‑negative | — | Distinct Handles (handles). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.handleEntropy` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Handle entropy (handles). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.maxHandlesOneProc` | float (extreme) | — | — | Maximum Handles One Proc (handles). Aggregation: extreme across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nAccess` | integer (count) | non‑negative | count | Count Access (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nHandles` | integer (count) | non‑negative | count | Count Handles (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeDesk` | integer (count) | non‑negative | count | Count Type Desk (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeDir` | integer (count) | non‑negative | count | Count Type Dir (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeEvent` | integer (count) | non‑negative | count | Count Type Event (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeFile` | integer (count) | non‑negative | count | Count Type File (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeIO` | integer (count) | non‑negative | count | Count Type I O (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeJob` | integer (count) | non‑negative | count | Count Type Job (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeKey` | integer (count) | non‑negative | count | Count Type Key (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeKeyEvent` | integer (count) | non‑negative | count | Count Type Key Event (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeMutant` | integer (count) | non‑negative | count | Count Type Mutant (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypePort` | integer (count) | non‑negative | count | Count Type Port (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeProc` | integer (count) | non‑negative | count | Count Type Proc (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeSec` | integer (count) | non‑negative | seconds | Count Type Sec (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeSemaph` | integer (count) | non‑negative | count | Count Type Semaph (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeSymLink` | integer (count) | non‑negative | count | Count Type Sym Link (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeThread` | integer (count) | non‑negative | count | Count Type Thread (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeTimer` | datetime / timestamp | non‑negative | timestamp | Count Type Timer (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeToken` | integer (count) | non‑negative | count | Count Type Token (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeWaitPort` | integer (count) | non‑negative | count | Count Type Wait Port (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nTypeWinSta` | integer (count) | non‑negative | count | Count Type Win Sta (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. GUI objects (windows/desktops/window stations). |
| `handles.nTypeWmi` | integer (count) | non‑negative | count | Count Type Wmi (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nproc` | integer (count) | non‑negative | count | Nproc (handles). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `handles.nullNameFileRatio` | float (ratio) | [0,1] | ratio | Null Name File ratio (handles). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Kernel object handles distribution/privilege mix. |
| `handles.privHighAccessPct` | float (ratio) | [0,1] | ratio | Priv High Access percentage (handles). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Kernel object handles distribution/privilege mix. |
| `handles.tokenHandlesUserProcs` | string / categorical | — | — | Token Handles User Procs (handles). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |


## hivescan (3)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `hivescan.offset_entropy` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Offset entropy (hivescan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `hivescan.orphan_offset_count` | boolean flag | non‑negative | count | Orphan offset count (hivescan). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `hivescan.too_high_offset_ratio` | float (ratio) | [0,1] | ratio | Too high offset ratio (hivescan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |


## info (7)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `info.Is64` | string / categorical | — | — | Is64 (info). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `info.IsPAE` | string / categorical | — | — | Is P A E (info). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `info.SystemTime` | datetime / timestamp | timestamp | timestamp | System Time (info). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `info.kbuildStr` | float (size / memory) | non‑negative | KB | Kbuild Str (info). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `info.layerdepth` | string / categorical | — | — | Layerdepth (info). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `info.npro` | integer (count) | non‑negative | count | Npro (info). Aggregation: count across entities. Interpretation: Context-dependent. |
| `info.winBuild` | string / categorical | — | — | Win Build (info). Aggregation: image-level aggregate. Interpretation: Context-dependent. |


## joblinks (5)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `joblinks.highActiveSkew` | string / categorical | — | — | High Active Skew (joblinks). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `joblinks.linkedProcRatio` | float (ratio) | [0,1] | ratio | Linked Proc ratio (joblinks). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `joblinks.nJobObjs` | integer (count) | non‑negative | count | Count Job Objs (joblinks). Aggregation: count across entities. Interpretation: Context-dependent. |
| `joblinks.nameEntropyMean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Name entropy average (joblinks). Aggregation: average across entities. Interpretation: Context-dependent. |
| `joblinks.sessMismatchCount` | boolean flag | non‑negative | count | Sess Mismatch Count (joblinks). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |


## ldrmodules (11)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `ldrmodules.memOnlyRatio` | float (ratio) | [0,1] | ratio | Mem Only ratio (ldrmodules). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `ldrmodules.nonDllPct` | float (ratio) | [0,1] | ratio | Non Dll percentage (ldrmodules). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `ldrmodules.not_in_init` | integer (count) | non‑negative | count | Not in init (ldrmodules). Aggregation: count across entities. Interpretation: Context-dependent. |
| `ldrmodules.not_in_init_avg` | integer (count) | non‑negative | count | Not in init average (ldrmodules). Aggregation: average across entities. Interpretation: Context-dependent. |
| `ldrmodules.not_in_load` | integer (count) | non‑negative | count | Not in load (ldrmodules). Aggregation: count across entities. Interpretation: Context-dependent. |
| `ldrmodules.not_in_load_avg` | integer (count) | non‑negative | count | Not in load average (ldrmodules). Aggregation: average across entities. Interpretation: Context-dependent. |
| `ldrmodules.not_in_mem` | integer (count) | non‑negative | count | Not in mem (ldrmodules). Aggregation: count across entities. Interpretation: Context-dependent. |
| `ldrmodules.not_in_mem_avg` | integer (count) | non‑negative | count | Not in mem average (ldrmodules). Aggregation: average across entities. Interpretation: Context-dependent. |
| `ldrmodules.nproc` | integer (count) | non‑negative | count | Nproc (ldrmodules). Aggregation: count across entities. Interpretation: Context-dependent. |
| `ldrmodules.suspPathCount` | integer (count) | non‑negative | count | Susp Path Count (ldrmodules). Aggregation: count across entities. Interpretation: Context-dependent. |
| `ldrmodules.total` | integer (count) | non‑negative | count | Total (ldrmodules). Aggregation: count across entities. Interpretation: Context-dependent. |


## malfind (13)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `malfind.RWXratio` | float (ratio) | [0,1] | ratio | R W Xratio (malfind). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `malfind.aveVPN_diff` | string / categorical | — | — | Ave V P count diff (malfind). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `malfind.avgInjec_per_proc` | float (aggregate) | — | — | Average Injec per proc (malfind). Aggregation: average across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `malfind.commitCharge` | float (size / memory) | — | — | Commit Charge (malfind). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `malfind.maxVADsize` | float (size / memory) | non‑negative | — | Maximum V A Dsize (malfind). Aggregation: extreme across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Virtual Address Descriptor / memory regions. |
| `malfind.meanVADsize` | float (size / memory) | non‑negative | — | Average V A Dsize (malfind). Aggregation: average across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Virtual Address Descriptor / memory regions. |
| `malfind.ninjections` | integer (count) | non‑negative | count | Ninjections (malfind). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `malfind.nullPct` | float (ratio) | [0,1] | ratio | Null percentage (malfind). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `malfind.protection` | string / categorical | — | — | Protection (malfind). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `malfind.shellJumpRatio` | float (ratio) | [0,1] | ratio | Shell Jump ratio (malfind). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `malfind.tagsVad` | string / categorical | — | — | Tags Vad (malfind). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Virtual Address Descriptor / memory regions. |
| `malfind.tagsVads` | string / categorical | — | — | Tags Vads (malfind). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Virtual Address Descriptor / memory regions. |
| `malfind.uniqueInjections` | integer (count) | non‑negative | — | Unique Injections (malfind). Aggregation: unique count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |


## mbrscan (9)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `mbrscan.avg_partition_size_mb` | float (size / memory) | non‑negative | MB | Average partition size mb (mbrscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `mbrscan.avg_partitions_per_mbr` | float (size / memory) | non‑negative | MB | Average partitions per mbr (mbrscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `mbrscan.bootable_partitions` | float (size / memory) | non‑negative | MB | Bootable partitions (mbrscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `mbrscan.nDiskSig` | float (size / memory) | non‑negative | MB | Count Disk Sig (mbrscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `mbrscan.nMBRentries` | float (size / memory) | non‑negative | MB | Count M B Rentries (mbrscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `mbrscan.nPartType` | float (size / memory) | non‑negative | MB | Count Part Type (mbrscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `mbrscan.nUniqueBootcode` | float (size / memory) | non‑negative | MB | Count Unique Bootcode (mbrscan). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `mbrscan.null_partition_size_pct` | float (ratio) | [0,1] | MB | Null partition size percentage (mbrscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `mbrscan.partition_type_diversity` | float (size / memory) | non‑negative | MB | Partition type diversity (mbrscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |


## mem (1)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `mem.name_extn` | integer (count) | non‑negative | count | Name extn (mem). Aggregation: count across entities. Interpretation: Context-dependent. |


## misc (9)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `avgImportsPerProc` | float (aggregate) | — | — | Average Imports Per Proc. Aggregation: average across entities. Interpretation: Context-dependent. |
| `boundRatio` | float (ratio) | [0,1] | ratio | Bound ratio. Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `cryptoCount` | integer (count) | non‑negative | count | Crypto Count. Aggregation: count across entities. Interpretation: Context-dependent. |
| `funcNameEntropyMean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Func Name entropy average. Aggregation: average across entities. Interpretation: Context-dependent. |
| `nProcesses` | integer (count) | non‑negative | count | Count Processes. Aggregation: count across entities. Interpretation: Context-dependent. |
| `netApiCount` | integer (count) | non‑negative | count | Net Api Count. Aggregation: count across entities. Interpretation: Context-dependent. |
| `syscallRatio` | float (ratio) | [0,1] | ratio | Syscall ratio. Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `totalEntries` | integer (count) | non‑negative | count | Total Entries. Aggregation: count across entities. Interpretation: Context-dependent. |
| `wow64LibCount` | integer (count) | non‑negative | count | Wow64 Lib Count. Aggregation: count across entities. Interpretation: Context-dependent. Notes: 32‑bit process on 64‑bit Windows context. |


## modscan (14)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `modscan.AvgSize` | float (size / memory) | non‑negative | — | Average Size (modscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `modscan.FO_Enabled` | string / categorical | — | — | F O Enabled (modscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `modscan.MeanChildExist` | float (aggregate) | — | — | Average Child Exist (modscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `modscan.dupBaseCnt` | string / categorical | non‑negative | seconds | Dup Base Cnt (modscan). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `modscan.nDLL` | integer (count) | non‑negative | count | Count D L L (modscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `modscan.nEXE` | integer (count) | non‑negative | count | Count E X E (modscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `modscan.nMod` | integer (count) | non‑negative | count | Count Mod (modscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `modscan.nOthers` | integer (count) | non‑negative | count | Count Others (modscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `modscan.nSYS` | integer (count) | non‑negative | count | Count S Y S (modscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `modscan.nUniqueExt` | integer (count) | non‑negative | count | Count Unique Ext (modscan). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `modscan.nameEntropyMean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Name entropy average (modscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `modscan.offPathCount` | integer (count) | non‑negative | count | Off Path Count (modscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `modscan.sizeStddev` | float (size / memory) | non‑negative | — | Size standard deviation (modscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `modscan.unknownExtCount` | integer (count) | non‑negative | count | Unknown Ext Count (modscan). Aggregation: count across entities. Interpretation: Context-dependent. |


## modules (9)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `modules.avgSizeKB` | float (size / memory) | non‑negative | KB | Average Size K B (modules). Aggregation: average across entities. Interpretation: Context-dependent. |
| `modules.driverStoreRatio` | float (ratio) | [0,1] | ratio | Driver Store ratio (modules). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `modules.fileOutEnabled` | string / categorical | — | — | File Out Enabled (modules). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `modules.largeModuleRatio` | float (ratio) | [0,1] | ratio | Large Module ratio (modules). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `modules.nModules` | integer (count) | non‑negative | count | Count Modules (modules). Aggregation: count across entities. Interpretation: Context-dependent. |
| `modules.nameEntropyMean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Name entropy average (modules). Aggregation: average across entities. Interpretation: Context-dependent. |
| `modules.nonAsciiNameCount` | integer (count) | non‑negative | count | Non Ascii Name Count (modules). Aggregation: count across entities. Interpretation: Context-dependent. |
| `modules.sharedBaseAddrCount` | integer (count) | non‑negative | count | Shared Base Addr Count (modules). Aggregation: count across entities. Interpretation: Context-dependent. |
| `modules.userPathCount` | integer (count) | non‑negative | count | User Path Count (modules). Aggregation: count across entities. Interpretation: Context-dependent. |


## mutantscan (12)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `mutantscan.avgNameLen` | float (aggregate) | — | — | Average Name Len (mutantscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `mutantscan.dbwinCount` | integer (count) | non‑negative | count | Dbwin Count (mutantscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `mutantscan.duplicateNameRatio` | float (ratio) | [0,1] | ratio | Duplicate Name ratio (mutantscan). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `mutantscan.nMutantObjects` | integer (count) | non‑negative | count | Count Mutant Objects (mutantscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `mutantscan.nNamedMutant` | integer (count) | non‑negative | count | Count Named Mutant (mutantscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `mutantscan.nameEntropyMean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Name entropy average (mutantscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `mutantscan.nonAsciiNameCount` | integer (count) | non‑negative | count | Non Ascii Name Count (mutantscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `mutantscan.nullNameCount` | integer (count) | non‑negative | count | Null Name Count (mutantscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `mutantscan.nullOffsetCount` | integer (count) | non‑negative | count | Null Offset Count (mutantscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `mutantscan.officeClickRunCount` | integer (count) | non‑negative | count | Office Click Run Count (mutantscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `mutantscan.smPrefixRatio` | float (ratio) | [0,1] | ratio | Sm Prefix ratio (mutantscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `mutantscan.wilErrorCount` | integer (count) | non‑negative | count | Wil Error Count (mutantscan). Aggregation: count across entities. Interpretation: Context-dependent. |


## netscan (19)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `netscan.Proto_TCPv4` | integer (count) | non‑negative | count | Proto T C Pv4 (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.Proto_TCPv6` | integer (count) | non‑negative | count | Proto T C Pv6 (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.Proto_UDPv4` | integer (count) | non‑negative | count | Proto U D Pv4 (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.Proto_UDPv6` | integer (count) | non‑negative | count | Proto U D Pv6 (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.closedButUnowned` | integer (count) | non‑negative | count | Closed But Unowned (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.duplicateListen` | integer (count) | non‑negative | count | Duplicate Listen (netscan). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Network connections/sockets. |
| `netscan.highPortListenCount` | integer (count) | non‑negative | count | High Port Listen Count (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.ipv6Ratio` | float (ratio) | [0,1] | ratio | Ipv6 ratio (netscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Network connections/sockets. |
| `netscan.loopbackPairCount` | integer (count) | non‑negative | count | Loopback Pair Count (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.nConn` | integer (count) | non‑negative | count | Count Conn (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.nDistinctForeignAdd` | integer (count) | non‑negative | count | Count Distinct Foreign Add (netscan). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.nDistinctForeignPort` | integer (count) | non‑negative | count | Count Distinct Foreign Port (netscan). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.nDistinctLocalAddr` | integer (count) | non‑negative | count | Count Distinct Local Addr (netscan). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.nDistinctLocalPort` | integer (count) | non‑negative | count | Count Distinct Local Port (netscan). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.nDistinctProc` | integer (count) | non‑negative | count | Count Distinct Proc (netscan). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.nListening` | integer (count) | non‑negative | count | Count Listening (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.nOwners` | integer (count) | non‑negative | count | Count Owners (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |
| `netscan.publicEstablished` | integer (count) | non‑negative | count | Public Established (netscan). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Network connections/sockets. |
| `netscan.unownedConnCount` | integer (count) | non‑negative | count | Unowned Conn Count (netscan). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Network connections/sockets. |


## poolscanner (7)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `poolscanner.driver_obj_ratio` | float (ratio) | [0,1] | ratio | Driver obj ratio (poolscanner). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Kernel pool allocation patterns. |
| `poolscanner.file_obj_ratio` | float (ratio) | [0,1] | ratio | File obj ratio (poolscanner). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Kernel pool allocation patterns. |
| `poolscanner.nPool` | integer (count) | non‑negative | count | Count Pool (poolscanner). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |
| `poolscanner.nUniquePool` | integer (count) | non‑negative | count | Count Unique Pool (poolscanner). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |
| `poolscanner.null_name_ratio` | float (ratio) | [0,1] | ratio | Null name ratio (poolscanner). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Kernel pool allocation patterns. |
| `poolscanner.tag_entropy_mean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Tag entropy average (poolscanner). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |
| `poolscanner.top_tag` | string / categorical | — | — | Top tag (poolscanner). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |


## privileges (13)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `privileges.highPrivProcRatio` | float (ratio) | [0,1] | ratio | High Priv Proc ratio (privileges). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `privileges.maxPrivsInProc` | float (extreme) | — | — | Maximum Privs In Proc (privileges). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `privileges.nAtt_D` | integer (count) | non‑negative | count | Count Att D (privileges). Aggregation: count across entities. Interpretation: Context-dependent. |
| `privileges.nAtt_NaN` | integer (count) | non‑negative | count | Count Att Na count (privileges). Aggregation: count across entities. Interpretation: Context-dependent. |
| `privileges.nAtt_P` | integer (count) | non‑negative | count | Count Att P (privileges). Aggregation: count across entities. Interpretation: Context-dependent. |
| `privileges.nAtt_PE` | integer (count) | non‑negative | count | Count Att P E (privileges). Aggregation: count across entities. Interpretation: Context-dependent. |
| `privileges.nAtt_PED` | integer (count) | non‑negative | count | Count Att P E D (privileges). Aggregation: count across entities. Interpretation: Context-dependent. |
| `privileges.nPID` | integer (count) | non‑negative | count | Count P I D (privileges). Aggregation: count across entities. Interpretation: Context-dependent. |
| `privileges.nProcess` | integer (count) | non‑negative | count | Count Process (privileges). Aggregation: count across entities. Interpretation: Context-dependent. |
| `privileges.nTotal` | integer (count) | non‑negative | count | Count Total (privileges). Aggregation: count across entities. Interpretation: Context-dependent. |
| `privileges.nUniquePrivilege` | integer (count) | non‑negative | count | Count Unique Privilege (privileges). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `privileges.nullNameRatio` | float (ratio) | [0,1] | ratio | Null Name ratio (privileges). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `privileges.rarePrivCount` | integer (count) | non‑negative | count | Rare Priv Count (privileges). Aggregation: count across entities. Interpretation: Context-dependent. |


## pslist (10)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `pslist.avg_handlers` | float (aggregate) | — | — | Average handlers (pslist). Aggregation: average across entities. Interpretation: Context-dependent. |
| `pslist.avg_threads` | float (aggregate) | — | — | Average threads (pslist). Aggregation: average across entities. Interpretation: Context-dependent. |
| `pslist.nppid` | integer (count) | non‑negative | count | Nppid (pslist). Aggregation: count across entities. Interpretation: Context-dependent. |
| `pslist.nproc` | integer (count) | non‑negative | count | Nproc (pslist). Aggregation: count across entities. Interpretation: Context-dependent. |
| `pslist.nprocs64bit` | integer (count) | non‑negative | count | Nprocs64bit (pslist). Aggregation: count across entities. Interpretation: Context-dependent. |
| `pslist.outfile` | string / categorical | — | — | Outfile (pslist). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `pslist.restricted_handles_pct` | float (ratio) | [0,1] | ratio | Restricted handles percentage (pslist). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Kernel object handles distribution/privilege mix. |
| `pslist.user_path_ratio` | float (ratio) | [0,1] | ratio | User path ratio (pslist). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `pslist.wow64_ratio` | float (ratio) | [0,1] | ratio | Wow64 ratio (pslist). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: 32‑bit process on 64‑bit Windows context. |
| `pslist.zombie_count` | float (size / memory) | non‑negative | MB | Zombie count (pslist). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |


## psscan (14)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `psscan.avg_children` | float (aggregate) | — | — | Average children (psscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `psscan.avg_offset` | float (aggregate) | — | — | Average offset (psscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `psscan.avg_threads` | float (aggregate) | — | — | Average threads (psscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `psscan.child_present_ratio` | float (ratio) | [0,1] | ratio | Child present ratio (psscan). Aggregation: ratio across entities. Interpretation: Heuristic: lower may indicate greater risk/suspicion. |
| `psscan.create_timespan_days` | datetime / timestamp | timestamp | timestamp | Create timespan days (psscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `psscan.disabled_output_ratio` | float (ratio) | [0,1] | ratio | Disabled output ratio (psscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `psscan.exit_time_ratio` | float (ratio) | [0,1] | ratio | Exit time ratio (psscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `psscan.handle_present_ratio` | float (ratio) | [0,1] | ratio | Handle present ratio (psscan). Aggregation: ratio across entities. Interpretation: Heuristic: lower may indicate greater risk/suspicion. |
| `psscan.nEntries` | integer (count) | non‑negative | count | Count Entries (psscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `psscan.nUniqueNames` | integer (count) | non‑negative | count | Count Unique Names (psscan). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `psscan.nUniquePIDs` | integer (count) | non‑negative | count | Count Unique P I Ds (psscan). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `psscan.offset_std` | float (aggregate) | — | — | Offset standard deviation (psscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `psscan.ppid_diversity` | string / categorical | — | — | Ppid diversity (psscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `psscan.wow64_ratio` | float (ratio) | [0,1] | ratio | Wow64 ratio (psscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: 32‑bit process on 64‑bit Windows context. |


## pstree (11)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `pstree.AvgChildren` | float (aggregate) | — | — | Average Children (pstree). Aggregation: average across entities. Interpretation: Context-dependent. |
| `pstree.AvgThreads` | float (aggregate) | — | — | Average Threads (pstree). Aggregation: average across entities. Interpretation: Context-dependent. |
| `pstree.avg_branching_factor` | float (aggregate) | — | — | Average branching factor (pstree). Aggregation: average across entities. Interpretation: Context-dependent. |
| `pstree.cross_session_edges` | string / categorical | — | — | Cross session edges (pstree). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `pstree.max_depth` | float (extreme) | — | — | Maximum depth (pstree). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `pstree.nHandles` | integer (count) | non‑negative | count | Count Handles (pstree). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Kernel object handles distribution/privilege mix. |
| `pstree.nPID` | integer (count) | non‑negative | count | Count P I D (pstree). Aggregation: count across entities. Interpretation: Context-dependent. |
| `pstree.nPPID` | integer (count) | non‑negative | count | Count P P I D (pstree). Aggregation: count across entities. Interpretation: Context-dependent. |
| `pstree.nTree` | integer (count) | non‑negative | count | Count Tree (pstree). Aggregation: count across entities. Interpretation: Context-dependent. |
| `pstree.nWow64` | integer (count) | non‑negative | count | Count Wow64 (pstree). Aggregation: count across entities. Interpretation: Context-dependent. Notes: 32‑bit process on 64‑bit Windows context. |
| `pstree.orphan_ratio` | float (ratio) | [0,1] | ratio | Orphan ratio (pstree). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |


## psxview (14)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `psxview.all_seen_ratio` | float (ratio) | [0,1] | ratio | All seen ratio (psxview). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `psxview.avg_offset` | float (aggregate) | — | — | Average offset (psxview). Aggregation: average across entities. Interpretation: Context-dependent. |
| `psxview.csrss_ratio` | float (ratio) | [0,1] | ratio | Csrss ratio (psxview). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `psxview.exit_time_ratio` | float (ratio) | [0,1] | ratio | Exit time ratio (psxview). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `psxview.nEntries` | integer (count) | non‑negative | count | Count Entries (psxview). Aggregation: count across entities. Interpretation: Context-dependent. |
| `psxview.nUniqueNames` | integer (count) | non‑negative | count | Count Unique Names (psxview). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `psxview.nUniquePIDs` | integer (count) | non‑negative | count | Count Unique P I Ds (psxview). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `psxview.none_seen_count` | integer (count) | non‑negative | count | None seen count (psxview). Aggregation: count across entities. Interpretation: Context-dependent. |
| `psxview.offset_std` | float (aggregate) | — | — | Offset standard deviation (psxview). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `psxview.partial_seen_count` | integer (count) | non‑negative | count | Partial seen count (psxview). Aggregation: count across entities. Interpretation: Context-dependent. |
| `psxview.pslist_ratio` | float (ratio) | [0,1] | ratio | Pslist ratio (psxview). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `psxview.psscan_ratio` | float (ratio) | [0,1] | ratio | Psscan ratio (psxview). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `psxview.single_seen_count` | integer (count) | non‑negative | count | Single seen count (psxview). Aggregation: count across entities. Interpretation: Context-dependent. |
| `psxview.thrdscan_ratio` | float (ratio) | [0,1] | ratio | Thrdscan ratio (psxview). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |


## registry (40)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `registry.certificates.ca_cross_store_mismatch` | boolean flag | — | — | Certificates.ca cross store mismatch (registry). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Certificate or trust store related. |
| `registry.certificates.disallowed_count` | integer (count) | non‑negative | count | Certificates.disallowed count (registry). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Certificate or trust store related. |
| `registry.certificates.duplicate_autoupdate_entries` | datetime / timestamp | timestamp | timestamp | Certificates.duplicate autoupdate entries (registry). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Certificate or trust store related. |
| `registry.certificates.nCert` | integer (count) | non‑negative | count | Certificates.count Cert (registry). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Certificate or trust store related. |
| `registry.certificates.nID_Auto` | integer (count) | non‑negative | count | Certificates.count I D Auto (registry). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Certificate or trust store related. |
| `registry.certificates.nID_Others` | integer (count) | non‑negative | count | Certificates.count I D Others (registry). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Certificate or trust store related. |
| `registry.certificates.nID_Protected` | integer (count) | non‑negative | count | Certificates.count I D Protected (registry). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Certificate or trust store related. |
| `registry.certificates.null_name_root_ratio` | float (ratio) | [0,1] | ratio | Certificates.null name root ratio (registry). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Certificate or trust store related. |
| `registry.hivelist.duplicate_paths` | string / categorical | — | — | Hivelist.duplicate paths (registry). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `registry.hivelist.empty_path_entries` | string / categorical | — | — | Hivelist.empty path entries (registry). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `registry.hivelist.nFO_Enabled` | integer (count) | non‑negative | count | Hivelist.count F O Enabled (registry). Aggregation: count across entities. Interpretation: Context-dependent. |
| `registry.hivelist.nFiles` | integer (count) | non‑negative | count | Hivelist.count Files (registry). Aggregation: count across entities. Interpretation: Context-dependent. |
| `registry.hivelist.offset_gap_stddev` | float (aggregate) | — | — | Hivelist.offset gap standard deviation (registry). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `registry.hivelist.user_hive_count` | integer (count) | non‑negative | count | Hivelist.user hive count (registry). Aggregation: count across entities. Interpretation: Context-dependent. |
| `registry.hivescan.Children_exist` | string / categorical | — | — | Hivescan. Children exist (registry). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `registry.hivescan.nHives` | integer (count) | non‑negative | count | Hivescan.count Hives (registry). Aggregation: count across entities. Interpretation: Context-dependent. |
| `registry.printkey.Avg_Children` | float (aggregate) | — | — | Printkey. average Children (registry). Aggregation: average across entities. Interpretation: Context-dependent. |
| `registry.printkey.Volatile_0` | string / categorical | — | — | Printkey. Volatile 0 (registry). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `registry.printkey.avg_name_len` | integer (count) | non‑negative | count | Printkey.average name len (registry). Aggregation: average across entities. Interpretation: Context-dependent. |
| `registry.printkey.distinct_hives` | integer (count) | non‑negative | — | Printkey.distinct hives (registry). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `registry.printkey.dword_ratio` | float (ratio) | [0,1] | ratio | Printkey.dword ratio (registry). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `registry.printkey.nDistinct` | integer (count) | non‑negative | count | Printkey.count Distinct (registry). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `registry.printkey.nKeys` | integer (count) | non‑negative | count | Printkey.count Keys (registry). Aggregation: count across entities. Interpretation: Context-dependent. |
| `registry.printkey.nType_key` | integer (count) | non‑negative | count | Printkey.count Type key (registry). Aggregation: count across entities. Interpretation: Context-dependent. |
| `registry.printkey.nType_other` | integer (count) | non‑negative | count | Printkey.count Type other (registry). Aggregation: count across entities. Interpretation: Context-dependent. |
| `registry.printkey.volatile_ratio` | float (ratio) | [0,1] | ratio | Printkey.volatile ratio (registry). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `registry.printkey.write_timespan_days` | datetime / timestamp | timestamp | timestamp | Printkey.write timespan days (registry). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `registry.userassist.Avg_Children` | float (aggregate) | — | — | Userassist. average Children (registry). Aggregation: average across entities. Interpretation: Context-dependent. |
| `registry.userassist.avg_focus_count` | integer (count) | non‑negative | count | Userassist.average focus count (registry). Aggregation: average across entities. Interpretation: Context-dependent. |
| `registry.userassist.child_present_ratio` | float (ratio) | [0,1] | ratio | Userassist.child present ratio (registry). Aggregation: ratio across entities. Interpretation: Heuristic: lower may indicate greater risk/suspicion. |
| `registry.userassist.max_children_count` | integer (count) | non‑negative | count | Userassist.maximum children count (registry). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `registry.userassist.n` | string / categorical | — | — | Userassist.count (registry). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `registry.userassist.nUnique` | integer (count) | non‑negative | count | Userassist.count Unique (registry). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `registry.userassist.name_null_ratio` | float (ratio) | [0,1] | ratio | Userassist.name null ratio (registry). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `registry.userassist.path_DNE` | string / categorical | — | — | Userassist.path D count E (registry). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `registry.userassist.time_focused_present_ratio` | float (ratio) | [0,1] | ratio | Userassist.time focused present ratio (registry). Aggregation: ratio across entities. Interpretation: Heuristic: lower may indicate greater risk/suspicion. |
| `registry.userassist.type_key` | string / categorical | — | — | Userassist.type key (registry). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `registry.userassist.type_other` | string / categorical | — | — | Userassist.type other (registry). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `registry.userassist.write_timespan_days` | datetime / timestamp | timestamp | timestamp | Userassist.write timespan days (registry). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `registry.userassist.zero_count_ratio` | float (ratio) | [0,1] | ratio | Userassist.zero count ratio (registry). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |


## servicesids (8)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `servicesids.maxdepth` | float (extreme) | — | — | Maxdepth (servicesids). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `servicesids.nServices` | integer (count) | non‑negative | count | Count Services (servicesids). Aggregation: count across entities. Interpretation: Context-dependent. |
| `servicesids.nonAlphaNameCount` | integer (count) | non‑negative | count | Non Alpha Name Count (servicesids). Aggregation: count across entities. Interpretation: Context-dependent. |
| `servicesids.sidEntropy` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Sid entropy (servicesids). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `servicesids.sidGapAvg` | float (aggregate) | — | — | Sid Gap average (servicesids). Aggregation: average across entities. Interpretation: Context-dependent. |
| `servicesids.sidReuseCount` | integer (count) | non‑negative | seconds | Sid Reuse Count (servicesids). Aggregation: count across entities. Interpretation: Context-dependent. |
| `servicesids.svcNameEntropyMean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Svc Name entropy average (servicesids). Aggregation: average across entities. Interpretation: Context-dependent. |
| `servicesids.unusualSIDAuthority` | string / categorical | — | — | Unusual S I D Authority (servicesids). Aggregation: image-level aggregate. Interpretation: Context-dependent. |


## shimcache (6)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `shimcache.avg_children` | float (aggregate) | — | — | Average children (shimcache). Aggregation: average across entities. Interpretation: Context-dependent. |
| `shimcache.exec_flag_ratio` | float (ratio) | [0,1] | ratio | Exec flag ratio (shimcache). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `shimcache.future_last_modified_ratio` | float (ratio) | [0,1] | ratio | Future last modified ratio (shimcache). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `shimcache.nDistinctPaths` | integer (count) | non‑negative | count | Count Distinct Paths (shimcache). Aggregation: unique count across entities. Interpretation: Context-dependent. |
| `shimcache.nEntries` | integer (count) | non‑negative | count | Count Entries (shimcache). Aggregation: count across entities. Interpretation: Context-dependent. |
| `shimcache.null_last_modified_ratio` | float (ratio) | [0,1] | ratio | Null last modified ratio (shimcache). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |


## skeleton_key (5)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `skeleton_key.Found_False` | string / categorical | — | — | Found False (skeleton_key). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `skeleton_key.Found_True` | string / categorical | — | — | Found True (skeleton_key). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `skeleton_key.nKey` | integer (count) | non‑negative | count | Count Key (skeleton_key). Aggregation: count across entities. Interpretation: Context-dependent. |
| `skeleton_key.nProcess` | integer (count) | non‑negative | count | Count Process (skeleton_key). Aggregation: count across entities. Interpretation: Context-dependent. |
| `skeleton_key.rc4Hmac_decrypt_time` | datetime / timestamp | timestamp | timestamp | Rc4 Hmac decrypt time (skeleton_key). Aggregation: image-level aggregate. Interpretation: Context-dependent. |


## ssdt (8)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `ssdt.Children_exist` | string / categorical | — | — | Children exist (ssdt). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `ssdt.modified_syscalls` | string / categorical | — | — | Modified syscalls (ssdt). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `ssdt.nEntries` | integer (count) | non‑negative | count | Count Entries (ssdt). Aggregation: count across entities. Interpretation: Context-dependent. |
| `ssdt.nIndex` | integer (count) | non‑negative | count | Count Index (ssdt). Aggregation: count across entities. Interpretation: Context-dependent. |
| `ssdt.nModules` | integer (count) | non‑negative | count | Count Modules (ssdt). Aggregation: count across entities. Interpretation: Context-dependent. |
| `ssdt.nSymbols` | float (size / memory) | non‑negative | MB | Count Symbols (ssdt). Aggregation: count across entities. Interpretation: Context-dependent. |
| `ssdt.syscall_entropy` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Syscall entropy (ssdt). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `ssdt.unique_syscalls` | integer (count) | non‑negative | — | Unique syscalls (ssdt). Aggregation: unique count across entities. Interpretation: Context-dependent. |


## statistics (9)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `statistics.Invalid_all` | boolean flag | — | — | Invalid all (statistics). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `statistics.Invalid_large` | boolean flag | — | — | Invalid large (statistics). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `statistics.Invalid_other` | boolean flag | — | — | Invalid other (statistics). Aggregation: image-level aggregate. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `statistics.Swapped_all` | string / categorical | — | — | Swapped all (statistics). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `statistics.Swapped_large` | string / categorical | — | — | Swapped large (statistics). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `statistics.Valid_all` | string / categorical | — | — | Valid all (statistics). Aggregation: image-level aggregate. Interpretation: Heuristic: lower may indicate greater risk/suspicion. |
| `statistics.Valid_large` | string / categorical | — | — | Valid large (statistics). Aggregation: image-level aggregate. Interpretation: Heuristic: lower may indicate greater risk/suspicion. |
| `statistics.invalid_page_ratio` | float (ratio) | [0,1] | ratio | Invalid page ratio (statistics). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `statistics.swapped_page_count` | integer (count) | non‑negative | count | Swapped page count (statistics). Aggregation: count across entities. Interpretation: Context-dependent. |


## svclist (6)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `svclist.auto_start_services` | string / categorical | — | — | Auto start services (svclist). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svclist.custom_service_type_ratio` | float (ratio) | [0,1] | ratio | Custom service type ratio (svclist). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `svclist.running_services_count` | integer (count) | non‑negative | count | Running services count (svclist). Aggregation: count across entities. Interpretation: Context-dependent. |
| `svclist.services_with_no_binary` | integer (count) | non‑negative | count | Services with no binary (svclist). Aggregation: count across entities. Interpretation: Context-dependent. |
| `svclist.suspended_service_ratio` | float (ratio) | [0,1] | ratio | Suspended service ratio (svclist). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `svclist.svchost_share_process_count` | integer (count) | non‑negative | count | Svchost share process count (svclist). Aggregation: count across entities. Interpretation: Context-dependent. |


## svcscan (14)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `svcscan.Start_Auto` | string / categorical | — | — | Start Auto (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.Start_Sys` | string / categorical | — | — | Start Sys (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.State_Run` | string / categorical | — | — | State Run (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.State_Stop` | string / categorical | — | — | State Stop (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.Type_FileSys_Driver` | string / categorical | — | — | Type File Sys Driver (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.Type_Kernel_Driver` | string / categorical | — | — | Type Kernel Driver (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.Type_Others` | string / categorical | — | — | Type Others (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.Type_Own` | string / categorical | — | — | Type Own (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.Type_Own_Interactive` | string / categorical | — | — | Type Own Interactive (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.Type_Own_Share` | string / categorical | — | — | Type Own Share (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.Type_Share` | string / categorical | — | — | Type Share (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.Type_Share_Interactive` | string / categorical | — | — | Type Share Interactive (svcscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `svcscan.nServices` | integer (count) | non‑negative | count | Count Services (svcscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `svcscan.nUniqueServ` | integer (count) | non‑negative | count | Count Unique Serv (svcscan). Aggregation: unique count across entities. Interpretation: Context-dependent. |


## symlinkscan (9)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `symlinkscan.Avg_Children` | float (aggregate) | — | — | Average Children (symlinkscan). Aggregation: average across entities. Interpretation: Context-dependent. |
| `symlinkscan.device_target_ratio` | float (ratio) | [0,1] | ratio | Device target ratio (symlinkscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `symlinkscan.duplicate_fromname_count` | integer (count) | non‑negative | count | Duplicate fromname count (symlinkscan). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `symlinkscan.globalroot_presence` | string / categorical | — | — | Globalroot presence (symlinkscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `symlinkscan.nFrom` | integer (count) | non‑negative | count | Count From (symlinkscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `symlinkscan.nLinks` | integer (count) | non‑negative | count | Count Links (symlinkscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `symlinkscan.nTo` | integer (count) | non‑negative | count | Count To (symlinkscan). Aggregation: count across entities. Interpretation: Context-dependent. |
| `symlinkscan.null_to_ratio` | float (ratio) | [0,1] | ratio | Null to ratio (symlinkscan). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `symlinkscan.offset_gap_stddev` | float (aggregate) | — | — | Offset gap standard deviation (symlinkscan). Aggregation: image-level aggregate. Interpretation: Context-dependent. |


## threads (4)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `threads.kernel_startaddr_ratio` | float (ratio) | [0,1] | ratio | Kernel startaddr ratio (threads). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `threads.nThreads` | integer (count) | non‑negative | count | Count Threads (threads). Aggregation: count across entities. Interpretation: Context-dependent. |
| `threads.null_startpath_ratio` | float (ratio) | [0,1] | ratio | Null startpath ratio (threads). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `threads.per_process_max_threads` | float (extreme) | — | — | Per process maximum threads (threads). Aggregation: extreme across entities. Interpretation: Context-dependent. |


## timers (10)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `timers.high_periodic_timer_ms` | float (duration) | timestamp | milliseconds | High periodic timer ms (timers). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `timers.max_timers_per_module` | datetime / timestamp | timestamp | timestamp | Maximum timers per module (timers). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `timers.periodic_timers_count` | datetime / timestamp | non‑negative | timestamp | Periodic timers count (timers). Aggregation: count across entities. Interpretation: Context-dependent. |
| `timers.popfx_idle_reuse_count` | datetime / timestamp | non‑negative | timestamp | Popfx idle reuse count (timers). Aggregation: count across entities. Interpretation: Context-dependent. |
| `timers.signaled_timers_count` | datetime / timestamp | non‑negative | timestamp | Signaled timers count (timers). Aggregation: count across entities. Interpretation: Context-dependent. |
| `timers.suspicious_module_timer_count` | datetime / timestamp | non‑negative | timestamp | Suspicious module timer count (timers). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. |
| `timers.timers_with_null_symbols` | datetime / timestamp | non‑negative | MB | Timers with null symbols (timers). Aggregation: count across entities. Interpretation: Context-dependent. |
| `timers.timers_with_symbols` | datetime / timestamp | non‑negative | MB | Timers with symbols (timers). Aggregation: image-level aggregate. Interpretation: Context-dependent. |
| `timers.total_timers` | datetime / timestamp | non‑negative | timestamp | Total timers (timers). Aggregation: count across entities. Interpretation: Context-dependent. |
| `timers.unique_modules_count` | datetime / timestamp | non‑negative | timestamp | Unique modules count (timers). Aggregation: unique count across entities. Interpretation: Context-dependent. |


## vadinfo (22)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `vadinfo.Avg_Children` | float (aggregate) | — | — | Average Children (vadinfo). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Process_Malware` | string / categorical | — | — | Process Malware (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Protection_ERW` | string / categorical | — | — | Protection E R W (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Protection_EWC` | string / categorical | — | — | Protection E W C (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Protection_NA` | string / categorical | — | — | Protection count A (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Protection_RO` | string / categorical | — | — | Protection R O (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Protection_RW` | string / categorical | — | — | Protection R W (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Protection_WC` | string / categorical | — | — | Protection W C (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Type_Vad` | string / categorical | — | — | Type Vad (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Type_VadF` | string / categorical | — | — | Type Vad F (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Type_VadI` | string / categorical | — | — | Type Vad I (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.Type_VadS` | string / categorical | — | — | Type Vad S (vadinfo). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.avg_region_size_kb` | float (size / memory) | non‑negative | KB | Average region size kb (vadinfo). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.exec_ratio` | float (ratio) | [0,1] | ratio | Exec ratio (vadinfo). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.file_backed_ratio` | float (ratio) | [0,1] | ratio | File backed ratio (vadinfo). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.large_commit_count` | float (size / memory) | non‑negative | count | Large commit count (vadinfo). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.nEntries` | integer (count) | non‑negative | count | Count Entries (vadinfo). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.nFile` | integer (count) | non‑negative | count | Count File (vadinfo). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.nPID` | integer (count) | non‑negative | count | Count P I D (vadinfo). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.nParent` | integer (count) | non‑negative | count | Count Parent (vadinfo). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.nProcess` | integer (count) | non‑negative | count | Count Process (vadinfo). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadinfo.susp_ext_count` | integer (count) | non‑negative | count | Susp ext count (vadinfo). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |


## vadwalk (6)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `vadwalk.Avg_Size` | float (size / memory) | non‑negative | — | Average Size (vadwalk). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadwalk.avg_gap_kb` | float (size / memory) | non‑negative | KB | Average gap kb (vadwalk). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadwalk.max_vad_size` | float (size / memory) | non‑negative | — | Maximum vad size (vadwalk). Aggregation: extreme across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadwalk.std_vad_size` | float (size / memory) | non‑negative | — | Standard deviation vad size (vadwalk). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadwalk.tag_entropy` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Tag entropy (vadwalk). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |
| `vadwalk.total_vads` | integer (count) | non‑negative | count | Total vads (vadwalk). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Virtual Address Descriptor / memory regions. |


## verinfo (9)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `verinfo.Avg_Children` | float (aggregate) | — | — | Average Children (verinfo). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `verinfo.avg_major_version` | float (aggregate) | — | — | Average major version (verinfo). Aggregation: average across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `verinfo.dup_base_count` | integer (count) | non‑negative | count | Dup base count (verinfo). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Derived from PE version metadata / Amcache. |
| `verinfo.nEntries` | integer (count) | non‑negative | count | Count Entries (verinfo). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `verinfo.nPID` | integer (count) | non‑negative | count | Count P I D (verinfo). Aggregation: count across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `verinfo.nUniqueProg` | integer (count) | non‑negative | count | Count Unique Prog (verinfo). Aggregation: unique count across entities. Interpretation: Context-dependent. Notes: Derived from PE version metadata / Amcache. |
| `verinfo.null_name_ratio` | float (ratio) | [0,1] | ratio | Null name ratio (verinfo). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: Derived from PE version metadata / Amcache. |
| `verinfo.orphan_entry_count` | boolean flag | non‑negative | count | Orphan entry count (verinfo). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: Derived from PE version metadata / Amcache. |
| `verinfo.valid_version_ratio` | float (ratio) | [0,1] | ratio | Valid version ratio (verinfo). Aggregation: ratio across entities. Interpretation: Heuristic: lower may indicate greater risk/suspicion. Notes: Derived from PE version metadata / Amcache. |


## virtmap (8)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `virtmap.Avg_Children` | float (aggregate) | — | — | Average Children (virtmap). Aggregation: average across entities. Interpretation: Context-dependent. |
| `virtmap.Avg_Offset_Size` | float (size / memory) | non‑negative | — | Average Offset Size (virtmap). Aggregation: average across entities. Interpretation: Context-dependent. |
| `virtmap.max_region_size_mb` | float (size / memory) | non‑negative | MB | Maximum region size mb (virtmap). Aggregation: extreme across entities. Interpretation: Context-dependent. |
| `virtmap.nEntries` | integer (count) | non‑negative | count | Count Entries (virtmap). Aggregation: count across entities. Interpretation: Context-dependent. |
| `virtmap.nonstandard_region_count` | integer (count) | non‑negative | count | Nonstandard region count (virtmap). Aggregation: count across entities. Interpretation: Context-dependent. |
| `virtmap.pagedpool_fragmentation` | string / categorical | non‑negative | — | Pagedpool fragmentation (virtmap). Aggregation: image-level aggregate. Interpretation: Context-dependent. Notes: Kernel pool allocation patterns. |
| `virtmap.unused_size_ratio` | float (ratio) | [0,1] | ratio | Unused size ratio (virtmap). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. |
| `virtmap.zero_len_region_count` | integer (count) | non‑negative | count | Zero len region count (virtmap). Aggregation: count across entities. Interpretation: Context-dependent. |


## windows (6)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `windows.avg_win_per_process` | float (aggregate) | — | — | Average win per process (windows). Aggregation: average across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |
| `windows.blank_process_ratio` | float (ratio) | [0,1] | ratio | Blank process ratio (windows). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: GUI objects (windows/desktops/window stations). |
| `windows.null_title_ratio` | float (ratio) | [0,1] | ratio | Null title ratio (windows). Aggregation: ratio across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: GUI objects (windows/desktops/window stations). |
| `windows.pid0_window_ratio` | float (ratio) | [0,1] | ratio | Pid0 window ratio (windows). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: GUI objects (windows/desktops/window stations). |
| `windows.station_mismatch_count` | boolean flag | non‑negative | count | Station mismatch count (windows). Aggregation: count across entities. Interpretation: Heuristic: higher may indicate greater risk/suspicion. Notes: GUI objects (windows/desktops/window stations). |
| `windows.total_window_objs` | integer (count) | non‑negative | count | Total window objs (windows). Aggregation: count across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |


## winsta (5)

| Feature | Type | Domain | Unit | Description |
|---|---|---|---|---|
| `winsta.custom_station_count` | integer (count) | non‑negative | count | Custom station count (winsta). Aggregation: count across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |
| `winsta.name_entropy_mean` | float (entropy) | ≥ 0 (typically 0–8 for ASCII) | bits (Shannon) | Name entropy average (winsta). Aggregation: average across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |
| `winsta.service_station_ratio` | float (ratio) | [0,1] | ratio | Service station ratio (winsta). Aggregation: ratio across entities. Interpretation: Heuristic: interpret relative to baseline of the same host class. Notes: GUI objects (windows/desktops/window stations). |
| `winsta.session0_gui_count` | integer (count) | non‑negative | count | Session0 gui count (winsta). Aggregation: count across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |
| `winsta.total_stations` | integer (count) | non‑negative | count | Total stations (winsta). Aggregation: count across entities. Interpretation: Context-dependent. Notes: GUI objects (windows/desktops/window stations). |