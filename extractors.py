import pandas as pd
import numpy as np

import math
import json
from utils import shannon_entropy, char_entropy, flatten_records, list_entropy
from collections import Counter
import re


def extract_svclist_features(jsondump):
    """
    Pandas‐based extractor for windows.svclist JSON output.
    """
    df = pd.read_json(jsondump)
    # Schema‐stable defaults
    keys = [
        "svclist.running_services_count",
        "svclist.suspended_service_ratio",
        "svclist.auto_start_services",
        "svclist.svchost_share_process_count",
        "svclist.custom_service_type_ratio",
        "svclist.services_with_no_binary",
    ]
    if df.empty:
        return {k: 0 if "count" in k or "services" in k else 0.0 for k in keys}

    # 1) Total running services
    running_services_count = int((df["State"] == "SERVICE_RUNNING").sum())

    # 2) Suspended‐service ratio: of stopped services, how many are under svchost.exe
    stopped = df[df["State"] == "SERVICE_STOPPED"]
    if not stopped.empty:
        suspended_service_ratio = float(
            stopped["Binary"]
            .str.lower()
            .fillna("")
            .str.contains("svchost.exe")
            .mean()
        )
    else:
        suspended_service_ratio = 0.0

    # 3) Auto‐start services
    auto_start_services = int((df["Start"] == "SERVICE_AUTO_START").sum())

    # 4) svchost share‐process count
    mask_share = (
        df["Binary"].str.lower().fillna("").str.contains("svchost.exe")
        & df["Type"].fillna("").str.contains("SHARE_PROCESS")
    )
    svchost_share_process_count = int(mask_share.sum())

    # 5) Custom service types
    standard = {
        "SERVICE_WIN32_OWN_PROCESS",
        "SERVICE_WIN32_SHARE_PROCESS",
        "SERVICE_KERNEL_DRIVER",
        "SERVICE_FILE_SYSTEM_DRIVER",
    }
    # Break multi‐type strings into sets, then test subset
    types_series = (
        df["Type"]
        .fillna("")
        .str.split("|")
        .apply(lambda lst: {t.strip() for t in lst if t.strip()})
    )
    custom_count = int(types_series.apply(lambda s: not s.issubset(standard)).sum())
    custom_service_type_ratio = custom_count / len(df)

    # 6) Services with no Binary
    services_with_no_binary = int(df["Binary"].isna().sum())

    return {
        "svclist.running_services_count": running_services_count,
        "svclist.suspended_service_ratio": round(suspended_service_ratio, 4),
        "svclist.auto_start_services": auto_start_services,
        "svclist.svchost_share_process_count": svchost_share_process_count,
        "svclist.custom_service_type_ratio": round(custom_service_type_ratio, 4),
        "svclist.services_with_no_binary": services_with_no_binary,
    }


def extract_unhooked_system_calls_features(jsondump):
    """
    Extracts four metrics from windows.unhooked_system_calls JSON:
      • syscalls.hooked_function_count  : # rows with non-empty 'Distinct Implementations'
      • syscalls.userland_hook_ratio    : share of hooked rows where the hooker is a user-mode process
      • syscalls.max_impl_discrepancy   : max(baseline_total_impls − Total Implementations)
      • syscalls.hooked_entropy         : entropy of all implementer IDs (PID:PROC strings)
    """
    df = pd.read_json(jsondump)

    # schema-stable defaults
    if df.empty:
        return {
            'syscalls.hooked_function_count': 0,
            'syscalls.userland_hook_ratio'  : 0.0,
            'syscalls.max_impl_discrepancy' : 0,
            'syscalls.hooked_entropy'       : 0.0,
        }

    # 1) Which functions were hooked at all?
    di          = df['Distinct Implementations'].fillna('').astype(str)
    hooked_mask = di.str.strip().astype(bool)
    hooked_count= int(hooked_mask.sum())

    # 2) Baseline vs. actual implementations → discrepancy
    baseline     = int(df['Total Implementations'].max())
    discrepancies= baseline - df['Total Implementations']
    max_discrepancy = int(discrepancies.max())

    # 3) Identify user-mode hooks: rows where the implementer string after ":"
    #    looks like a user process (e.g. "7436:OUTLOOK.EXE")
    def _is_userland(s: str) -> bool:
        parts = s.split(':', 1)
        if len(parts) == 2:
            proc = parts[1].strip()
            return '.' in proc   # crude check: user-mode executables have an extension
        return False

    hooked_series = di[hooked_mask]
    # per-row mask: does any implementer in this row qualify?
    is_user_row = hooked_series.apply(
        lambda s: any(_is_userland(p.strip()) for p in s.replace(',', ';').split(';') if p.strip())
    )
    userland_hook_ratio = float(is_user_row.mean()) if hooked_count else 0.0

    # 4) Collect **all** implementer tokens and compute entropy
    impls = []
    for s in hooked_series:
        for part in [p.strip() for p in s.replace(',', ';').split(';') if p.strip()]:
            impls.append(part)
    hooked_entropy = list_entropy(impls)

    return {
        'syscalls.hooked_function_count': hooked_count,
        'syscalls.userland_hook_ratio'  : round(userland_hook_ratio, 4),
        'syscalls.max_impl_discrepancy' : max_discrepancy,
        'syscalls.hooked_entropy'       : round(hooked_entropy, 4),
    }





def extract_windows_features(jsondump):
    """
    windows.windows → six new metrics:
      • windows.total_window_objs       : total window objects
      • windows.pid0_window_ratio       : share of rows with PID == 0
      • windows.null_title_ratio        : fraction where Window is null
      • windows.blank_process_ratio     : fraction where Process is empty
      • windows.avg_win_per_process     : mean windows-per-PID
      • windows.station_mismatch_count  : rows whose Station != 'WinSta0'
    """
    df = pd.read_json(jsondump)

    keys = [
        'windows.total_window_objs',
        'windows.pid0_window_ratio',
        'windows.null_title_ratio',
        'windows.blank_process_ratio',
        'windows.avg_win_per_process',
        'windows.station_mismatch_count',
    ]
    if df.empty:
        return {
            'windows.total_window_objs'      : 0,
            'windows.pid0_window_ratio'      : 0.0,
            'windows.null_title_ratio'       : 0.0,
            'windows.blank_process_ratio'    : 0.0,
            'windows.avg_win_per_process'    : 0.0,
            'windows.station_mismatch_count' : 0,
        }

    total = len(df)

    # 1) raw count
    total_objs = total

    # 2) share PID==0
    pid0_ratio = df['PID'].eq(0).mean()

    # 3) null Window titles
    null_title_ratio = df['Window'].isna().mean()

    # 4) blank Process strings
    blank_proc_ratio = df['Process'].fillna('').eq('').mean()

    # 5) average windows per process
    avg_per_proc = df.groupby('PID').size().mean()

    # 6) stations not 'WinSta0'
    station_mismatch = int(
        df['Station'].fillna('').ne('WinSta0').sum()
    )

    return {
        'windows.total_window_objs'      : int(total_objs),
        'windows.pid0_window_ratio'      : round(pid0_ratio, 4),
        'windows.null_title_ratio'       : round(null_title_ratio, 4),
        'windows.blank_process_ratio'    : round(blank_proc_ratio, 4),
        'windows.avg_win_per_process'    : round(avg_per_proc, 2),
        'windows.station_mismatch_count' : station_mismatch,
    }

def extract_windowstations_features(jsondump):
    """
    Extracts these features from windows.windowstations JSON:
      • winsta.total_stations         : total station objects
      • winsta.service_station_ratio  : proportion where Name starts with "Service-"
      • winsta.custom_station_count   : count of Names ≠ WinSta0 and not "Service-*"
      • winsta.session0_gui_count     : session 0 stations whose Name ≠ WinSta0
      • winsta.name_entropy_mean      : mean Shannon entropy of Name strings
    """
    df = pd.read_json(jsondump)
    # keep schema stable on empty output
    if df.empty:
        return {
            'winsta.total_stations'        : 0,
            'winsta.service_station_ratio' : 0.0,
            'winsta.custom_station_count'  : 0,
            'winsta.session0_gui_count'    : 0,
            'winsta.name_entropy_mean'     : 0.0,
        }

    # normalize names
    names = df['Name'].fillna('')
    total = len(names)

    # 1) Service-stations
    service_mask = names.str.startswith('Service-')
    service_ratio = service_mask.mean()

    # 2) Custom stations (neither WinSta0 nor Service-*)
    custom_mask = (~names.str.lower().eq('winsta0')) & (~service_mask)
    custom_count = int(custom_mask.sum())

    # 3) Session-0 GUI stations (Name ≠ WinSta0 in Session 0)
    sess0_gui_mask = (df['SessionId'] == 0) & (~names.str.lower().eq('winsta0'))
    session0_gui_count = int(sess0_gui_mask.sum())

    # 4) Name-entropy
    entropies = names.apply(shannon_entropy)
    entropy_mean = entropies.mean()

    return {
        'winsta.total_stations'        : int(total),
        'winsta.service_station_ratio' : round(service_ratio, 4),
        'winsta.custom_station_count'  : custom_count,
        'winsta.session0_gui_count'    : session0_gui_count,
        'winsta.name_entropy_mean'     : round(entropy_mean, 4),
    }


def extract_unloadedmodules_features(jsondump, known_drivers: set[str] = None):
    """
    Extracts these features from windows.unloadedmodules JSON:
      • unloaded.n_entries              : total unload records
      • unloaded.unique_driver_count    : distinct driver names
      • unloaded.repeated_driver_ratio  : (n_entries – unique_driver_count) ÷ n_entries
      • unloaded.burst_max_per_sec      : max unloads in any 1-second window
      • unloaded.non_ms_driver_ratio    : share of names NOT in `known_drivers`
    
    Parameters
    ----------
    jsondump : file-like or path
        JSON list from `windows.unloadedmodules -r json`.
    known_drivers : set[str], optional
        If you have a set of “legit” Windows driver names (e.g. from your
        earlier modules dump), pass it here so we can flag 3rd-party/unsigned.
        If None, this ratio will be returned as None.
    """
    df = pd.read_json(jsondump)

    # keep schema stable on empty output
    keys = [
        'unloaded.n_entries',
        'unloaded.unique_driver_count',
        'unloaded.repeated_driver_ratio',
        'unloaded.burst_max_per_sec',
        'unloaded.non_ms_driver_ratio',
    ]
    if df.empty:
        return {k: 0 if 'count' in k or 'entries' in k else None for k in keys}

    # 1) total / unique
    n_entries       = len(df)
    unique_count    = df['Name'].nunique()
    repeated_ratio  = (n_entries - unique_count) / n_entries if n_entries else 0.0

    # 2) burst: parse Time, floor to second, count per-second, take max
    times           = pd.to_datetime(df['Time'], errors='coerce', utc=True)
    secs            = times.dt.floor('S')
    burst_max       = int(secs.value_counts().max()) if not secs.isna().all() else 0

    # 3) optional non-MS ratio
    if known_drivers is not None:
        non_ms_ratio = float((~df['Name'].isin(known_drivers)).mean())
    else:
        non_ms_ratio = None

    return {
        'unloaded.n_entries'             : n_entries,
        'unloaded.unique_driver_count'   : unique_count,
        'unloaded.repeated_driver_ratio' : round(repeated_ratio, 4),
        'unloaded.burst_max_per_sec'     : burst_max,
        'unloaded.non_ms_driver_ratio'   : non_ms_ratio,
    }



def extract_statistics_features(jsondump):
    """
    Extracts three metrics from windows.statistics JSON:
      • statistics.invalid_page_ratio      – proportion of invalid pages
      • statistics.swapped_page_count      – total swapped pages
      • statistics.large_invalid_page_count– invalid pages (large)
    """
    df = pd.read_json(jsondump)

    # keep schema stable on empty output
    keys = [
        'statistics.invalid_page_ratio',
        'statistics.swapped_page_count',
        'statistics.large_invalid_page_count',
    ]
    if df.empty:
        return {
            k: 0 if 'count' in k else None
            for k in keys
        }

    row = df.iloc[0]

    # count all invalid pages (including “Other Invalid Pages”)
    invalid_all      = row.get('Invalid Pages (all)', 0) + row.get('Other Invalid Pages (all)', 0)
    valid_all        = row.get('Valid pages (all)', 0)
    swapped_all      = row.get('Swapped Pages (all)', 0)
    total_pages      = invalid_all + valid_all + swapped_all

    invalid_ratio    = (invalid_all / total_pages) if total_pages else None
    swapped_count    = int(swapped_all)
    large_invalid    = int(row.get('Invalid Pages (large)', 0))

    return {
        'statistics.invalid_page_ratio'       : invalid_ratio,
        'statistics.swapped_page_count'       : swapped_count,
        'statistics.large_invalid_page_count' : large_invalid,
    }





def extract_certificates_features(jsondump):
    """
    windows.registry.certificates → four new metrics:
      • certs.disallowed_count
      • certs.duplicate_autoupdate_entries
      • certs.null_name_root_ratio
      • certs.ca_cross_store_mismatch
    """
    df = pd.read_json(jsondump)

    # keep schema even on empty output
    keys = [
        'certs.disallowed_count',
        'certs.duplicate_autoupdate_entries',
        'certs.null_name_root_ratio',
        'certs.ca_cross_store_mismatch',
    ]
    if df.empty:
        return {k: 0 for k in keys}

    # normalize column names for convenience
    sec = df['Certificate section'].fillna('')
    cid = df['Certificate ID'].fillna('')
    name = df['Certificate name']

    # 1) Disallowed-store count
    disallowed_cnt = int((sec == 'Disallowed').sum())

    # 2) Duplicate AutoUpdate in AuthRoot
    dup_auto = int(((cid == 'AutoUpdate') & (sec == 'AuthRoot')).sum())

    # 3) Null-name ratio in ROOT store
    root_mask = sec == 'ROOT'
    total_root = int(root_mask.sum())
    null_root = int((root_mask & name.isna()).sum())
    null_name_root_ratio = null_root / total_root if total_root else 0.0

    # 4) CA↔AuthRoot ID mismatches
    #   IDs present in both sections with conflicting names or paths
    auth = df[sec == 'AuthRoot']
    ca   = df[sec == 'CA']
    common_ids = set(auth['Certificate ID']).intersection(ca['Certificate ID'])

    mismatch = 0
    for _id in common_ids:
        sub_a = auth[auth['Certificate ID'] == _id]
        sub_c = ca[ca['Certificate ID'] == _id]

        # compare name-sets (ignoring NaN)
        names_a = set(sub_a['Certificate name'].dropna())
        names_c = set(sub_c['Certificate name'].dropna())
        if names_a != names_c:
            mismatch += 1
            continue

        # compare paths
        paths_a = set(sub_a['Certificate path'].str.lower())
        paths_c = set(sub_c['Certificate path'].str.lower())
        if paths_a != paths_c:
            mismatch += 1

    return {
        'certs.disallowed_count'               : disallowed_cnt,
        'certs.duplicate_autoupdate_entries'  : dup_auto,
        'certs.null_name_root_ratio'          : round(null_name_root_ratio, 4),
        'certs.ca_cross_store_mismatch'       : mismatch,
    }








def extract_hivelist_features(jsondump):
    """
    Extracts these features from windows.registry.hivelist JSON:
      • hivelist.empty_path_entries : # rows where FileFullPath == ""
      • hivelist.duplicate_paths    : total rows minus # unique FileFullPath
      • hivelist.user_hive_count    : # per-user NTUSER/UsrClass hives loaded
      • hivelist.offset_gap_stddev  : std-dev of gaps between sorted Offsets
    """
    df = pd.read_json(jsondump)

    # If no rows, keep schema stable
    keys = [
        'hivelist.empty_path_entries',
        'hivelist.duplicate_paths',
        'hivelist.user_hive_count',
        'hivelist.offset_gap_stddev',
    ]
    if df.empty:
        return {k: 0 if 'count' in k or 'entries' in k else None for k in keys}

    # normalize path column
    paths = df['FileFullPath'].fillna('')
    paths_lc = paths.str.lower()

    #  empty-path entries
    empty_cnt = (paths == '').sum()

    #  duplicates: total rows minus unique non-empty paths
    dup_cnt = len(paths) - paths.nunique()

    #  per-user hives: look for ntuser.dat or usrclass.dat under Users\
    user_mask = (
        paths_lc.str.contains(r'\\users\\', na=False)
        & paths_lc.str.contains(r'ntuser\.dat$|usrclass\.dat$', na=False)
    )
    user_hive_cnt = int(user_mask.sum())

    #  offset gaps std-dev
    offs = pd.to_numeric(df['Offset'], errors='coerce').dropna().sort_values()
    gaps = offs.diff().dropna()
    gap_std = float(gaps.std()) if not gaps.empty else None

    return {
        'hivelist.empty_path_entries': int(empty_cnt),
        'hivelist.duplicate_paths'   : int(dup_cnt),
        'hivelist.user_hive_count'   : user_hive_cnt,
        'hivelist.offset_gap_stddev' : gap_std,
    }


def extract_modules_features(jsondump):
    """
    Extract features from windows.modules JSON (pd.read_json style).
    Returns:
      • modules.nModules
      • modules.avgSizeKB
      • modules.largeModuleRatio
      • modules.userPathCount
      • modules.driverStoreRatio
      • modules.fileOutEnabled
      • modules.nameEntropyMean
      • modules.nonAsciiNameCount
      • modules.sharedBaseAddrCount
    """
    df = pd.read_json(jsondump)
    # guard empty
    keys = [
        'modules.nModules','modules.avgSizeKB','modules.largeModuleRatio',
        'modules.userPathCount','modules.driverStoreRatio','modules.fileOutEnabled',
        'modules.nameEntropyMean','modules.nonAsciiNameCount','modules.sharedBaseAddrCount'
    ]
    if df.empty:
        return {k: None for k in keys}


    # print(df.head())

    # 1) Volume / mix
    n = len(df)
    avg_size_kb      = df['Size'].mean() / 1024
    large_ratio      = (df['Size'] > 5 * 1024 * 1024).mean()

    # 2) Path sanity
    paths_lc         = df['Path'].fillna('').str.lower()
    user_mask        = paths_lc.str.contains(r'\\program files|\\users\\.*\\temp|\\temp\\|\\appdata', regex=True)
    user_count       = int(user_mask.sum())
    driverstore_mask = paths_lc.str.contains('driverstore', na=False)
    driverstore_ratio= driverstore_mask.mean()

    # 3) File-output flag
    fileout_enabled  = int((df['File output'] == 'Enabled').sum())

    # 4) Entropy / masquerade
    names            = df['Name'].fillna('')
    entropies        = names.apply(shannon_entropy)
    name_entropy_mean= entropies.mean()
    nonascii_count   = int(names.apply(lambda s: any(ord(c) >= 128 for c in s)).sum())

    # 5) Duplicate base
    base_counts      = df['Base'].value_counts()
    shared_base_cnt  = int((base_counts > 1).sum())

    return {
        'modules.nModules'            : n,
        'modules.avgSizeKB'           : round(avg_size_kb, 2),
        'modules.largeModuleRatio'    : round(large_ratio, 4),
        'modules.userPathCount'       : user_count,
        'modules.driverStoreRatio'    : round(driverstore_ratio, 4),
        'modules.fileOutEnabled'      : fileout_enabled,
        'modules.nameEntropyMean'     : round(name_entropy_mean, 4),
        'modules.nonAsciiNameCount'   : nonascii_count,
        'modules.sharedBaseAddrCount' : shared_base_cnt,
    }


def extract_iat_features(jsondump):
    df = pd.read_json(jsondump)

    # 2. Compute features
    total_entries = len(df)
    n_processes = df['PID'].nunique()
    avg_imports_per_proc = total_entries / n_processes if n_processes else 0

    # Ratio of bound imports
    bound_ratio = df['Bound'].mean()

    # Syscall appetite: proportion of imports that are direct syscalls (Nt*/Zw*)
    syscall_mask = df['Function'].str.startswith(('Nt', 'Zw'), na=False)
    syscall_ratio = syscall_mask.mean()

    # Crypto & net use counts
    crypto_mask = df['Function'].str.contains('Crypt|Crypto', case=False, na=False)
    crypto_count = crypto_mask.sum()

    netapi_mask = df['Function'].str.contains('Wininet|Ws2_32|Http', case=False, na=False)
    net_api_count = netapi_mask.sum()

    # Cross-architecture library count (api-ms-win-crt-* imports)
    wow64_lib_mask = df['Library'].str.contains(r'^api-ms-win-crt-', case=False, na=False)
    wow64_lib_count = wow64_lib_mask.sum()

    # Entropy of function names
    df['funcEntropy'] = df['Function'].fillna('').apply(shannon_entropy)
    func_name_entropy_mean = df['funcEntropy'].mean()

    # 3. Summarize
    features = {
        'totalEntries': total_entries,
        'nProcesses': n_processes,
        'avgImportsPerProc': avg_imports_per_proc,
        'boundRatio': bound_ratio,
        'syscallRatio': syscall_ratio,
        'cryptoCount': crypto_count,
        'netApiCount': net_api_count,
        'wow64LibCount': wow64_lib_count,
        'funcNameEntropyMean': func_name_entropy_mean
    }

    return features




def extract_getservicesids_features(jsondump):
    """
    Extractor for windows.getservicesids JSON output (pd.read_json style).
    Returns a dict with keys:
      • servicesids.nServices
      • servicesids.sidEntropy
      • servicesids.svcNameEntropyMean
      • servicesids.nonAlphaNameCount
      • servicesids.sidReuseCount
      • servicesids.highPrivRatio
      • servicesids.exeMissingCount
    """
    df = pd.read_json(jsondump)

    # 1) total services
    n_services = len(df)

    # 2) entropy of SID strings
    sids = df["SID"].dropna().tolist()
    sid_counts = Counter(sids)
    if n_services:
        sid_entropy = -sum(
            (count / n_services) * math.log2(count / n_services)
            for count in sid_counts.values()
        )
    else:
        sid_entropy = None

    # 3) per-string char entropy for service names → mean
    names = df["Service"].fillna("").astype(str)

    name_entropies = names.map(char_entropy)
    svc_name_entropy_mean = name_entropies.mean() if n_services else None

    # 4) count of names containing any non-A–Z/a–z character
    non_alpha_mask = names.str.contains(r"[^A-Za-z]")
    non_alpha_count = int(non_alpha_mask.sum())

    # 5) duplicate-SID reuse: sum of (count>1) occurrences
    sid_reuse_count = sum(cnt for cnt in sid_counts.values() if cnt > 1)

    # 6) privilege-tilt ratio: RIDs < 1000 (last dash-field of SID)
    rids = pd.to_numeric(
        df["SID"].str.rsplit("-", n=1).str[-1],
        errors="coerce"
    )
    high_priv_mask = rids < 1000
    high_priv_ratio = float(high_priv_mask.sum() / n_services) if n_services else None

    # 7) shadow services: missing ImagePath entries
    #    (only works if the plugin ever emits an ImagePath column)
    if "ImagePath" in df.columns:
        exe_missing_count = int(df["ImagePath"].isna().sum())
    else:
        exe_missing_count = None

    return {
        "servicesids.nServices"          : n_services,
        "servicesids.sidEntropy"         : round(sid_entropy, 4) if sid_entropy is not None else None,
        "servicesids.svcNameEntropyMean" : round(svc_name_entropy_mean, 4) if svc_name_entropy_mean is not None else None,
        "servicesids.nonAlphaNameCount"  : non_alpha_count,
        "servicesids.sidReuseCount"      : sid_reuse_count,
        "servicesids.highPrivRatio"      : round(high_priv_ratio, 4) if high_priv_ratio is not None else None,
        "servicesids.exeMissingCount"    : exe_missing_count,
    }

    
def extract_deskscan_features(jsondump):
    """
    Extractor for windows.deskscan → computes:
      • deskscan.totalEntries         : total number of Desktop objects
      • deskscan.uniqueDesktops       : count of distinct Desktop names
      • deskscan.uniqueWinStations    : count of distinct Window Station names
      • deskscan.session0GuiCount     : rows where Session==0 AND Window Station=="WinSta0"
      • deskscan.topProcDesktopRatio  : max windows owned by one Process ÷ totalEntries
    """
    df = pd.read_json(jsondump)  # reads the JSON array into a DataFrame :contentReference[oaicite:0]{index=0}

    # empty‐output guard
    if df.empty:
        return {
            'deskscan.totalEntries'        : 0,
            'deskscan.uniqueDesktops'      : 0,
            'deskscan.uniqueWinStations'   : 0,
            'deskscan.session0GuiCount'    : 0,
            'deskscan.topProcDesktopRatio' : 0.0,
        }

    total = len(df)

    #  Desktop spread
    unique_desktops    = df['Desktop'].nunique()
    unique_winstns     = df['Window Station'].nunique()

    # Session-0 GUI check
    sess0_gui = df[
        (df['Session'] == 0) &
        (df['Window Station'] == 'WinSta0')
    ].shape[0]

    #  Process diversity: who “owns” the most windows?
    proc_counts = df['Process'].value_counts()
    top_owner   = proc_counts.iloc[0] if not proc_counts.empty else 0
    top_ratio   = top_owner / total if total else 0.0

    # ── Orphan desktops ────────────────────────────────────────────────────────
    defaults     = {"Default", "Winlogon"}
    unique_names = df["Desktop"].dropna().unique()
    n_orphan     = sum(1 for name in unique_names if name not in defaults)

    # …then in your return dict, add:

    return {
        'deskscan.totalEntries'        : total,
        'deskscan.uniqueDesktops'      : unique_desktops,
        'deskscan.uniqueWinStations'   : unique_winstns,
        'deskscan.session0GuiCount'    : sess0_gui,
        'deskscan.topProcDesktopRatio' : round(top_ratio, 4),
        "deskscan.nOrphanDesktops": n_orphan,

    }








######################################

def extract_winInfo_features(jsondump):
    df = pd.read_json(jsondump)
    try:
        a = bool(json.loads(df.loc[3].at["Value"].lower()))           #Is Windows a 64 Version 
        b = df.loc[8].at["Value"]                                     #Version of Windows Build
        c = int(df.loc[11].at["Value"])                               #Number of Processors
        d = bool(json.loads(df.loc[4].at["Value"].lower()))           #Is Windows Physical Address Extension (PAE) is a processor feature that enables x86 processors to access more than 4 GB of physical memory
        # e = df[df['Variable']]
        e = int(pd.to_datetime(df.loc[df['Variable']=='SystemTime','Value'].iat[0], utc=True))
    except:
        a = None
        b = None
        c = None
        d = None
        e = None
    return{
        'info.Is64': a,
        'info.winBuild': b,
        'info.npro': c,
        'info.IsPAE': d,
        'info.SystemTime': e
    }

def extract_bigpools_features(jsondump):
    df = pd.read_json(jsondump)

    if df.empty:
        # ensure all headers exist even if the plugin produced nothing
        return {k: None for k in (
            'bigpools.nAllocs', 'bigpools.sumBytes', 'bigpools.maxBytes',
            'bigpools.avgBytes', 'bigpools.largeAllocs',
            'bigpools.nonPagedRatio', 'bigpools.tagEntropyMean',
            'bigpools.tagRare'
        )}

    # ─ Size-based metrics ----------------------------------------------------
    n_allocs     = len(df)
    sum_bytes    = df['NumberOfBytes'].sum()
    max_bytes    = df['NumberOfBytes'].max()
    avg_bytes    = df['NumberOfBytes'].mean()
    large_allocs = (df['NumberOfBytes'] > (1 << 20)).sum()          # > 1 MiB

    # ─ Pool-type metric ------------------------------------------------------
    nonpaged_ratio = (
        df['PoolType'].str.contains('nonpaged', case=False, na=False).mean()
    )

    # ─ Tag-based metrics -----------------------------------------------------
    tags             = df['Tag'].dropna().astype(str)
    tag_entropy_mean = tags.apply(shannon_entropy).mean() if not tags.empty else 0.0
    tag_rare         = (tags.value_counts() == 1).sum()

    return {
        'bigpools.nAllocs'       : int(n_allocs),
        'bigpools.sumBytes'      : int(sum_bytes),
        'bigpools.maxBytes'      : int(max_bytes),
        'bigpools.avgBytes'      : float(avg_bytes),
        'bigpools.largeAllocs'   : int(large_allocs),
        'bigpools.nonPagedRatio' : float(round(nonpaged_ratio, 4)),
        'bigpools.tagEntropyMean': float(round(tag_entropy_mean, 4)),
        'bigpools.tagRare'       : int(tag_rare),
    }



def extract_consoles_features(jsondump):
    """
    Extract all seven console metrics from windows.consoles JSON.
    Expects `jsondump` to be a file‐like handle (open(…, 'r')) whose
    contents are the raw JSON array emitted by `windows.consoles -r json`.
    """
    try:
        data = json.load(jsondump)
    except Exception:
        # keep your CSV schema if the plugin failed
        return {k: None for k in [
            'consoles.nConhost',
            'consoles.avgProcPerConsole',
            'consoles.maxProcPerConsole',
            'consoles.emptyHistoryRatio',
            'consoles.histBufOverflow',
            'consoles.titleSuspicious',
            'consoles.dumpIoC',
        ]}

    # Detect root‐wrapped JSON vs flat list
    if (isinstance(data, list) and len(data) == 1
        and isinstance(data[0], dict) and "__children" in data[0]
        and all(k == "__children" for k in data[0].keys())):
        consoles = data[0]["__children"]
    else:
        consoles = data

    nConhost = len(consoles)

    proc_counts = []
    total_cmds = 0
    null_cmds  = 0
    buf_overflow = 0
    title_susp   = 0
    dump_ioc     = 0

    IOC_KEYWORDS = ["curl", "http", "invoke-webrequest", "mimikatz"]

    def is_system_path(p):
        p = (p or "").lower()
        return p.startswith("c:\\windows") or p.startswith("%systemroot%")

    for console in consoles:
        children = console.get("__children", [])

        # 1) ProcessCount
        pc = 0
        for c in children:
            if c.get("Property","").endswith(".ProcessCount"):
                pc = int(c.get("Data") or 0)
                break
        proc_counts.append(pc)

        # 2) HistoryBuffer overflow?
        hb_count = hb_max = None
        for c in children:
            prop = c.get("Property","")
            if prop.endswith(".HistoryBufferCount"):
                hb_count = int(c.get("Data") or 0)
            elif prop.endswith(".HistoryBufferMax"):
                hb_max = int(c.get("Data") or 0)
        if hb_count is not None and hb_max is not None and hb_count == hb_max:
            buf_overflow += 1

        # 3) emptyHistoryRatio
        for c in children:
            if c.get("Property","").endswith(".CommandCount"):
                total_cmds += 1
                if c.get("Data") in (None, "", []):
                    null_cmds += 1

        # 4) titleSuspicious
        title = ""
        # prefer .Title
        for c in children:
            if c.get("Property","").endswith(".Title"):
                title = c.get("Data") or ""
                break
        # fallback to .OriginalTitle
        if not title:
            for c in children:
                if c.get("Property","").endswith(".OriginalTitle"):
                    title = c.get("Data") or ""
                    break
        if title and not is_system_path(title):
            title_susp += 1

        # 5) dumpIoC
        dump_txt = ""
        for c in children:
            if c.get("Property","").endswith(".Dump"):
                dump_txt = (c.get("Data") or "").lower()
                break
        if any(kw in dump_txt for kw in IOC_KEYWORDS):
            dump_ioc += 1

    # finalize aggregates
    avg_proc = sum(proc_counts) / nConhost if nConhost else 0
    max_proc = max(proc_counts) if proc_counts else 0
    empty_hist_ratio = (null_cmds / total_cmds) if total_cmds else 0.0

    return {
        'consoles.nConhost'          : nConhost,
        'consoles.avgProcPerConsole' : round(avg_proc, 2),
        'consoles.maxProcPerConsole' : int(max_proc),
        'consoles.emptyHistoryRatio' : round(empty_hist_ratio, 3),
        'consoles.histBufOverflow'   : buf_overflow,
        'consoles.titleSuspicious'   : title_susp,
        'consoles.dumpIoC'           : dump_ioc,
    }



def extract_pslist_features(jsondump):
    df = pd.read_json(jsondump)

    # ---------- V2 metrics ----------
    try:
        nproc          = len(df)                               # total rows
        nppid          = df.PPID.nunique()
        avg_threads    = df.Threads.mean()
        avg_handles    = df.Handles.mean()
        nprocs64bit    = len(df[df["Wow64"] == True])
        outfile        = nproc - len(df[df["File output"] == "Disabled"])
    except Exception:
        nproc = nppid = avg_threads = avg_handles = nprocs64bit = outfile = None

    # ---------- NEW v3 metrics ----------
    try:
        zombie_count   = len(df[df["ExitTime"].notna()])        # still resident but ExitTime recorded
        wow64_ratio    = nprocs64bit / nproc if nproc else None

        # Handles column can be null – cast safely
        handles_numeric = pd.to_numeric(df["Handles"], errors="coerce")
        restricted_pct  = (handles_numeric.lt(4).sum() / nproc) if nproc else None

        # User-land path heuristic: basename *not* living under Windows\ or Program Files\
        def is_user_path(name):
            name = str(name).lower()
            return (not name.startswith("c:\\windows\\")
                    and not name.startswith("c:\\program files"))
        user_path_ratio = df["ImageFileName"].apply(is_user_path).mean()
    except Exception:
        zombie_count = wow64_ratio = restricted_pct = user_path_ratio = None

    return {
        # V2
        "pslist.nproc"        : nproc,
        "pslist.nppid"        : nppid,
        "pslist.avg_threads"  : avg_threads,
        "pslist.avg_handlers" : avg_handles,
        "pslist.nprocs64bit"  : nprocs64bit,
        "pslist.outfile"      : outfile,

        # v3 additions
        "pslist.zombie_count"       : zombie_count,
        "pslist.wow64_ratio"        : wow64_ratio,
        "pslist.restricted_handles_pct": restricted_pct,
        "pslist.user_path_ratio"    : user_path_ratio,
    }

def extract_ssdt_features(jsondump):
    """
    windows.ssdt extractor

    • ssdt.modified_syscalls   – # entries whose Module ≠ ntoskrnl
    • ssdt.uncommon_syscalls   – list of those Symbol names (joined by ‘|’)
    • ssdt.syscall_entropy     – Shannon entropy of Module::Symbol pairs
    """
    df = pd.read_json(jsondump)

    if df.empty:
        return {
            'ssdt.modified_syscalls': 0,
            'ssdt.uncommon_syscalls': "",
            'ssdt.syscall_entropy'  : None,
        }

    # Modified / hooked calls
    mod_mask   = df['Module'].str.lower() != 'ntoskrnl'
    modified   = int(mod_mask.sum())
    uncommon   = '|'.join(sorted(df.loc[mod_mask, 'Symbol'].astype(str).unique()))

    # Entropy of the whole table
    pair_series = df['Module'].astype(str) + '::' + df['Symbol'].astype(str)
    entropy_val = shannon_entropy(pair_series)

    return {
        'ssdt.modified_syscalls': modified,
        'ssdt.uncommon_syscalls': uncommon,
        'ssdt.syscall_entropy'  : entropy_val,
    }



import json
from statistics import mean

def extract_cmdscan_features(jsondump):
    """
    Extracts per-console history metrics from `windows.cmdscan` JSON.

    Returns
    -------
    dict
        cmdscan.nHistories        : total _COMMAND_HISTORY blocks
        cmdscan.nonZeroHist       : # blocks with CommandCount > 0
        cmdscan.maxCmds           : largest CommandCount observed
        cmdscan.appMismatch       : # blocks where Application ≠ parent Process
        cmdscan.cmdCountRatio     : mean(CommandCount / CommandCountMax)
    """
    df = pd.read_json(jsondump)          # jsondump is an open()-handle
    if df.empty:
        return {k: None for k in (
        'cmdscan.nHistories', 'cmdscan.nonZeroHist',
        'cmdscan.maxCmds', 'cmdscan.appMismatch',
        'cmdscan.cmdCountRatio')
        }

    cmd_df = df[df['Property'] == '_COMMAND_HISTORY']
    nHistories = len(cmd_df)
    cmd_counts = []
    mismatch = 0
        
    # print(cmd_df)
    for _, row in cmd_df.iterrows():
        # print(row)
        pid = row['PID']
        children_arr =  row['__children'] #['Property']
        
        for child in children_arr:
            if child['Property'].endswith(".CommandCount"): # and child['Data'] != '0':
                # nNonZero +=1
                # cmd_counts.append(int(child['Data']))
                cmd_count = int(child['Data'])
            
            # print(child['PID'])
            if child['Property'].endswith('.Application') and child['PID'] != pid:
                mismatch +=1
    
            if child['Property'].endswith('.CommandCountMax'):
                cmd_max = int(child['Data'])

        cmd_counts.append(cmd_count)  

    cmd_counts = np.array(cmd_counts)
    nNonZero = np.count_nonzero(cmd_counts)
    MaxCmd = int(max(cmd_counts))
    CmdCountRatio = float(mean(cmd_counts/cmd_max))
        
    return {
        'cmdscan.nHistories'   : nHistories,
        'cmdscan.nonZeroHist'  : nNonZero,
        'cmdscan.maxCmds'      : MaxCmd,
        'cmdscan.appMismatch'  : mismatch,
        'cmdscan.cmdCountRatio': CmdCountRatio,
    }



def extract_joblinks_features(jsondump):
    """
    Extracts behavioural metrics from `windows.joblinks` output.

    Returns
    -------
    dict with keys:
        joblinks.nJobObjs           : unique Job objects  (JobLink is null)
        joblinks.linkedProcRatio    : #PIDs with JobLink == 'Yes' / total
        joblinks.sessMismatchCount  : rows where JobSess != Sess
        joblinks.highActiveSkew     : rows where Active/Total > 0.8
        joblinks.nameEntropyMean    : mean entropy of Name strings
    """
    # --- load JSON -----------------------------------------------------------
    if isinstance(jsondump, str):          # path was passed in
        with open(jsondump, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:                                  # already-parsed object
        data = json.load(jsondump)

    flat = list(flatten_records(data))
    if not flat:        # keep columns stable on empty output
        return {
            'joblinks.nJobObjs'         : 0,
            'joblinks.linkedProcRatio'  : 0.0,
            'joblinks.sessMismatchCount': 0,
            'joblinks.highActiveSkew'   : 0,
            'joblinks.nameEntropyMean'  : 0.0,
        }

    # --- pre-compute helpers -------------------------------------------------
    total_rows   = len(flat)
    linked_rows  = sum(1 for r in flat if str(r.get("JobLink")).lower() == "yes")
    sess_mismatch= sum(1 for r in flat if r.get("JobSess") != r.get("Sess"))

    high_skew    = 0
    for r in flat:
        tot = r.get("Total") or 0
        if tot:
            active = r.get("Active") or 0
            if active / tot > 0.8:
                high_skew += 1

    name_entropy = [char_entropy(str(r.get("Name", ""))) for r in flat]
    name_entropy_mean = sum(name_entropy) / total_rows

    # Job objects = top-level rows (JobLink is null)
    n_jobobjs = sum(1 for r in flat if r.get("JobLink") in (None, "", "null"))

    linked_ratio = linked_rows / total_rows if total_rows else 0.0

    # --- package -------------------------------------------------------------
    return {
        'joblinks.nJobObjs'         : n_jobobjs,
        'joblinks.linkedProcRatio'  : round(linked_ratio, 4),
        'joblinks.sessMismatchCount': sess_mismatch,
        'joblinks.highActiveSkew'   : high_skew,
        'joblinks.nameEntropyMean'  : round(name_entropy_mean, 4),
    }


# def extract_pslist_features(jsondump):
#     df = pd.read_json(jsondump)
#     try:
#         a = df.PPID.size                                           #Number of Processes
#         b = df.PPID.nunique()                                  #Number of Parent Processes
#         c = df.Threads.mean()                  #Average Thread count
#         d = df.Handles.mean()                 #Average Handler count
#         e = len(df[df["Wow64"]=="True"])                     #Number of 64-Bit Processes
#         f = df.PPID.size - len(df[df["File output"]=="Disabled"]) #Number of processes with FileOutput enabled 
#     except:
#         a = None
#         b = None
#         c = None
#         d = None
#         e = None
#         f = None
#     return{
#         'pslist.nproc': a,
#         'pslist.nppid': b,
#         'pslist.avg_threads': c,
#         'pslist.avg_handlers': d,
#         'pslist.nprocs64bit': e,
#         'pslist.outfile': f
#     }

def extract_dlllist_features(jsondump):
    df = pd.read_json(jsondump)
    try:
        a = df.PID.size                                           #Total Number of all loaded libraries
        b = df.PID.unique().size                              #Number of Processes loading dlls
        c = df.PID.size/df.PID.unique().size             #Average loaded libraries per process
        d = df.Size.sum()/df.PID.unique().size                  #Average Size of loaded libraries
        e = df.PID.size - len(df[df["File output"]=="Disabled"]) #Number of loaded librearies outputting files
    except:
        a = None
        b = None
        c = None
        d = None
        e = None
    return{
        'dlllist.ndlls': a,
        'dlllist.nproc_dll': b,
        'dlllist.avg_dllPerProc': c,
        'dlllist.avgSize': d,
        'dlllist.outfile': e
    }

def extract_handles_features(jsondump):
    df = pd.read_json(jsondump)
    try:
        a = df.HandleValue.size                                #Total number of opened Handles
        b = df.HandleValue.unique().size                #Total number of distinct Handle Values
        c = df.PID.unique().size                                  #Number of processes with handles
        d = df.GrantedAccess.unique().size                      #Number of distinct GrantedAccess
        e = df.HandleValue.size/df.PID.unique().size#Average number of handles per process
        f = len(df[df["Type"]=="Port"])                       #Number of Type of Handles --> Ports
        g = len(df[df["Type"]=="Process"])                    #Number of Type of Handles --> Process
        h = len(df[df["Type"]=="Thread"])                   #Number of Type of Handles --> Thread
        i = len(df[df["Type"]=="Key"])                         #Number of Type of Handles --> Key
        j = len(df[df["Type"]=="Event"])                     #Number of Type of Handles --> Event
        k = len(df[df["Type"]=="File"])                      #Number of Type of Handles --> File
        l = len(df[df["Type"]=="Directory"])                   #Number of Type of Handles --> Directory
        m = len(df[df["Type"]=="Section"])                     #Number of Type of Handles --> Section
        n = len(df[df["Type"]=="Desktop"])                    #Number of Type of Handles --> Desktop
        o = len(df[df["Type"]=="Token"])                     #Number of Type of Handles --> Token
        p = len(df[df["Type"]=="Mutant"])                   #Number of Type of Handles --> Mutant
        q = len(df[df["Type"]=="KeyedEvent"])             #Number of Type of Handles --> KeyedEvent
        r = len(df[df["Type"]=="SymbolicLink"])           #Number of Type of Handles --> SymbolicLink
        s = len(df[df["Type"]=="Semaphore"])                #Number of Type of Handles --> Semaphore
        t = len(df[df["Type"]=="WindowStation"])            #Number of Type of Handles --> WindowStation
        u = len(df[df["Type"]=="Timer"])                     #Number of Type of Handles --> Timer
        v = len(df[df["Type"]=="IoCompletion"])                 #Number of Type of Handles --> IoCompletion
        w = len(df[df["Type"]=="WmiGuid"])                     #Number of Type of Handles --> WmiGuid
        x = len(df[df["Type"]=="WaitablePort"])           #Number of Type of Handles --> WaitablePort
        y = len(df[df["Type"]=="Job"])                         #Number of Type of Handles --> Job
        z = df.HandleValue.size - len(df[df["Type"]=="Port"]) - len(df[df["Type"]=="Process"]) - len(df[df["Type"]=="Thread"]) - len(df[df["Type"]=="Key"])  \
                                                    - len(df[df["Type"]=="Event"]) - len(df[df["Type"]=="File"]) - len(df[df["Type"]=="Directory"]) - len(df[df["Type"]=="Section"])\
                                                    - len(df[df["Type"]=="Desktop"]) - len(df[df["Type"]=="Token"]) - len(df[df["Type"]=="Mutant"]) - len(df[df["Type"]=="KeyedEvent"])\
                                                    - len(df[df["Type"]=="Semaphore"]) - len(df[df["Type"]=="WindowStation"]) - len(df[df["Type"]=="Timer"]) - len(df[df["Type"]=="IoCompletion"])\
                                                    - len(df[df["Type"]=="WaitablePort"]) - len(df[df["Type"]=="Job"]) - len(df[df["Type"]=="SymbolicLink"]) - len(df[df["Type"]=="WmiGuid"])
    except:
        a = None
        b = None
        c = None
        d = None
        e = None
        f = None        
        g = None
        h = None
        i = None
        j = None
        k = None
        l = None
        m = None
        n = None
        o = None
        p = None
        q = None
        r = None
        s = None
        t = None
        u = None
        v = None
        w = None
        x = None
        y = None
        z = None
                                                                                #Number of Type of Handles --> Unknown 
    return{
        'handles.nHandles': a,
        'handles.distinctHandles': b,
        'handles.nproc': c,
        'handles.nAccess': d,
        'handles.avgHandles_per_proc': e,
        'handles.nTypePort': f,
        'handles.nTyepProc': g,
        'handles.nTypeThread': h,
        'handles.nTypeKey': i,
        'handles.nTypeEvent': j,
        'handles.nTypeFile': k,
        'handles.nTypeDir': l,
        'handles.nTypeSec': m,
        'handles.nTypeDesk': n,
        'handles.nTypeToken': o,
        'handles.nTypeMutant': p,
        'handles.nTypeKeyEvent': q,
        'handles.nTypeSymLink': r,
        'handles.nTypeSemaph': s,
        'handles.nTypeWinSta': t,
        'handles.nTypeTimer': u,
        'handles.nTypeIO': v,
        'handles.nTypeWmi': w,
        'handles.nTypeWaitPort': x,
        'handles.nTypeJob': y,
        'handles.nTypeUnknown': z  
    }

def extract_ldrmodules_features(jsondump):
    df = pd.read_json(jsondump)
    return {
        'ldrmodules.total': df.Base.size,                                       #Number of total modules
        'ldrmodules.not_in_load': len(df[df["InLoad"]==False]),                 #Number of modules missing from load list
        'ldrmodules.not_in_init': len(df[df["InInit"]==False]),                 #Number of modules missing from init list
        'ldrmodules.not_in_mem': len(df[df["InMem"]==False]),                   #Number of modules missing from mem list
	'ldrmodules.nporc': df.Pid.unique().size,                               #Number of processes with modules in memory
        'ldrmodules.not_in_load_avg': len(df[df["InLoad"]==False])/df.Base.size,#Avg number of modules missing from load list
        'ldrmodules.not_in_init_avg': len(df[df["InInit"]==False])/df.Base.size,#Avg number of modules missing from init list
        'ldrmodules.not_in_mem_avg': len(df[df["InMem"]==False])/df.Base.size,  #Avg number of modules missing from mem list
    }

def extract_malfind_features(jsondump):
    df = pd.read_json(jsondump)
    return {                                                                        
        'malfind.ninjections': df.CommitCharge.size,                              #Number of hidden code injections found by malfind
	'malfind.commitCharge': df.CommitCharge.sum(),                            #Sum of Commit Charges over time                                
	'malfind.protection': len(df[df["Protection"]=="PAGE_EXECUTE_READWRITE"]),#Number of injections with all permissions 
	'malfind.uniqueInjections': df.PID.unique().size,                         #Number of unique injections
        'malfind.avgInjec_per_proc': df.PID.size/df.PID.unique().size,            #Average number of injections per process
        'malfind.tagsVad': len(df[df["Tag"]=="Vad"]),                             #Number of Injections tagged as Vad
        'malfind.tagsVads': len(df[df["Tag"]=="Vads"]),                           #Number of Injections tagged as Vads
        'malfind.aveVPN_diff': df['End VPN'].sub(df['Start VPN']).sum()           #Avg VPN size of injections
    }

# def extract_modules_features(jsondump):
#     df = pd.read_json(jsondump)
#     return {
#         'modules.nmodules': df.Base.size,                                          #Number of Modules
#         'modules.avgSize': df.Size.mean(),                             #Average size of the modules
#         'modules.FO_enabled': df.Base.size - len(df[df["File output"]=='Disabled'])#Number of Output enabled File Output
#     }

def extract_callbacks_features(jsondump):
    df = pd.read_json(jsondump)
    return {
        'callbacks.ncallbacks': df.Callback.size,                                               #Number of callbacks
        'callbacks.nNoDetail': len(df[df["Detail"]=='None']),                                   #Number of callbacks with no detail
        'callbacks.nBugCheck': len(df[df["Type"]=='KeBugCheckCallbackListHead']),               #Number of callback Type --> KeBugCheckCallbackListHead
        'callbacks.nBugCheckReason': len(df[df["Type"]=='KeBugCheckReasonCallbackListHead']),   #Number of callback Type --> KeBugCheckReasonCallbackListHead
        'callbacks.nCreateProc': len(df[df["Type"]=='PspCreateProcessNotifyRoutine']),          #Number of callback Type --> PspCreateProcessNotifyRoutine
        'callbacks.nCreateThread': len(df[df["Type"]=='PspCreateThreadNotifyRoutine']),         #Number of callback Type --> PspCreateThreadNotifyRoutine
        'callbacks.nLoadImg': len(df[df["Type"]=='PspLoadImageNotifyRoutine']),                 #Number of callback Type --> PspLoadImageNotifyRoutine
        'callbacks.nRegisterCB': len(df[df["Type"]=='CmRegisterCallback']),                     #Number of callback Type --> CmRegisterCallback
        'callback.nUnknownType': df.Callback.size - len(df[df["Type"]=='KeBugCheckCallbackListHead']) - len(df[df["Type"]=='CmRegisterCallback'])\
                                                  - len(df[df["Type"]=='KeBugCheckReasonCallbackListHead']) - len(df[df["Type"]=='PspLoadImageNotifyRoutine'])\
                                                  - len(df[df["Type"]=='PspCreateProcessNotifyRoutine']) - len(df[df["Type"]=='PspCreateThreadNotifyRoutine']),
                                                                                                #Number of callback Type --> UNKNOWN
                
    }

def extract_cmdline_features(jsondump):
    df = pd.read_json(jsondump)
    return{
        'cmdline.nLine': df.PID.size,                                                           #Number of cmd operations
        'cmdline.not_in_C': df.PID.size - df['Args'].str.startswith("C:").sum(),                #Number of cmd initiating from C drive
        'cmdline.n_exe': df['Process'].str.endswith("exe").sum(),                               #Number of cmd line exe
        'cmdline.n_bin': df['Process'].str.endswith("bin").sum(),                               #Number of cmd line bin
    }

def extract_devicetree_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'devicetree.ndevice': df.Type.size,                                                     #Number of devices in Device tree
        'devicetree.nTypeNotDRV': df.Type.size - len(df[df["Type"]=='DRV']),                    #Number of devices with other than DRV type
    }

def extract_driverirp_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'driverirp.nIRP': df.IRP.size,                                                          #Number of deviceirps
        'driverirp.nModules': df.Module.unique().size,                                          #Number of diff modules
        'driverirp.nSymbols': df.Symbol.unique().size,                                          #Number fo diff Symbols
        'driverirp.n_diff_add': df.Address.unique().size,                                       #Number of diff address
    }

def extract_drivermodule_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'drivermodule.nModules': df.Offset.size,                                                #Numner of driver module
    }

def extract_driverscan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'driverscan.nscan': df.Name.size,                                                       #Number of driverscans
        'driverscan.avgSize': df.Size.sum()/df.Name.size,                                       #Average size of scan
    }

# def extract_dumpfiles_features(jsondump):     ##### Use if you need the features as creates a lot of garbage in VOLMEMLYZER Folder
#     df=pd.read_json(jsondump)
#     return{
#         'dumpfiles.ndump': df.FileObject.size,                                                  #Number of dump files
#         'dumpfiles.nCache': df.Cache.unique().size,                                             #Number of Cache
#         'dumpfiles.nFile': df.FileName.unique().size,                                           #Number of distinct files
#     }

def extract_envars_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'envars.nVars': df.Value.size,                                                          #Number of environment variables
        'envars.nProc': df.PID.unique().size,                                                   #Number of Processes using Env vars
        'envars.nBlock': df.Block.unique().size,                                                #Number of Blocks 
        'envars.n_diff_var': df.Variable.unique().size,                                         #Number of diff variable names
        'envars.nValue': df.Value.unique().size,                                                #Number of distinct value entries
    }

def extract_filescan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'filescan.nFiles': df.Name.size,                                                        #Number of files
        'filescan.n_diff_file': df.Name.unique().size,                                          #Number of distinct files
    }

def extract_getsids_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'getsids.nSIDcalls': df.SID.size,                                                       #Number of Security Identifier calls
        'getsids.nProc': df.PID.unique().size,                                                  #Number of processes
        'getsids.nDiffName': df.Name.unique().size,                                             #Number of Names
        'getsids.n_diff_sids': df.SID.unique().size,                                            #Number of Unique SIDs
        'getsids.avgSIDperProc': df.SID.size/df.PID.unique().size,                              #Avg number of SID per Process        
    }

def extract_mbrscan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'mbrscan.nMBRentries': df.Bootable.size,                                                #Number of MBR entries
        'mbrscan.nDiskSig': df["Disk Signature"].unique().size,                                 #Number of Disk Signatures
        'mbrscan.nPartType': df.PartitionType.unique().size,                                    #Number of partition type
        'mbrscan.bootable': df.Bootable.size - df.Bootable.isna().size                          #Numner of bootable 
    }

def extract_memmap_features(jsondump):
    df=pd.read_json(jsondump)
    try:
        a = len(df)
        b = len(df.Physical) - len(df[df['File output'] == 'Enabled'])
        c = df['__children'].apply(len).mean()
    except:
        a = None
        b = None
        c = None

    return{
        'memmap.nEntries': a,
        'memmap.nEnabledF_op': b,
        'memmap.AvgChildren': c     
    }

def extract_mftscan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'mftscan.nEntriesMFT': len(df), #101
        'mftscan.nAttributeType': df['Attribute Type'].nunique(),
        'mftscan.nRecordType': df['Record Type'].nunique(),
        'mftscan.AvgRecordNum': df['Record Number'].mean(),
        'mftscan.AvgLinkCount': df['Link Count'].mean(),
        'mftscan.0x9_typeMFT': len(df[df['MFT Type'] == '0x9']),
        'mftscan.0xd_typeMFT': len(df[df['MFT Type'] == '0xd']),
        'mftscan.DirInUse_typeMFT': len(df[df['MFT Type'] == 'DirInUse']),
        'mftscan.Removed_typeMFT': len(df[df['MFT Type'] == 'Removed']),
        'mftscan.File_typeMFT': len(df[df['MFT Type'] == 'File']),
        'mftscan.Other_typeMFT': len(df[~df['MFT Type'].isin(['0x9','0xd','DirInUse','Removed','File'])]),
        'mftscan.AvgChildren': df['__children'].apply(len).mean()
    }

def extract_modscan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'modscan.nMod': len(df),   #List of Loaded Kernel Modules #113
        'modscan.nUniqueExt': len(df['Name'].str.extract(r'\.(\w+)$')[0].str.lower().unique()) - 1, 
        'modscan.nDLL': len(df[df['Name'].str.endswith('.dll','.DLL')]),
        'modscan.nSYS': len(df[df['Name'].str.endswith('.sys','.SYS')]),
        'modscan.nEXE': len(df[df['Name'].str.endswith('.exe','.EXE')]),
        'modscan.nOthers': len(df) - len(df[df['Name'].str.endswith('.dll','.DLL')]) - len(df[df['Name'].str.endswith('.sys','.SYS')]) - len(df[df['Name'].str.endswith('.exe','.EXE')]),
        'modscan.AvgSize': df['Size'].mean(),
        'modscan.MeanChildExist': df['__children'].apply(lambda x: len(x) if isinstance(x, list) else 0).astype(bool).mean(), # CHIld exist 1 else 0
        'modscan.FO_Enabled': len(df[df['File output'] == 'Enabled'])
    }

def extract_mutantscan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'mutantscan.nMutantObjects': len(df),
        'mutantscan.nNamedMutant': df['Name'].isna().sum() 
    }

def extract_netscan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'netscan.nConn': len(df),
        'netscan.nDistinctForeignAdd': df.ForeignAddr.unique().size,
        'netscan.nDistinctForeignPort': df.ForeignPort.unique().size,
        'netscan.nDistinctLocalAddr': df.LocalAddr.unique().size,
        'netscan.nDistinctLocalPort': df.LocalPort.unique().size,
        'netscan.nOwners': df.Owner.unique().size,
        'netscan.nDistinctProc': df.PID.unique().size,
        'netscan.nListening': len(df[df['State'].isin(['LISTENING'])]),
        'netscan.Proto_TCPv4': len(df[df["Proto"]=="TCPv4"]),
        'netscan.Proto_TCPv6': len(df[df["Proto"]=="TCPv4"]),
        'netscan.Proto_UDPv4': len(df[df["Proto"]=="UDPv4"]),
        'netscan.Proto_UDPv6': len(df[df["Proto"]=="UDPv6"])
    }

def extract_netstat_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'netstat.nConn': len(df),
        'netstat.nDistinctForeignAdd': df.ForeignAddr.unique().size,
        'netstat.nUnexpectForeignAdd': df[df['ForeignAddr'].isin(['::','*'])].shape[0],
        'netscan.nDistinctForeignPort': df.ForeignPort.unique().size,
        'netstat.nDistinctLocalAddr': df.LocalAddr.unique().size,
        'netstat.nUnexpectLocalAddr': df[df['LocalAddr'].isin(['::','::1'])].shape[0],
        'netstat.nDistinctLocalPort': df.LocalPort.unique().size,
        'netstat.nOwners': df.Owner.unique().size,
        'netstat.nDistinctProc': df.PID.unique().size,
        'netstat.nListening': len(df[df['State'].isin(['LISTENING'])]),
        'netstat.nEstablished': len(df[df['State'].isin(['ESTABLISHED'])]),
        'netstat.nClose_wait': len(df[df['State'].isin(['CLOSE_WAIT'])]),
        'netstat.Proto_TCPv4': len(df[df["Proto"]=="TCPv4"]),
        'netstat.Proto_TCPv6': len(df[df["Proto"]=="TCPv4"]),
        'netstat.Proto_UDPv4': len(df[df["Proto"]=="UDPv4"]),
        'netstat.Proto_UDPv6': len(df[df["Proto"]=="UDPv6"]),
        'netstat.nNaNPID': df['PID'].isna().sum() 
    }

def extract_poolscanner_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'poolscanner.nPool': len(df),
        'poolscanner.nUniquePool': df.Tag.unique().size,
    }

def extract_privileges_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'privileges.nTotal': len(df),
        'privileges.nUniquePrivilege': df.Privilege.nunique(),
        'privileges.nPID': df.PID.nunique(),
        'privileges.nProcess': df.Process.nunique(),
        'privileges.nAtt_D': len(df[df["Attributes"]=="Default"]),
        'privileges.nAtt_P': len(df[df["Attributes"]=="Present"]),
        'privileges.nAtt_PE': len(df[df["Attributes"]=="Present,Enabled"]),
        'privileges.nAtt_PED': len(df[df["Attributes"]=="Present,Enabled,Default"]),
        'privileges.nAtt_NaN': df['Attributes'].isna().sum() 
    }

def extract_pstree_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'pstree.nTree': len(df),
        'pstree.nHandles': len(df) - df['Handles'].isna().sum(),
        'pstree.nPID': df.PID.nunique(),
        'pstree.nPPID': df.PPID.nunique(),
        'pstree.AvgThreads': df.Threads.mean(),
        'pstree.nWow64': len(df[df["Wow64"]=="True"]),
        'pstree.AvgChildren': df['__children'].apply(len).mean()
    }

def extract_registry_certificates_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'registry.certificates.nCert': len(df),
        'registry.certificates.nID_Auto': len(df[df["Certificate ID"]=="AutoUpdate"]),
        'registry.certificates.nID_Protected': len(df[df["Certificate ID"]=="ProtectedRoots"]),
        'registry.certificates.nID_Others': len(df[~df['Certificate ID'].isin(['AutoUpdate','ProtectedRoots'])]) #174
    }

def extract_registry_hivelist_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'registry.hivelist.nFiles': len(df),
        'registry.hivelist.nFO_Enabled': len(df) - len(df[df["File output"]=="Disabled"])
    }

def extract_registry_hivescan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'registry.hivescan.nHives': len(df),
        'registry.hivescan.Children_exist': df['__children'].apply(lambda x: len(x) if isinstance(x, list) else 0).astype(bool).sum()  
    }

def extract_registry_printkey_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'registry.printkey.nKeys': len(df),
        'registry.printkey.nDistinct': df.Name.nunique(),
        'registry.printkey.nType_key': len(df[df["Type"]=="Key"]),
        'registry.printkey.nType_other': len(df) - len(df[df["Type"]=="Key"]),
        'registry.printkey.Volatile_0': len(df[df["Volatile"]==0]),
        'registry.printkey.Avg_Children': df['__children'].apply(len).mean() 
    }

def extract_registry_userassist_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'registry.userassist.n': len(df),
        'registry.userassist.nUnique': df["Hive Name"].nunique(),
        'registry.userassist.Avg_Children': df['__children'].apply(len).mean(),
        'registry.userassist.path_DNE': len(df[df["Path"]=="None"]),
        'registry.userassist.type_key': len(df[df["Type"]=="Key"]),
        'registry.userassist.type_other': len(df) - len(df[df["Type"]=="Key"])
    }

def extract_sessions_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'sessions.nSessions': len(df),
        'sessions.nProcess': df.Process.nunique(),
        'sessions.nUsers': df["User Name"].nunique(),
        'sessions.nType': df["Session Type"].nunique(),
        'sessions.Children_exist': df['__children'].apply(lambda x: len(x) if isinstance(x, list) else 0).astype(bool).sum()
    }

def extract_skeleton_key_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'skeleton_key.nKey': len(df),
        'skeleton_key.nProcess': df.Process.nunique(),
        'skeleton_key.Found_True': len(df[df["Skeleton Key Found"]=="True"]),
        'skeleton_key.Found_False': len(df[df["Skeleton Key Found"]=="False"])
    }

def extract_ssdt_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'ssdt.n': len(df),
        'ssdt.nIndex': df.Index.nunique(),
        'ssdt.nModules': df.Module.nunique(),
        'ssdt.nSymbols': df.Symbol.nunique(),
        'ssdt.Children_exist': df['__children'].apply(lambda x: len(x) if isinstance(x, list) else 0).astype(bool).sum() 
    }

def extract_statistics_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'statistics.Invalid_all': int(df.loc[0].at["Invalid Pages (all)"]),
        'statistics.Invalid_large': int(df.loc[0].at["Invalid Pages (large)"]),
        'statistics.Invalid_other': int(df.loc[0].at["Other Invalid Pages (all)"]),
        'statistics.Swapped_all': int(df.loc[0].at["Swapped Pages (all)"]),
        'statistics.Swapped_large': int(df.loc[0].at["Swapped Pages (large)"]),
        'statistics.Valid_all': int(df.loc[0].at["Valid pages (all)"]),
        'statistics.Valid_large': int(df.loc[0].at["Valid pages (large)"])
    }


def extract_svcscan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'svcscan.nServices': len(df),
        'svcscan.nUniqueServ': df.Name.nunique(),
        'svcscan.State_Run': len(df[df["State"]=="SERVICE_RUNNING"]),
        'svcscan.State_Stop': len(df[df["State"]=="SERVICE_STOPPED"]),
        'svcscan.Start_Sys': len(df[df["Start"]=="SERVICE_SYSTEM_START"]),
        'svcscan.Start_Auto': len(df[df["Start"]=="SERVICE_AUTO_START"]),
        'svcscan.Type_Own_Share': len(df[df["Type"]=="SERVICE_WIN32_OWN_PROCESS|SERVICE_WIN32_SHARE_PROCESS"]),
        'svcscan.Type_Own': len(df[df["Type"]=="SERVICE_WIN32_OWN_PROCESS"]),
        'svcscan.Type_Share': len(df[df["Type"]=="SERVICE_WIN32_SHARE_PROCESS"]),
        'svcscan.Type_Own_Interactive': len(df[df["Type"]=="SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS"]),
        'svcscan.Type_Share_Interactive': len(df[df["Type"]=="SERVICE_WIN32_SHARE_PROCESS|SERVICE_INTERACTIVE_PROCESS"]),
        'svcscan.Type_Kernel_Driver': len(df[df["Type"]=="SERVICE_KERNEL_DRIVER"]),
        'svcscan.Type_FileSys_Driver': len(df[df["Type"]=="SERVICE_FILE_SYSTEM_DRIVER"]),
        'svcscan.Type_Others': len(df[~df['Type'].isin(['SERVICE_WIN32_OWN_PROCESS|SERVICE_WIN32_SHARE_PROCESS','SERVICE_WIN32_OWN_PROCESS','SERVICE_KERNEL_DRIVER','SERVICE_WIN32_SHARE_PROCESS','SERVICE_FILE_SYSTEM_DRIVER','SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS','SERVICE_WIN32_SHARE_PROCESS|SERVICE_INTERACTIVE_PROCESS'])])
    }

def extract_symlinkscan_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'symlinkscan.nLinks': len(df),
        'symlinkscan.nFrom': df["From Name"].nunique(),
        'symlinkscan.nTo': df["To Name"].nunique(),
        'symlinkscan.Avg_Children': df['__children'].apply(len).mean()
    }

def extract_vadinfo_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'vadinfo.nEntries': len(df),
        'vadinfo.nFile': df.File.nunique(),
        'vadinfo.nPID': df.PID.nunique(),
        'vadinfo.nParent': df.Parent.nunique(),
        'vadinfo.nProcess': df.Process.nunique(),
        'vadinfo.Process_Malware': len(df[df["Process"]=="malware.exe"]),   ##### Tells if malware ran or not
        'vadinfo.Type_Vad': len(df[df["Tag"]=="Vad "]),
        'vadinfo.Type_VadS': len(df[df["Tag"]=="VadS"]),
        'vadinfo.Type_VadF': len(df[df["Tag"]=="VadF"]),
        'vadinfo.Type_VadI': len(df[df["Tag"]=="VadI"]),
        'vadinfo.Protection_RO': len(df[df["Protection"]=="PAGE_READONLY"]),
        'vadinfo.Protection_RW': len(df[df["Protection"]=="PAGE_READWRITE"]),
        'vadinfo.Protection_NA': len(df[df["Protection"]=="PAGE_NOACCESS"]),
        'vadinfo.Protection_EWC': len(df[df["Protection"]=="PAGE_EXECUTE_WRITECOPY"]),
        'vadinfo.Protection_WC': len(df[df["Protection"]=="PAGE_WRITECOPY"]),
        'vadinfo.Protection_ERW': len(df[df["Protection"]=="PAGE_EXECUTE_READWRITE"]),
        'vadinfo.Avg_Children': df['__children'].apply(len).mean()
    }

def extract_vadwalk_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'vadwalk.Avg_Size': (df['End'] - df['Start']).mean(),
    }

def extract_verinfo_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'verinfo.nEntries': len(df),
        'verinfo.nUniqueProg': df.Name.nunique(),
        'verinfo.nPID': df.PID.nunique(),
        'verinfo.Avg_Children': df['__children'].apply(len).mean()
    }

def extract_virtmap_features(jsondump):
    df=pd.read_json(jsondump)
    return{
        'virtmap.nEntries': len(df),
        'virtmap.Avg_Offset_Size': (df['Start offset'] - df['End offset']).mean(),
        'virtmap.Avg_Children': df['__children'].apply(len).mean() #254
    }