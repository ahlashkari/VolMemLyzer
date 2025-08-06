import pandas as pd
import numpy as np
from datetime import datetime, timezone
import math
import json
from utils import *
from collections import Counter
import re
from statistics import mean


#### fix ioc keyword input
#### fix time baseline for the dump

# Added empty handling 
def extract_amcache_features(jsondump, **kwargs):    
    
    df = pd.read_json(jsondump)
    keys = ["amcache.nEntries", "amcache.nUniqueSHA1",  
        "amcache.CompileAfterDump", "amcache.InstallAfterDump",    
        "amcache.LastModifyAfterDump",  "amcache.nonMicrosoftRatio", 
        "amcache.outsideSystem32",  "amcache.fileAgeDays_mean"]

    if df.empty:
        return {k: None for k in keys}
    
    compile_ts = pd.to_datetime(df["CompileTime"].dropna(),    errors="coerce", utc=True)
    install_ts = pd.to_datetime(df["InstallTime"].dropna(),    errors="coerce", utc=True)
    modify_ts  = pd.to_datetime(df["LastModifyTime"].dropna(), errors="coerce", utc=True)
    dump_ts = kwargs.get('amcache', None)

    if dump_ts:
        CompileAfterDump = float(compile_ts.gt(dump_ts).sum() / len(compile_ts)) if len(compile_ts) else None
        InstallAfterDump = float(install_ts.gt(dump_ts).sum() / len(install_ts)) if len(install_ts) else None
        LastModifyAfterDump = float(modify_ts.gt(dump_ts).sum() / len(modify_ts)) if len(modify_ts) else None
        FileAgeDays_mean = float((dump_ts - modify_ts).dt.total_seconds().div(86400).mean()) if len(modify_ts) else None
    else:
        CompileAfterDump = InstallAfterDump = LastModifyAfterDump = FileAgeDays_mean = None


    return {
        "amcache.nEntries"            : len(df),
        "amcache.nUniqueSHA1"         : df["SHA1"].nunique(),
        "amcache.CompileAfterDump"    : CompileAfterDump,
        "amcache.InstallAfterDump"    : InstallAfterDump,
        "amcache.LastModifyAfterDump" : LastModifyAfterDump,
        "amcache.nonMicrosoftRatio"   : float((df["Company"].fillna("").str.lower() != "microsoft corporation").mean()),
        "amcache.outsideSystem32"     : int(df["Path"].fillna("").str.lower().apply(not_system_path).sum()),
        "amcache.fileAgeDays_mean"    : FileAgeDays_mean,
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

    tags             = df['Tag'].dropna().astype(str)
    tag_entropy_mean = tags.apply(char_entropy).mean() if not tags.empty else 0.0
    tag_rare         = (tags.value_counts() == 1).sum()

    return {
        'bigpools.nAllocs'       : int(len(df)),
        'bigpools.sumBytes'      : int(df['NumberOfBytes'].sum()),
        'bigpools.maxBytes'      : int(df['NumberOfBytes'].max()),
        'bigpools.avgBytes'      : float(df['NumberOfBytes'].mean()),
        'bigpools.largeAllocs'   : int((df['NumberOfBytes'] > (1 << 20)).sum()),
        'bigpools.nonPagedRatio' : float(df['PoolType'].str.contains('nonpaged', case=False, na=False).mean()),
        'bigpools.tagEntropyMean': float(tag_entropy_mean),
        'bigpools.tagRare'       : int(tag_rare),
    }

def extract_callbacks_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'callbacks.ncallbacks',     'callbacks.nNoDetail',      'callbacks.nBugCheck',
        'callbacks.nBugCheckReason','callbacks.nCreateProc',    'callbacks.nCreateThread',
        'callbacks.nLoadImg',       'callbacks.nRegisterCB',     # V2 features
        'callbacks.distinctModules','callbacks.maxPerModule',   'callbacks.genericKernel',
        'callbacks.noSymbol'        # New features
    ]

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    features = {
        'callbacks.ncallbacks': total,
        'callbacks.nNoDetail': int(df['Detail'].isna().sum()),
        'callbacks.nBugCheck': int((df['Type'] == 'KeBugCheckCallbackListHead').sum()),
        'callbacks.nBugCheckReason': int((df['Type'] == 'KeBugCheckReasonCallbackListHead').sum()),
        'callbacks.nCreateProc': int((df['Type'] == 'PspCreateProcessNotifyRoutine').sum()),
        'callbacks.nCreateThread': int((df['Type'] == 'PspCreateThreadNotifyRoutine').sum()),
        'callbacks.nLoadImg': int((df['Type'] == 'PspLoadImageNotifyRoutine').sum()),
        'callbacks.nRegisterCB': int((df['Type'] == 'CmRegisterCallback').sum()),
    }

    # new metrics inlined
    features.update({
        'callbacks.distinctModules': df['Module'].nunique(),
        'callbacks.maxPerModule': round(df.groupby('Module').size().max() / total, 4),
        'callbacks.genericKernel': int((df['Type'] == 'GenericKernelCallback').sum()),
        'callbacks.noSymbol': int(df['Symbol'].isna().sum())
    })

    return features

def extract_cmdline_features(jsondump):
    df = pd.read_json(jsondump)

    features = {
        'cmdline.nLine': df.PID.size,                                                           # Number of cmd operations
        'cmdline.not_in_C': df.PID.size - df['Args'].str.startswith("C:").sum(),                # Number of cmd initiating from C drive
        'cmdline.n_exe': df['Process'].str.endswith("exe").sum(),                               # Number of cmd line exe
        'cmdline.n_bin': int(df['Process'].str.endswith("bin").sum()),                               # Number of cmd line bin
    }

    # New features
    features.update({
        'cmdline.argsNull': int(df['Args'].isna().sum()),                                            # Number of rows where Args == null
        'cmdline.scriptExec': df['Args'].str.endswith(tuple(['.ps1', '.bat', '.vbs', '.js', '.hta'])).sum(),  # Script execution (PowerShell, bat, etc.)
        'cmdline.urlInArgs': df['Args'].str.contains(r'https?://').sum(),                       # Number of cmd lines containing URLs
        'cmdline.netPath': df['Args'].str.startswith('\\\\').sum(),                             # Number of cmd lines with UNC paths
        'cmdline.avgArgLen': df['Args'].str.len().mean() if df['Args'].notna().sum() > 0 else None,  # Average argument length
        'cmdline.distinctProcesses': df['Process'].nunique(),                                  # Unique process names
    })
    
    return features


def extract_cmdscan_features(jsondump):
    """
        cmdscan.nHistories        : total _COMMAND_HISTORY blocks
        cmdscan.nonZeroHist       : # blocks with CommandCount > 0
        cmdscan.maxCmds           : largest CommandCount observed
        cmdscan.appMismatch       : # blocks where Application ≠ parent Process
        cmdscan.cmdCountRatio     : mean(CommandCount / CommandCountMax)
    """
    df = pd.read_json(jsondump)       
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
        
    for _, row in cmd_df.iterrows():
        pid = row['PID']
        children_arr =  row['__children'] 
        
        for child in children_arr:
            if child['Property'].endswith(".CommandCount"): 
                cmd_count = int(child['Data'])

            if child['Property'].endswith('.Application') and child['PID'] != pid:
                mismatch +=1
    
            if child['Property'].endswith('.CommandCountMax'):
                cmd_max = int(child['Data'])

        cmd_counts.append(cmd_count)  

    cmd_counts = np.array(cmd_counts)
        
    return {
        'cmdscan.nHistories'   : nHistories,
        'cmdscan.nonZeroHist'  : np.count_nonzero(cmd_counts),
        'cmdscan.maxCmds'      : int(max(cmd_counts)),
        'cmdscan.appMismatch'  : mismatch,
        'cmdscan.cmdCountRatio': float(mean(cmd_counts/cmd_max)),
    }



def extract_consoles_features(jsondump):
    """
    Extract all seven console metrics from windows.consoles JSON.
    Expects `jsondump` to be a file‐like handle (open(…, 'r')) whose
    contents are the raw JSON array emitted by `windows.consoles -r json`.
    """
    df = pd.read_json(jsondump)
   
    if df.empty:
        return {k: None for k in [
            'consoles.nConhost',
            'consoles.avgProcPerConsole',
            'consoles.maxProcPerConsole',
            'consoles.emptyHistoryRatio',
            'consoles.histBufOverflow',
            'consoles.titleSuspicious',
            'consoles.dumpIoC',
        ]}

    children = pd.json_normalize(df['__children'].explode().dropna())
    nConhost = len(df)

    proc_counts = children[children['Property'].str.endswith('.ProcessCount')].copy()
    proc_counts['Data'] = pd.to_numeric(proc_counts['Data'], errors='coerce').fillna(0)
    avg_proc = proc_counts['Data'].mean()
    max_proc = proc_counts['Data'].max()

    cmd_counts = children[children['Property'].str.endswith('.CommandCount')]
    total_cmds = len(cmd_counts)
    null_cmds = cmd_counts['Data'].isin([None, '', []]).sum()
    empty_hist_ratio = null_cmds / total_cmds if total_cmds else 0

    hb_df = children[children['Property'].str.endswith('.HistoryBufferCount')][['PID', 'Data']].rename(columns={'Data': 'HBCount'})
    hbmax_df = children[children['Property'].str.endswith('.HistoryBufferMax')][['PID', 'Data']].rename(columns={'Data': 'HBMax'})
    hb_merged = pd.merge(hb_df, hbmax_df, on='PID', how='inner')
    hb_merged = hb_merged.apply(pd.to_numeric, errors='coerce')
    buf_overflow = (hb_merged['HBCount'] == hb_merged['HBMax']).sum()

    titles = children[children['Property'].str.endswith('.Title')]['Data'].dropna().astype(str)
    orig_titles = children[children['Property'].str.endswith('.OriginalTitle')]['Data'].dropna().astype(str)
    title_susp = sum(titles.apply(not_system_path)) + sum(orig_titles.apply(not_system_path))

    dumps = children[children['Property'].str.endswith('.Dump')]['Data'].dropna().astype(str).str.lower()
    IOC_KEYWORDS = ["curl", "http", "invoke-webrequest", "mimikatz"]
    dump_ioc = dumps.apply(lambda s: any(kw in s for kw in IOC_KEYWORDS)).sum()

    return {
        'consoles.nConhost': int(nConhost),
        'consoles.avgProcPerConsole': round(avg_proc, 2),
        'consoles.maxProcPerConsole': int(max_proc),
        'consoles.emptyHistoryRatio': round(empty_hist_ratio, 3),
        'consoles.histBufOverflow': int(buf_overflow),
        'consoles.titleSuspicious': int(title_susp),
        'consoles.dumpIoC': int(dump_ioc),
    }

def extract_deskscan_features(jsondump, **kwargs):
    """
    Extractor for windows.deskscan → computes:
      • deskscan.totalEntries         : total number of Desktop objects
      • deskscan.uniqueDesktops       : count of distinct Desktop names
      • deskscan.uniqueWinStations    : count of distinct Window Station names
      • deskscan.session0GuiCount     : rows where Session==0 AND Window Station=="WinSta0"
      • deskscan.topProcDesktopRatio  : max windows owned by one Process ÷ totalEntries
    """
    df = pd.read_json(jsondump)  
    keys = ['deskscan.totalEntries', 'deskscan.uniqueDesktops',
            'deskscan.uniqueWinStations',  'deskscan.session0GuiCount',  
            'deskscan.topProcDesktopRatio', "deskscan.nOrphanDesktops",
            'deskscan.nondefaultdesktops']
    
    if df.empty:
        return {k : None for k in keys}

    
    pids = kwargs.get('deskscan', [])
    total = len(df)
    proc_counts = df['Process'].value_counts()
    top_owner   = proc_counts.iloc[0] if not proc_counts.empty else 0

    # ── Orphan desktops ───────────
    defaults     = {"Default", "Winlogon"}
    unique_names = df["Desktop"].dropna().unique()
    if len(pids):
        orphan_desktops = sum(1 for pid in df['PID'].values if pid not in pids)
    else:
        orphan_desktops = None

    return {
        'deskscan.totalEntries'        : total,
        'deskscan.uniqueDesktops'      : df['Desktop'].nunique(),
        'deskscan.uniqueWinStations'   : df['Window Station'].nunique(),
        'deskscan.session0GuiCount'    : df[(df['Session'] == 0) &  (df['Window Station'] == 'WinSta0')].shape[0],
        'deskscan.topProcDesktopRatio' : float(top_owner / total if total else 0.0),
        "deskscan.nOrphanDesktops"     : orphan_desktops,
        'deskscan.nondefaultdesktops': sum(1 for name in unique_names if name not in defaults)
    }


def extract_devicetree_features(jsondump):
    df = pd.read_json(jsondump)

    # Existing v2 features
    features = {
        'devicetree.ndevice': df['Type'].size,  # Number of devices in device tree
        'devicetree.nTypeNotDRV': df['Type'].size - len(df[df["Type"] == 'DRV']),  # Number of devices not of type DRV
    }

    # New features
    features.update({
        'devicetree.uniqueDrivers': df['DriverName'].nunique(),  # Number of unique drivers
        'devicetree.driverEntropy': shannon_entropy(df['DriverName']) if len(df) > 0 else None,  # Entropy of driver names                                         
        'devicetree.maxDepth': int(df['__children'].apply(get_depth).max()) if df['__children'].notna().any() else None,  # Max depth of device tree
        'devicetree.avgChildrenPerDRV': df[df['Type'] == 'DRV']['__children'].apply(len).mean() if len(df[df['Type'] == 'DRV']) > 0 else None,  # Avg children per DRV
        'devicetree.attToNullDriver': len(df[(df['Type'] == 'ATT') & df['DriverNameOfAttDevice'].isna()]),  # Attachments with null drivers
        'devicetree.nonDrvAttachRatio': len(df[df['Type'] != 'DRV']) / len(df) if len(df) > 0 else None,  # Non-DRV attachment ratio
        'devicetree.diskDevRatio': len(df[df['DeviceType'] == 'FILE_DEVICE_DISK']) / len(df) if len(df) > 0 else None,  # Ratio of disk devices
        'devicetree.busExtenderRatio': len(df[df['DeviceType'] == 'FILE_DEVICE_BUS_EXTENDER']) / len(df) if len(df) > 0 else None,  # Ratio of bus extender devices
    })
    
    return features


def extract_dlllist_features(jsondump):
    df = pd.read_json(jsondump)
    if df.empty:                         # early‑out for empty inputs
        return {}

    df['LoadTime'] = pd.to_datetime(df['LoadTime'], errors='coerce')
    pid_count = df['PID'].nunique() or 1  # avoid zero‑division

# then:
    features = {
        # Core counts / averages
        'dlllist.ndlls'            : df.shape[0],
        'dlllist.nproc_dll'        : int(pid_count),
        'dlllist.avg_dllPerProc'   : df.shape[0] / float(pid_count),
        'dlllist.avgSize'          : float(df['Size'].sum() / float(pid_count)),
        'dlllist.outfile'          : int(df.shape[0] - (df['File output'] == 'Disabled').sum()),
    }

    features.update({
        # New heuristics
        'dlllist.nonSystemPathRatio': int(df['Path'].apply(not_system_path).sum()),
        'dlllist.tempDirDlls'       : int(df['Path'].str.lower().str.contains(r'(?:%temp%|\\temp\\|appdata)', na=False).sum()),
        'dlllist.globalSharedDlls'  : df.groupby('Name')
                                          .filter(lambda x: len(x) / pid_count >= 0.5).shape[0],
        'dlllist.uniqueDllRatio'    : df['Name'].nunique() / float(df.shape[0]),
        'dlllist.smallDllCount'     : int((df['Size'] < 10_240).sum()),
        'dlllist.hugeDllCount'      : int((df['Size'] > 20_971_520).sum()),
        'dlllist.maxLoadDelaySec'   : int(
            (df['LoadTime'] - df.groupby('PID')['LoadTime'].transform('first'))
            .dt.total_seconds()
            .max()
        ),
    })

    return features


def extract_driverirp_features(jsondump):
    df = pd.read_json(jsondump)
    
    # Existing v2 features
    features = {
        'driverirp.nIRP': df['IRP'].size,                                                      # Number of device IRPs
        'driverirp.nModules': df['Module'].unique().size,                                      # Number of different modules
        'driverirp.nSymbols': df['Symbol'].unique().size,                                      # Number of different symbols
        'driverirp.n_diff_add': df['Address'].unique().size,                                   # Number of different addresses
    }
    
    # New features
    features.update({
        'driverirp.invalidHandlerRatio': len(df[df['Symbol'] == 'IopInvalidDeviceRequest']) / len(df) if len(df) > 0 else None,  # Invalid handler ratio
        'driverirp.nullSymbolCount': df['Symbol'].isna().sum(),  # Null symbol count
        'driverirp.entropyIRPTypes': shannon_entropy(df['IRP']) if len(df) > 0 else None,  # Entropy of IRP types
        'driverirp.sameAddressMultiDriver': (df['Address'].value_counts() > 1).sum(),  # Count of same address used by multiple drivers
    })
    return features



def extract_drivermodule_features(jsondump):
    df=pd.read_json(jsondump)
    features = {
        'drivermodule.nModules': df.Offset.size,                                                #Numner of driver module
    }

    features.update({
        'drivermodule.knownExceptionRatio'  : float(df['Known Exception'].sum() / len(df)),
        'drivermodule.altNameMismatch'      : int((~df['Alternative Name'].str.startswith(('\\FileSystem', '\\Driver'))).sum()),
        'drivermodule.noServiceKeyCount'    : int(df['Service Key'].isna().sum()),
    })

    return features


def extract_driverscan_features(jsondump):
    df=pd.read_json(jsondump)
    features = {
        'driverscan.nscan': df.Name.size,                                                       #Number of driverscans
        'driverscan.avgSize': float(df.Size.sum()/df.Name.size),                                       #Average size of scan)
    }

    features.update({
        'driverscan.sizeZeroCount' : df[df['Size'] == 0].shape[0],  
        'driverscan.nullServiceKeyRatio' : float(df[df['Service Key'].isna()].shape[0] / len(df)),
        'driverscan.largeDriverCount' : int(df[df['Size'] > 2 * math.pow(10,6)].shape[0]),
        'driverscan.miniDriverCount' : int(df[(df['Size'] < 2 * math.pow(10, 3)) & (df['Size'] > 0)].shape[0]),
        'driverscan.nameEntropyMean' : float(df['Name'].dropna().apply(shannon_entropy).mean()), 
        'driverscan.nonAsciiNameCount' : int(df['Name'].dropna().apply(is_non_ascii).sum()), 
        'driverscan.duplicateStartAddr' : int(df['Start'].value_counts().apply(lambda x: x > 1).sum()),
    })

    return features



def extract_envars_features(jsondump):
    df = pd.read_json(jsondump)
    keys = ['envars.nVars', 'envars.nProc',  'envars.nBlock', 'envars.n_diff_var', 'envars.nValue', 
        'envars.tempPathOutsideWinRatio',  'envars.has_PSModulePathUser', 'envars.cmdExeComSpecMismatch',
        'envars.dupBlockCount', 'envars.pathEntropyMean', 'envars.userTempMismatch' ]

    if df.empty:
        return {k: None for k in keys}
    
    features = {
        'envars.nVars': df.Value.size,                                                          #Number of environment variables
        'envars.nProc': df.PID.unique().size,                                                   #Number of Processes using Env vars
        'envars.nBlock': df.Block.unique().size,                                                #Number of Blocks 
        'envars.n_diff_var': df.Variable.unique().size,                                         #Number of diff variable names
        'envars.nValue': df.Value.unique().size,                                                #Number of distinct value entries
    }

    tempPathOutsideWin = (~df.loc[df['Variable'].isin(['TEMP','TMP']), 'Value'].str.lower().str.startswith('c:\\windows\\'))
    has_PSModulePath = df.loc[df['Variable'] == 'PSModulePath', 'Value'].str.contains('AppData', case=False)
    cmdExeComSpecMismatch = (df['Variable'].eq('ComSpec') & ~df['Value'].str.lower().eq('c:\\windows\\system32\\cmd.exe'))
    pathEntropyMask = df.loc[df['Variable'] == 'Path', 'Value']

    
    features.update({
        'envars.tempPathOutsideWinRatio': float(tempPathOutsideWin.sum() / max(1, df['Variable'].isin(['TEMP','TMP']).sum())),
        'envars.has_PSModulePathUser': int(has_PSModulePath.any()),
        'envars.cmdExeComSpecMismatch': int(cmdExeComSpecMismatch.sum()),
        'envars.dupBlockCount': int((df.groupby('Block')['PID'].nunique() > 1).sum()),
        'envars.pathEntropyMean': float(pathEntropyMask.apply(char_entropy).mean()),
        # 'envars.userTempMismatch': None
        #TODO for each PID, the logged-on user name or token needed from pslist!
    })

    return features

def extract_filescan_features(jsondump):
    df=pd.read_json(jsondump)
    features = {
        'filescan.nFiles': df.Name.size,                                                        #Number of files
        'filescan.n_diff_file': df.Name.unique().size,                                          #Number of distinct files
    }

    features.update({
        'filescan.nonAsciiNameCount' : int(df['Name'].dropna().apply(is_non_ascii).sum()),
        'filescan.nameEntropyMean' : float(df['Name'].dropna().apply(char_entropy).mean()),
        'filescan.metaFileRatio' : float(df['Name'].str.startswith('\\$').sum() / len(df)),
        'filescan.userProfileFileCount' : int(df['Name'].str.lower().str.startswith('\\users').sum()),
        'filescan.sysUnderSystem32Ratio' : int(df['Name'].str.lower().str.startswith('\\windows\\system32').sum()),
        'filescan.adsCount' : int(df['Name'].str.contains(r'\$DATA', regex=True).sum())
    })

    return features

def extract_getservicesids_features(jsondump):
    """
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
    # print(sid_counts)
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
    svc_name_entropy_mean = float(name_entropies.mean()) if n_services else None

    # 4) count of names containing any non-A–Z/a–z character
    non_alpha_mask = names.str.contains(r"[^A-Za-z]")
    non_alpha_count = int(non_alpha_mask.sum())

    # 5) duplicate-SID reuse: sum of (count>1) occurrences
    sid_reuse_count = sum(cnt for cnt in sid_counts.values() if cnt > 1)


    
    sid_group_count = (~df['SID'].str.startswith('S-1-5-80-')).sum()

    # 6) privilege-tilt ratio: RIDs < 1000 (last dash-field of SID)
    rids = pd.to_numeric(
        df["SID"].str.rsplit("-", n=1).str[-1],
        errors="coerce"
    )

    sorted_sids = sorted(rids)
    sid_gaps = [sorted_sids[i+1] - sorted_sids[i] for i in range(len(sorted_sids) - 1)]
    sid_gap_avg = sum(sid_gaps) / len(sid_gaps) if sid_gaps else 0
    

    sid_depths = df["SID"].apply(lambda x: len(x.split("-")) - 1)
    sid_depth_max = sid_depths.max() #value_counts()
    # print(sid_depth_max)

    return {
        "servicesids.nServices"          : n_services,
        "servicesids.sidEntropy"         : round(sid_entropy, 4) if sid_entropy is not None else None,
        "servicesids.svcNameEntropyMean" : round(svc_name_entropy_mean, 4) if svc_name_entropy_mean is not None else None,
        "servicesids.nonAlphaNameCount"  : non_alpha_count,
        "servicesids.sidReuseCount"      : sid_reuse_count,
        "servicesids.maxdepth"           : sid_depth_max,
        "servicesids.unusualSIDAuthority": sid_group_count,
        "servicesids.sidGapAvg"          : sid_gap_avg,
    }
    

def extract_getsids_features(jsondump):
    df = pd.read_json(jsondump)
    features = {
        'getsids.nSIDcalls': df.SID.size,                                                       #Number of Security Identifier calls
        'getsids.nProc': df.PID.unique().size,                                                  #Number of processes
        'getsids.nDiffName': df.Name.unique().size,                                             #Number of Names
        'getsids.n_diff_sids': df.SID.unique().size,                                            #Number of Unique SIDs
        'getsids.avgSIDperProc': df.SID.size/df.PID.unique().size,                              #Avg number of SID per Process        
    }
    features.update({
        'getsids.adminSidInUserPID':    int(((df.PID > 1000) & df.SID.str.endswith('-544')).sum()),
        'getsids.nullNameRatio':        float(df.Name.isna().mean()),
        'getsids.serviceSidCount':      int(df.SID.str.contains(r'^S-1-5-80-').sum()),
        'getsids.foreignAuthorityPct':  float((df.SID.str.split('-').str[2] != '5').mean()),
        'getsids.maxSidsSingleProc':    int(df.groupby('PID').size().max()),
    })

    return features


import pandas as pd
import math
from collections import Counter

def extract_handles_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'handles.nHandles',           'handles.distinctHandles',      'handles.nproc',
        'handles.nAccess',            'handles.avgHandles_per_proc',  'handles.nTypePort',
        'handles.nTypeProc',          'handles.nTypeThread',          'handles.nTypeKey',
        'handles.nTypeEvent',         'handles.nTypeFile',            'handles.nTypeDir',
        'handles.nTypeSec',           'handles.nTypeDesk',            'handles.nTypeToken',
        'handles.nTypeMutant',        'handles.nTypeKeyEvent',        'handles.nTypeSymLink',
        'handles.nTypeSemaph',        'handles.nTypeWinSta',          'handles.nTypeTimer',
        'handles.nTypeIO',            'handles.nTypeWmi',             'handles.nTypeWaitPort',
        'handles.nTypeJob',           # V2 features
        'handles.privHighAccessPct',  'handles.nullNameFileRatio',    'handles.tokenHandlesUserProcs',
        'handles.maxHandlesOneProc',  'handles.handleEntropy'         # New features
    ]

    if df.empty:
        return {k: None for k in keys}

    features = {
        'handles.nHandles': len(df),
        'handles.distinctHandles': df.HandleValue.nunique(),
        'handles.nproc': df.PID.nunique(),
        'handles.nAccess': df.GrantedAccess.nunique(),
        'handles.avgHandles_per_proc': len(df) / df.PID.nunique(),
        'handles.nTypePort': int((df['Type'] == 'Port').sum()),
        'handles.nTypeProc': int((df['Type'] == 'Process').sum()),
        'handles.nTypeThread': int((df['Type'] == 'Thread').sum()),
        'handles.nTypeKey': int((df['Type'] == 'Key').sum()),
        'handles.nTypeEvent': int((df['Type'] == 'Event').sum()),
        'handles.nTypeFile': int((df['Type'] == 'File').sum()),
        'handles.nTypeDir': int((df['Type'] == 'Directory').sum()),
        'handles.nTypeSec': int((df['Type'] == 'Section').sum()),
        'handles.nTypeDesk': int((df['Type'] == 'Desktop').sum()),
        'handles.nTypeToken': int((df['Type'] == 'Token').sum()),
        'handles.nTypeMutant': int((df['Type'] == 'Mutant').sum()),
        'handles.nTypeKeyEvent': int((df['Type'] == 'KeyedEvent').sum()),
        'handles.nTypeSymLink': int((df['Type'] == 'SymbolicLink').sum()),
        'handles.nTypeSemaph': int((df['Type'] == 'Semaphore').sum()),
        'handles.nTypeWinSta': int((df['Type'] == 'WindowStation').sum()),
        'handles.nTypeTimer': int((df['Type'] == 'Timer').sum()),
        'handles.nTypeIO': int((df['Type'] == 'IoCompletion').sum()),
        'handles.nTypeWmi': int((df['Type'] == 'WmiGuid').sum()),
        'handles.nTypeWaitPort': int((df['Type'] == 'WaitablePort').sum()),
        'handles.nTypeJob': int((df['Type'] == 'Job').sum()),
    }

    features.update({
        'handles.privHighAccessPct': round((df.GrantedAccess > 0x1FFFFF).mean(), 4),
        'handles.nullNameFileRatio': float(len(df[(df['Type'] == 'File') & df['Name'].isna()]) 
                                           / len(df[df['Type'] == 'File'])),
        'handles.tokenHandlesUserProcs': int(((df['Type'] == 'Token') & (df['Process'] != 'System')).sum()),
        'handles.maxHandlesOneProc': int(df.groupby('PID').size().max()),
        'handles.handleEntropy': shannon_entropy(''.join(df['Name'].dropna().astype(str)))
    })

    return features

def extract_winInfo_features(jsondump):
    df = pd.read_json(jsondump)
    keys = ['info.Is64', 'info.winBuild', 'info.npro',
            'info.IsPAE', 'info.SystemTime']
    if df.empty:
        {k : None for k in keys}

    features = {
        'info.Is64': df.loc[df['Variable'] == 'Is64Bit', 'Value'].iat[0],      #Is Windows a 64 Version
        'info.winBuild': df.loc[df['Variable'] == 'Major/Minor', 'Value'].iat[0],
        'info.npro': df.loc[df['Variable'] == 'KeNumberProcessors', 'Value'].iat[0],
        'info.IsPAE': df.loc[df['Variable'] == 'IsPAE', 'Value'].iat[0],
        'info.SystemTime': pd.to_datetime(df.loc[df['Variable'] == 'SystemTime', 'Value'].iat[0], errors="coerce", utc=True)
    }

    features.update({
        'info.kbuildStr' : df.loc[df['Variable'] == 'KdVersionBlock', 'Value'].iat[0],
        'info.layerdepth' : df["Variable"].str.contains("layer", case=False).sum(),   
    })

    return [features.get('info.SystemTime', []), features]


def extract_iat_features(jsondump):
    df = pd.read_json(jsondump)
    keys = ['totalEntries','nProcesses','avgImportsPerProc',
            'boundRatio','syscallRatio','cryptoCount','netApiCount',
            'wow64LibCount', 'funcNameEntropyMean']
    if df.empty:
        return {k : None for k in keys}
    
    return {
        'totalEntries': len(df),
        'nProcesses': df['PID'].nunique(),
        'avgImportsPerProc': float(len(df) / df['PID'].nunique()) if df['PID'].nunique() != 0 else None,
        'boundRatio': float(df['Bound'].mean()),
        'syscallRatio': float(df['Function'].str.startswith(('Nt', 'Zw'), na=False).mean()),
        'cryptoCount': int(df['Function'].str.contains('Crypt|Crypto', case=False, na=False).sum()),
        'netApiCount': int(df['Function'].str.contains('Wininet|Ws2_32|Http', case=False, na=False).sum()),
        'wow64LibCount': int(df['Library'].str.contains(r'^api-ms-win-crt-', case=False, na=False).sum()),
        'funcNameEntropyMean': float(df['Function'].fillna('').apply(char_entropy).mean())
    }


def extract_joblinks_features(jsondump):
    """
    dict with keys:
        joblinks.nJobObjs           : unique Job objects  (JobLink is null)
        joblinks.linkedProcRatio    : #PIDs with JobLink == 'Yes' / total
        joblinks.sessMismatchCount  : rows where JobSess != Sess
        joblinks.highActiveSkew     : rows where Active/Total > 0.8
        joblinks.nameEntropyMean    : mean entropy of Name strings
    """
    with open(jsondump, 'r') as f:
        data = json.load(f)
    
    flat = list(flatten_records(data))
    if not flat:        # keep columns stable on empty output
        return ['joblinks.nJobObjs',
            'joblinks.linkedProcRatio' ,
            'joblinks.sessMismatchCount',
            'joblinks.highActiveSkew' ,
            'joblinks.nameEntropyMean' ]

    total_rows   = len(flat)
    linked_rows  = sum(1 for r in flat if str(r.get("JobLink")).lower() == "yes")

    high_skew    = 0
    for r in flat:
        tot = r.get("Total") or 0
        if tot:
            active = r.get("Active") or 0
            if active / tot > 0.8:
                high_skew += 1

    name_entropy = [char_entropy(str(r.get("Name", ""))) for r in flat]
    n_jobobjs = sum(1 for r in flat if r.get("JobLink") in (None, "", "null"))
    linked_ratio = linked_rows / total_rows if total_rows else 0.0

    return {
        'joblinks.nJobObjs'         : n_jobobjs,
        'joblinks.linkedProcRatio'  : round(linked_ratio, 4),
        'joblinks.sessMismatchCount': sum(1 for r in flat if r.get("JobSess") != r.get("Sess")),
        'joblinks.highActiveSkew'   : high_skew,
        'joblinks.nameEntropyMean'  : float(sum(name_entropy) / total_rows),
    }


def extract_ldrmodules_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'ldrmodules.total',     'ldrmodules.not_in_load',    'ldrmodules.not_in_init',
        'ldrmodules.not_in_mem', 'ldrmodules.memOnlyRatio',   'ldrmodules.suspPathCount',
        'ldrmodules.nonDllPct',  'ldrmodules.nameEntropyMean'
    ]

    if df.empty:
        return {k: None for k in keys}

    names = df['MappedPath'].dropna().apply(lambda p: os.path.basename(p))

    features = {
        'ldrmodules.total':           len(df),
        'ldrmodules.not_in_load':     int((df['InLoad'] == False).sum()),
        'ldrmodules.not_in_init':     int((df['InInit'] == False).sum()),
        'ldrmodules.not_in_mem':      int((df['InMem'] == False).sum()),
        'ldrmodules.nproc':           df.Pid.nunique(),
        'ldrmodules.not_in_load_avg': float((df['InLoad'] == False).mean()),
        'ldrmodules.not_in_init_avg': float((df['InInit'] == False).mean()),
        'ldrmodules.not_in_mem_avg':  float((df['InMem'] == False).mean()),
    }

    features.update({
        'ldrmodules.memOnlyRatio':    float(((df['InMem'] & ~df['InLoad'] & ~df['InInit']).mean())),
        'ldrmodules.suspPathCount':   int((~df['MappedPath'].str.lower().str.startswith(r'\\windows\\')).sum()),
        'ldrmodules.nonDllPct':       float((~df['MappedPath'].str.lower().str.endswith('.dll')).mean()),
    })

    return features


def extract_malfind_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'malfind.ninjections',     'malfind.commitCharge',    'malfind.protection',
        'malfind.uniqueInjections','malfind.avgInjec_per_proc','malfind.tagsVad',
        'malfind.tagsVads',        'malfind.aveVPN_diff',      # V2 features
        'malfind.maxVADsize',      'malfind.meanVADsize',     'malfind.shellJumpRatio',
        'malfind.nullPct',         'malfind.RWXratio'          # New features
    ]

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    vpn_sizes = df['End VPN'] - df['Start VPN']

    features = {
        'malfind.ninjections':      total,
        'malfind.commitCharge':     int(df['CommitCharge'].sum()),
        'malfind.protection':       int((df['Protection'] == 'PAGE_EXECUTE_READWRITE').sum()),
        'malfind.uniqueInjections': df['PID'].nunique(),
        'malfind.avgInjec_per_proc': float(total / df['PID'].nunique()),
        'malfind.tagsVad':          int((df['Tag'] == 'Vad').sum()),
        'malfind.tagsVads':         int((df['Tag'] == 'VadS').sum()),
        'malfind.aveVPN_diff':      int(vpn_sizes.sum()),
    }

    null_bytes = df['Hexdump'].str.findall(r'\b00\b').str.len().div(df['Hexdump'].str.split().str.len())
    
    features.update({
        'malfind.maxVADsize':      int(vpn_sizes.max()),
        'malfind.meanVADsize':     float(vpn_sizes.mean()),
        'malfind.shellJumpRatio':  float(df['Disasm'].str.contains('jmp').mean()),
        'malfind.nullPct':         float(null_bytes.mean()),
        'malfind.RWXratio':        float((df['Protection'] == 'PAGE_EXECUTE_READWRITE').mean())
    })

    return features


def extract_modscan_features(jsondump):
    df=pd.read_json(jsondump)

    keys = ['modscan.nMod', 'modscan.nUniqueExt', 'modscan.nDLL' , 'modscan.nSYS',
        'modscan.nEXE', 'modscan.nOthers', 'modscan.AvgSize', 'modscan.MeanChildExist',
        'modscan.FO_Enabled', 'modscan.offPathCount', 'modscan.sizeStddev', 'modscan.dupBaseCnt',
        'modscan.nameEntropyMean', 'modscan.unknownExtCount']
    
    if df.empty:
        return {k: None for k in keys}

    features = {
        'modscan.nMod': len(df),   #List of Loaded Kernel Modules #113
        'modscan.nUniqueExt': len(df['Name'].str.extract(r'\.(\w+)$')[0].str.lower().unique()) - 1, 
        'modscan.nDLL': int(df['Name'].dropna().str.lower().str.endswith('.dll').sum()),
        'modscan.nSYS': int(df['Name'].dropna().str.lower().str.endswith('.sys').sum()),
        'modscan.nEXE': int(df['Name'].dropna().str.lower().str.endswith('.exe').sum()),
        'modscan.nOthers': int(df['Name'].dropna().str.lower().apply(lambda x: not x.endswith(('.exe','.sys','.dll'))).sum()),  #str.endswith(('.dll','.exe','.sys')).sum()),
        'modscan.AvgSize': float(df['Size'].mean()),
        'modscan.MeanChildExist': float(df['__children'].apply(lambda x: len(x) if isinstance(x, list) else 0).astype(bool).mean()), # CHIld exist 1 else 0
        'modscan.FO_Enabled': len(df[df['File output'] == 'Enabled'])
    }
    
    features.update({
        'modscan.offPathCount': int((~df['Path'].str.lower().fillna('').str.startswith('\\systemroot\\')).sum()),                                       # outside SystemRoot
        'modscan.sizeStddev': float(df['Size'].std()),                                                        # size σ
        'modscan.dupBaseCnt': int(df['Base'].value_counts().gt(1).sum()),                                     # overlapping bases
        'modscan.nameEntropyMean': float(df['Name'].dropna().apply(char_entropy).mean()),                     # mean Name entropy
        'modscan.unknownExtCount': int((~df['Name'].dropna().str.extract(r'\.(\w+)$')[0].str.lower().isin({'sys','dll','exe'})).sum()),               # extensions ≠ sys/dll/exe
    })
    
    return features

def extract_mbrscan_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'mbrscan.nMBRentries',       'mbrscan.nDiskSig',            'mbrscan.nPartType',
        'mbrscan.bootable_partitions','mbrscan.nUniqueBootcode',     'mbrscan.avg_partitions_per_mbr',
        'mbrscan.avg_partition_size_mb','mbrscan.null_partition_size_pct','mbrscan.partition_type_diversity'
    ]

    if df.empty:
        return {k: None for k in keys}

    # flatten all children into one DataFrame
    children = pd.json_normalize(df['__children'].explode().dropna())

    features = {
        'mbrscan.nMBRentries'        : len(df),
        'mbrscan.nDiskSig'           : df['Disk Signature'].nunique(),
        'mbrscan.nPartType'          : df['PartitionType'].nunique(),
    }

    features.update({
        'mbrscan.bootable_partitions'   : int(children['Bootable'].sum()),
        'mbrscan.nUniqueBootcode'       : children['Bootcode MD5'].nunique(),
        'mbrscan.avg_partitions_per_mbr': float(df['__children'].apply(len).mean()),
        'mbrscan.avg_partition_size_mb' : float(children['SectorInSize'].dropna().mean() / (1024**2)),
        'mbrscan.null_partition_size_pct': round(children['SectorInSize'].isna().mean(), 4),
        'mbrscan.partition_type_diversity': children['PartitionType'].nunique()
    })

    return features

def extract_modules_features(jsondump):
    """
    Extract features from windows.modules JSON (pd.read_json style).
    """
    df = pd.read_json(jsondump)
    keys = ['modules.nModules','modules.avgSizeKB','modules.largeModuleRatio',
        'modules.userPathCount','modules.driverStoreRatio','modules.fileOutEnabled',
        'modules.nameEntropyMean','modules.nonAsciiNameCount','modules.sharedBaseAddrCount']
    if df.empty:
        return {k: None for k in keys}

    paths     = df['Path'].fillna('').str.lower()
    user_mask = paths.str.contains(r'\\program files|\\users\\.*\\temp|\\temp\\|\\appdata', regex=True)

    return {
        'modules.nModules'            : df.shape[0],
        'modules.avgSizeKB'           : float(df['Size'].mean() / 1024),
        'modules.largeModuleRatio'    : float((df['Size'] > 5 * 1024 * 1024).mean()),
        'modules.userPathCount'       : int(user_mask.sum()),
        'modules.driverStoreRatio'    : float(paths.str.contains('driverstore', na=False).mean()),
        'modules.fileOutEnabled'      : int((df['File output'] == 'Enabled').sum()),
        'modules.nameEntropyMean'     : float(df['Name'].fillna('').apply(char_entropy).mean()),
        'modules.nonAsciiNameCount'   : int(df['Name'].fillna('').apply(is_non_ascii).sum()),
        'modules.sharedBaseAddrCount' : int((df['Base'].value_counts() > 1).sum()),
    }



def extract_mutantscan_features(jsondump):
    df=pd.read_json(jsondump)
    features = {
        'mutantscan.nMutantObjects': len(df),
        'mutantscan.nNamedMutant': int(df['Name'].isna().sum()) 
    }
    
    features.update({
        'mutantscan.nullNameCount'         : int(df['Name'].isna().sum()),
        'mutantscan.smPrefixRatio'         : float(df['Name'].str.startswith('SM0:', na=False).mean()),
        'mutantscan.wilErrorCount'         : int(df['Name'].str.contains('WilError', na=False).sum()),
        'mutantscan.dbwinCount'            : int(df['Name'].str.contains('DBWinMutex', na=False).sum()),
        'mutantscan.officeClickRunCount'   : int(df['Name'].str.contains('ClickToRun|Office', na=False).sum()),
        'mutantscan.nameEntropyMean'       : float(df['Name'].dropna().apply(char_entropy).mean()),
        'mutantscan.nonAsciiNameCount'     : int(df['Name'].dropna().apply(lambda s: any(ord(c)>127 for c in s)).sum()),
        'mutantscan.duplicateNameRatio'    : float((len(df)-df['Name'].nunique(dropna=True))/len(df)),
        'mutantscan.avgNameLen'            : float(df['Name'].dropna().str.len().mean()),
        'mutantscan.nullOffsetCount'       : int(df['Offset'].isna().sum() + (df['Offset']==0).sum())
    })
    return features

def extract_netscan_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'netscan.nConn',               'netscan.nDistinctForeignAdd',  'netscan.nDistinctForeignPort',
        'netscan.nDistinctLocalAddr',   'netscan.nDistinctLocalPort',   'netscan.nOwners',
        'netscan.nDistinctProc',        'netscan.nListening',           'netscan.Proto_TCPv4',
        'netscan.Proto_UDPv4',          'netscan.Proto_TCPv6',          'netscan.Proto_UDPv6',
        'netscan.unownedConnCount',     'netscan.closedButUnowned',     'netscan.publicEstablished',
        'netscan.highPortListenCount',  'netscan.ipv6Ratio',            'netscan.loopbackPairCount',
        'netscan.duplicateListen'
    ]

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    features = {
        'netscan.nConn':               total,
        'netscan.nDistinctForeignAdd': df.ForeignAddr.nunique(),
        'netscan.nDistinctForeignPort':df.ForeignPort.nunique(),
        'netscan.nDistinctLocalAddr':  df.LocalAddr.nunique(),
        'netscan.nDistinctLocalPort':  df.LocalPort.nunique(),
        'netscan.nOwners':             df.Owner.nunique(),
        'netscan.nDistinctProc':       df.PID.nunique(),
        'netscan.nListening':          int((df['State'] == 'LISTENING').sum()),
        'netscan.Proto_TCPv4':         int((df['Proto'] == 'TCPv4').sum()),
        'netscan.Proto_UDPv4':         int((df['Proto'] == 'UDPv4').sum()),
        'netscan.Proto_TCPv6':         int((df['Proto'] == 'TCPv6').sum()),
        'netscan.Proto_UDPv6':         int((df['Proto'] == 'UDPv6').sum()),
    }

    private_re = re.compile(
        r'^(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.0\.0\.1|::1)', re.IGNORECASE)
    public_established_mask =  (df['State'] == 'ESTABLISHED') & ~df['ForeignAddr'].str.match(private_re, na=False) 
    
    loopback_mask = (df.LocalAddr.isin(['127.0.0.1','::1'])& df.ForeignAddr.isin(['127.0.0.1','::1'])
                    & (df.LocalAddr == df.ForeignAddr))
    
    duplicate_listen_mask = (df[df['State'] == 'LISTENING'].groupby(['LocalAddr','LocalPort']).size() > 1)

    features.update({
        'netscan.unownedConnCount':    int(((df.PID.isna()) | (df.Owner.isna())).sum()),
        'netscan.closedButUnowned':    int(((df['State'] == 'CLOSED') & df.PID.isna()).sum()),
        'netscan.publicEstablished':   float(public_established_mask.sum() / total),
        'netscan.highPortListenCount': int(((df['State'] == 'LISTENING') & (df.LocalPort > 49152)).sum()),
        'netscan.ipv6Ratio':           float(df['Proto'].str.endswith('v6').mean()),
        'netscan.loopbackPairCount':   int((loopback_mask).sum()),
        'netscan.duplicateListen':     int(duplicate_listen_mask.sum())
    })

    return features

def extract_poolscanner_features(jsondump):
    df=pd.read_json(jsondump)
    features = {
        'poolscanner.nPool': len(df),
        'poolscanner.nUniquePool': df.Tag.unique().size,
    }
    
    features.update({
        'poolscanner.tag_entropy_mean': float(df['Tag'].dropna().apply(char_entropy).mean()),
        'poolscanner.driver_obj_ratio': float((df['Tag'].str.contains(r'\_DRIVER_OBJECT', regex=True).sum() / len(df))),
        'poolscanner.file_obj_ratio': float((df['Tag'].str.contains(r'\_FILE_OBJECT', regex=True)).sum() / len(df)),
        'poolscanner.null_name_ratio': float(df['Name'].isna().mean()),
        'poolscanner.top_tag': df['Tag'].mode().iat[0] if not df['Tag'].mode().empty else None
    })
    
    return features


def extract_privileges_features(jsondump):
    df=pd.read_json(jsondump)
    features = {
        'privileges.nTotal': len(df),
        'privileges.nUniquePrivilege': df.Privilege.nunique(),
        'privileges.nPID': df.PID.nunique(),
        'privileges.nProcess': df.Process.nunique(),
        'privileges.nAtt_D': len(df[df["Attributes"]=="Default"]),
        'privileges.nAtt_P': len(df[df["Attributes"]=="Present"]),
        'privileges.nAtt_PE': len(df[df["Attributes"]=="Present,Enabled"]),
        'privileges.nAtt_PED': len(df[df["Attributes"]=="Present,Enabled,Default"]),
        'privileges.nAtt_NaN': int(df['Attributes'].isna().sum())
    }

    features.update({
        'privileges.rarePrivCount': int(df.Privilege.str.contains("SeRel|SeTcb|SeLoad|SeDebug|Assign").sum()),
        'privileges.nullNameRatio': float(df.Privilege.isna().mean()),
        'privileges.highPrivProcRatio': float((df.groupby("PID")["Privilege"].apply(lambda x: x.str.contains("Tcb|TcbPrivilege").sum() > 0)).mean()),
        'privileges.maxPrivsInProc': int(df.groupby("PID").size().max())
    })

    return features

def extract_pslist_features(jsondump):
    df = pd.read_json(jsondump)

    nproc          = len(df) 
    pids           = df['PID'].values
    nprocs64bit    = len(df[df["Wow64"] == True])

    zombie_count   = len(df[df["ExitTime"].notna()])        # still resident but ExitTime recorded
    wow64_ratio    = nprocs64bit / nproc if nproc else None

    handles_numeric = pd.to_numeric(df["Handles"], errors="coerce")
    restricted_pct  = (handles_numeric.lt(4).sum() / nproc) if nproc else None        

    def is_user_path(name):
        name = str(name).lower()
        return (not name.startswith("c:\\windows\\")
                and not name.startswith("c:\\program files"))
    user_path_ratio = df["ImageFileName"].apply(is_user_path).mean()

    return [pids, {
        # V2
        "pslist.nproc"        : nproc,
        "pslist.nppid"        : df.PPID.nunique(),
        "pslist.avg_threads"  : float(df.Threads.dropna().mean()) if not df.Threads.dropna().empty else None,
        "pslist.avg_handlers" : float(df.Handles.dropna().mean()) if not df.Handles.dropna().empty else None,
        "pslist.nprocs64bit"  : len(df[df["Wow64"] == True]),
        "pslist.outfile"      : nproc - len(df[df["File output"] == "Disabled"]),

        "pslist.zombie_count"       : zombie_count,
        "pslist.wow64_ratio"        : wow64_ratio,
        "pslist.restricted_handles_pct": restricted_pct,
        "pslist.user_path_ratio"    : user_path_ratio,
    }]


def extract_pstree_features(jsondump):
    with open(jsondump, 'r') as f:
        data = json.load(f)
    
    df = pd.DataFrame(data)

    def get_max_depth(node):
        if not node.get('__children'):
            return 1
        return 1 + max(get_max_depth(child) for child in node['__children'])

    max_depth = max(get_max_depth(proc) for proc in data) if data else 0

    # Orphan ratio
    orphan_ratio = len([proc for proc in data if proc.get("PPID") in (None, 0)]) / len(data) if data else 0

    # Average branching factor
    def collect_branching_factors(nodes):
        factors = []
        for node in nodes:
            children = node.get('__children', [])
            factors.append(len(children))
            factors.extend(collect_branching_factors(children))
        return factors

    all_branches = collect_branching_factors(data)
    avg_branching_factor = np.mean(all_branches) if all_branches else 0

    # Cross-session edges
    def count_cross_session_edges(node, parent_sid):
        count = 0
        sid = node.get("SessionId")
        children = node.get("__children", [])
        for child in children:
            child_sid = child.get("SessionId")
            if sid is not None and child_sid is not None and sid != child_sid:
                count += 1
            count += count_cross_session_edges(child, sid)
        return count

    cross_session_edges = sum(count_cross_session_edges(proc, proc.get("SessionId")) for proc in data)

    features = {
        'pstree.nTree': len(df),
        'pstree.nHandles': len(df) - df['Handles'].isna().sum(),
        'pstree.nPID': df.PID.nunique(),
        'pstree.nPPID': df.PPID.nunique(),
        'pstree.AvgThreads': df.Threads.mean(),
        'pstree.nWow64': len(df[df["Wow64"] == True]),
        'pstree.AvgChildren': df['__children'].apply(len).mean()
    }

    features.update({
        'pstree.max_depth': max_depth,
        'pstree.orphan_ratio': orphan_ratio,
        'pstree.avg_branching_factor': avg_branching_factor,
        'pstree.cross_session_edges': cross_session_edges
    })

    return features


def extract_psscan_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'psscan.nEntries',           'psscan.nUniquePIDs',        'psscan.nUniqueNames',
        'psscan.exit_time_ratio',    'psscan.wow64_ratio',        'psscan.avg_threads',
        'psscan.handle_present_ratio','psscan.disabled_output_ratio','psscan.ppid_diversity',
        'psscan.avg_offset',         'psscan.offset_std',         'psscan.child_present_ratio',
        'psscan.avg_children',       'psscan.create_timespan_days'
    ]

    if df.empty:
        return {k: None for k in keys}

    # prepare for multi-use calculations
    df['CreateTime'] = pd.to_datetime(df['CreateTime'], errors='coerce')
    df['ExitTime']   = pd.to_datetime(df['ExitTime'], errors='coerce')
    child_counts     = df['__children'].apply(len)
    total            = len(df)

    features = {
        'psscan.nEntries'     : total,
        'psscan.nUniquePIDs'  : df['PID'].nunique(),
        'psscan.nUniqueNames' : df['ImageFileName'].nunique()
    }

    features.update({
        'psscan.exit_time_ratio'     : float(df['ExitTime'].notna().mean()),
        'psscan.wow64_ratio'         : float(df['Wow64'].mean()),
        'psscan.avg_threads'         : float(df['Threads'].mean()),
        'psscan.handle_present_ratio': float(df['Handles'].notna().mean()),
        'psscan.disabled_output_ratio': float(df['File output'].eq('Disabled').mean()),
        'psscan.ppid_diversity'      : float(df['PPID'].nunique() / total),
        'psscan.avg_offset'          : float(df['Offset(V)'].mean()),
        'psscan.offset_std'          : float(df['Offset(V)'].std()),
        'psscan.child_present_ratio' : float(child_counts.gt(0).mean()),
        'psscan.avg_children'        : float(child_counts.mean()),
        'psscan.create_timespan_days': int((df['CreateTime'].max() - df['CreateTime'].min()).days)
    })

    return features


def extract_psxview_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'psxview.nEntries',        'psxview.nUniquePIDs',       'psxview.nUniqueNames',
        'psxview.csrss_ratio',     'psxview.pslist_ratio',      'psxview.psscan_ratio',
        'psxview.thrdscan_ratio',  'psxview.all_seen_ratio',    'psxview.none_seen_count',
        'psxview.partial_seen_count','psxview.single_seen_count','psxview.exit_time_ratio',
        'psxview.avg_offset',      'psxview.offset_std' ]

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    df['Exit Time'] = pd.to_datetime(df['Exit Time'], errors='coerce')
    detect_sum = df[['csrss', 'pslist', 'psscan', 'thrdscan']].sum(axis=1)

    features = {
        'psxview.nEntries'      : total,
        'psxview.nUniquePIDs'   : df['PID'].nunique(),
        'psxview.nUniqueNames'  : df['Name'].nunique()
    }

    features.update({
        'psxview.csrss_ratio'       : float(df['csrss'].mean()),
        'psxview.pslist_ratio'      : float(df['pslist'].mean()),
        'psxview.psscan_ratio'      : float(df['psscan'].mean()),
        'psxview.thrdscan_ratio'    : float(df['thrdscan'].mean()),
        'psxview.all_seen_ratio'    : float((detect_sum == 4).mean()),
        'psxview.none_seen_count'   : int((detect_sum == 0).sum()),
        'psxview.partial_seen_count': int(detect_sum.between(1, 3).sum()),
        'psxview.single_seen_count' : int((detect_sum == 1).sum()),
        'psxview.exit_time_ratio'   : float(df['Exit Time'].notna().mean()),
        'psxview.avg_offset'        : float(df['Offset(Virtual)'].mean()),
        'psxview.offset_std'        : float(df['Offset(Virtual)'].std())
    })

    return features

def extract_registry_amcache_features(jsondump):
    df = pd.read_json(jsondump)

    image_ts = pd.to_datetime(df['LastModifyTime']).max()
    drv_mask = df['Path'].str.lower().str.contains(r'\\windows\\system32\\drivers')
    vendor_counts = df.loc[drv_mask & (df['Company'] != 'Microsoft Corporation'), 'Company'] \
                      .value_counts(normalize=True)
    # print(vendor_counts)
    svc_counts   = df['Service'].value_counts(normalize=True)

    return {
        'amcache.nEntries'               : len(df),
        'amcache.nDistinctCompanies'     : df['Company'].nunique(),
        'amcache.future_compile_ratio'   : float((pd.to_datetime(df['CompileTime']) > image_ts).mean()),
        'amcache.null_install_time_count': int(df['InstallTime'].isna().sum()),
        'amcache.non_ms_driver_entropy'  : float(shannon_entropy(vendor_counts)) if not vendor_counts.empty else None,
        'amcache.service_name_entropy'   : float(shannon_entropy(svc_counts)) if not svc_counts.empty else None,
        'amcache.unsigned_product_ratio' : float(df['ProductVersion'].isna().mean())
    }


def extract_registry_printkey_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'registry.printkey.nKeys',          'registry.printkey.nDistinct',      'registry.printkey.nType_key',
        'registry.printkey.nType_other',    'registry.printkey.Volatile_0',     'registry.printkey.Avg_Children',
        'registry.printkey.volatile_ratio', 'registry.printkey.distinct_hives', 'registry.printkey.dword_ratio',
        'registry.printkey.avg_name_len',   'registry.printkey.write_timespan_days'
    ]

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    df['Last Write Time'] = pd.to_datetime(df['Last Write Time'])
    
    features = {
        'registry.printkey.nKeys'       : total,
        'registry.printkey.nDistinct'   : df['Name'].nunique(),
        'registry.printkey.nType_key'   : int((df['Type']=='Key').sum()),
        'registry.printkey.nType_other' : int((df['Type']!='Key').sum()),
        'registry.printkey.Volatile_0'  : int((df['Volatile']==False).sum()),
        'registry.printkey.Avg_Children': df['__children'].apply(len).mean()
    }

    features.update({
        'registry.printkey.volatile_ratio'       : float((df['Volatile']==True).sum()/total),
        'registry.printkey.distinct_hives'       : df['Hive Offset'].nunique(),
        'registry.printkey.dword_ratio'          : float((df['Type']!='Key').sum()/total),
        'registry.printkey.avg_name_len'         : float(df['Name'].str.len().mean()),
        'registry.printkey.write_timespan_days'  : int((df['Last Write Time'].max() - df['Last Write Time'].min()).days)
    })

    return features


def extract_registry_hivelist_features(jsondump):
    """
    Extracts these features from windows.registry.hivelist JSON:
      • hivelist.empty_path_entries : # rows where FileFullPath == ""
      • hivelist.duplicate_paths    : total rows minus # unique FileFullPath
      • hivelist.user_hive_count    : # per-user NTUSER/UsrClass hives loaded
      • hivelist.offset_gap_stddev  : std-dev of gaps between sorted Offsets
    """
    df = pd.read_json(jsondump)
    keys = ['registry.hivelist.nFiles', 'registry.hivelist.nFO_Enabled', 
            'registry.hivelist.empty_path_entries', 'registry.hivelist.duplicate_paths',
            'registry.hivelist.user_hive_count', 'registry.hivelist.offset_gap_stddev']
    if df.empty:
        return {k: None for k in keys}
    
    features = {
        'registry.hivelist.nFiles': len(df),
        'registry.hivelist.nFO_Enabled': len(df) - len(df[df["File output"]=="Disabled"])
    }

    paths = df['FileFullPath'].fillna('').str.lower()
    offs = pd.to_numeric(df['Offset'], errors='coerce').dropna().sort_values()
    user_hives = (paths.str.contains(r'\\users\\', na=False) &
                  paths.str.contains(r'\\ntuser\.dat$|\\usrclass\.dat$', na=False))
    
    features.update({
        'registry.hivelist.empty_path_entries': int(paths.eq('').sum()),
        'registry.hivelist.duplicate_paths'   : int(len(paths) - paths.nunique()),
        'registry.hivelist.user_hive_count'   : int(user_hives.sum()),
        'registry.hivelist.offset_gap_stddev' : float(offs.diff().dropna().std()) 
    })
    
    return [offs, features]


#TODO HIVELIST IS NEEDED cross plugin
def extract_registry_hivescan_features(jsondump, **kwargs):
    df=pd.read_json(jsondump)
    features = {
        'registry.hivescan.nHives': len(df),
        'registry.hivescan.Children_exist': df['__children'].apply(lambda x: len(x) if isinstance(x, list) else 0).astype(bool).sum()  
    }

    hivelist_offsets = kwargs.get('registry.hivescan', pd.Series(dtype=object))
    offsets = pd.to_numeric(df['Offset'], errors='coerce').dropna().sort_values()
    orphan_offsets = set(offsets) - set(hivelist_offsets) if not hivelist_offsets.empty else None

    features.update({
        'hivescan.orphan_offset_count': int(len(orphan_offsets)) if orphan_offsets else None,
        'hivescan.too_high_offset_ratio': float((df["Offset"] > 0x7FFFFFFFFFFF).mean()),
        'hivescan.offset_entropy': float(shannon_entropy(df['Offset']))
    })

    return features


def extract_registry_certificates_features(jsondump):
    df=pd.read_json(jsondump)
    features = {
        'registry.certificates.nCert': len(df),
        'registry.certificates.nID_Auto': len(df[df["Certificate ID"]=="AutoUpdate"]),
        'registry.certificates.nID_Protected': len(df[df["Certificate ID"]=="ProtectedRoots"]),
        'registry.certificates.nID_Others': len(df[~df['Certificate ID'].isin(['AutoUpdate','ProtectedRoots'])]) #174
    }

    authroot_auto = df[(df["Certificate section"] == "AuthRoot") & (df["Certificate ID"] == "AutoUpdate")]
    root_store = df[df["Certificate section"] == "ROOT"]
    ca_store = df[df["Certificate section"] == "CA"]
    authroot_ids = df[df["Certificate section"] == "AuthRoot"].set_index("Certificate ID")[["Certificate name", "Certificate path"]]
    ca_ids = ca_store.set_index("Certificate ID")[["Certificate name", "Certificate path"]]

    intersect_ids = set(authroot_ids.index).intersection(ca_ids.index)
    mismatch_count = 0
    for cert_id in intersect_ids:
        auth = authroot_ids.loc[cert_id]
        ca = ca_ids.loc[cert_id]
        # Handle duplicates
        if isinstance(auth, pd.DataFrame) or isinstance(ca, pd.DataFrame):
            mismatch_count += 1
        elif auth["Certificate name"] != ca["Certificate name"] or auth["Certificate path"] != ca["Certificate path"]:
            mismatch_count += 1

    features.update({
        'registry.certificates.disallowed_count' : df[df["Certificate section"] == "Disallowed"].shape[0],
        'registry.certificates.duplicate_autoupdate_entries' : int(authroot_auto.duplicated(subset=["Certificate ID", "Certificate section", "Certificate name", "Certificate path"]).sum()),
        'registry.certificates.null_name_root_ratio': float(root_store["Certificate name"].isna().mean() if not root_store.empty else 0),
        'registry.certificates.ca_cross_store_mismatch' : int(mismatch_count)
    })
    
    return features

def extract_registry_userassist_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'registry.userassist.n',            'registry.userassist.nUnique',      'registry.userassist.Avg_Children',
        'registry.userassist.path_DNE',     'registry.userassist.type_key',     'registry.userassist.type_other',
        'registry.userassist.name_null_ratio','registry.userassist.zero_count_ratio','registry.userassist.avg_focus_count',
        'registry.userassist.time_focused_present_ratio','registry.userassist.write_timespan_days'
    ]

    if df.empty:
        return {k: None for k in keys}

    # prepare datetime
    total = len(df)
    df['Last Write Time'] = pd.to_datetime(df['Last Write Time'], errors='coerce')
    child_counts = df['__children'].apply(len)

    features = {
        'registry.userassist.n'            : total,
        'registry.userassist.nUnique'      : df['Hive Name'].nunique(),
        'registry.userassist.Avg_Children' : float(df['__children'].apply(len).mean()),
        'registry.userassist.path_DNE'     : int((df['Path'] == 'None').sum()),
        'registry.userassist.type_key'     : int((df['Type'] == 'Key').sum()),
        'registry.userassist.type_other'   : int((df['Type'] != 'Key').sum())
    }

    features.update({
        'registry.userassist.name_null_ratio'             : float(df['Name'].isna().mean()),
        'registry.userassist.zero_count_ratio'            : float(df['Count'].fillna(0).eq(0).mean()),
        'registry.userassist.avg_focus_count'             : float(df['Focus Count'].dropna().mean()),
        'registry.userassist.time_focused_present_ratio'  : float(df['Time Focused'].notna().mean()),
        'registry.userassist.write_timespan_days'         : int((df['Last Write Time'].max() - df['Last Write Time'].min()).days),
        'registry.userassist.child_present_ratio'        : float((child_counts.gt(0).sum() / total)),
        'registry.userassist.max_children_count'         : int(child_counts.max())
    })

    return features


def extract_shimcache_features(jsondump):
    df = pd.read_json(jsondump)
    if df.empty:
        return {
            'shimcache.nEntries':     None, 'shimcache.exec_flag_ratio':         None, 'shimcache.null_last_modified_ratio': None,
            'shimcache.future_last_modified_ratio': None, 'shimcache.nDistinctPaths': None, 'shimcache.avg_children':           None
        }
    # reuseable series
    flags = pd.to_numeric(df['Exec Flag'], errors='coerce')
    lm = pd.to_datetime(df['Last Modified'], errors='coerce')
    now = pd.Timestamp.utcnow()
    return {
        'shimcache.nEntries':                   len(df), 
        'shimcache.exec_flag_ratio':            float(flags.eq(1).sum() / len(df)), 
        'shimcache.null_last_modified_ratio':   float(lm.isna().sum() / len(df)),
        'shimcache.future_last_modified_ratio': float(lm.gt(now).sum() / len(df)), 
        'shimcache.nDistinctPaths':             df['File Path'].nunique(), 
        'shimcache.avg_children':               df['__children'].apply(len).mean()
    }


def extract_skeleton_key_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'skeleton_key.nKey',         'skeleton_key.nProcess',        'skeleton_key.Found_True',
        'skeleton_key.Found_False',  'skeleton_key.rc4Hmac_decrypt_time'
    ]

    if df.empty:
        return {k: None for k in keys}

    features = {
        'skeleton_key.nKey'        : len(df),
        'skeleton_key.nProcess'    : df['Process'].nunique(),
        'skeleton_key.Found_True'  : int((df['Skeleton Key Found'] == True).sum()),
        'skeleton_key.Found_False' : int((df['Skeleton Key Found'] == False).sum())
    }

    # new metrics inlined
    features.update({
        'skeleton_key.rc4Hmac_decrypt_time' : float(df['rc4HmacDecrypt'].mean())
    })

    return features


def extract_statistics_features(jsondump):
    """
    Extracts two NEW metrics from windows.statistics JSON:
      • statistics.invalid_page_ratio      – proportion of invalid pages
      • statistics.swapped_page_count      – total swapped pages
    """
    df=pd.read_json(jsondump)
    keys = ['statistics.Invalid_all', 'statistics.Invalid_large', 'statistics.Invalid_other', 
            'statistics.Swapped_all', 'statistics.Swapped_large', 'statistics.Valid_all', 'statistics.Valid_large',
            'statistics.invalid_page_ratio',  'statistics.Invalid_large','statistics.swapped_page_count' ]
    
    if df.empty:
        return {k: None for k in keys}
    
    features = {
        'statistics.Invalid_all': int(df.loc[0].at["Invalid Pages (all)"]),
        'statistics.Invalid_large': int(df.loc[0].at["Invalid Pages (large)"]),
        'statistics.Invalid_other': int(df.loc[0].at["Other Invalid Pages (all)"]),
        'statistics.Swapped_all': int(df.loc[0].at["Swapped Pages (all)"]),
        'statistics.Swapped_large': int(df.loc[0].at["Swapped Pages (large)"]),
        'statistics.Valid_all': int(df.loc[0].at["Valid pages (all)"]),
        'statistics.Valid_large': int(df.loc[0].at["Valid pages (large)"])
    }
    
    stat_row = df.iloc[0]
    invalid_all = stat_row.get('Invalid Pages (all)') + stat_row.get('Other Invalid Pages (all)')
    valid_all = stat_row.get('Valid pages (all)')

    features.update({
        'statistics.invalid_page_ratio'       : float(invalid_all / (invalid_all + valid_all)) if (invalid_all + valid_all) != 0 else None,
        'statistics.swapped_page_count'       : int(stat_row.get('Swapped Pages (all)'))
    })
    
    return features

def extract_ssdt_features(jsondump):
    """
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

    features = {'ssdt.nEntries': len(df),
                'ssdt.nIndex': df.Index.nunique(),
                'ssdt.nModules': df.Module.nunique(),
                'ssdt.nSymbols': df.Symbol.nunique(),
                'ssdt.Children_exist': df['__children'].apply(lambda x: len(x) if isinstance(x, list) else 0).astype(bool).sum() 
            }

    mod_mask   = df['Module'].str.lower() != 'ntoskrnl'
    pair_series = df['Module'].astype(str) + '::' + df['Symbol'].astype(str)

    features.update({
        'ssdt.modified_syscalls': int(mod_mask.sum()),
        'ssdt.unique_syscalls': int(df['Symbol'].nunique()),
        'ssdt.syscall_entropy'  : float(shannon_entropy(pair_series)),
    })

    return features

def extract_sessions_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'sessions.nSessions',        'sessions.nProcess',             'sessions.nUsers',
        'sessions.nType',            'sessions.child_present_count',  'sessions.valid_sid_ratio',
        'sessions.type_present_ratio','sessions.user_session_ratio',   'sessions.top_type_ratio',
        'sessions.create_timespan_days','sessions.dup_process_count'
    ]

    if df.empty:
        return {k: None for k in keys}

    # prepare for multi-use calculations
    df['Create Time'] = pd.to_datetime(df['Create Time'], errors='coerce')
    child_counts = df['__children'].apply(lambda x: len(x) if isinstance(x, list) else 0)

    total = len(df)
    features = {
        'sessions.nSessions'           : total,
        'sessions.nProcess'            : df['Process'].nunique(),
        'sessions.nUsers'              : df['User Name'].nunique(),
        'sessions.nType'               : df['Session Type'].nunique(),
        'sessions.child_present_count' : int(child_counts.gt(0).sum())
    }

    time_span_series = (df['Create Time'].max() - df['Create Time'].min())

    features.update({
        'sessions.valid_sid_ratio'        : float(df['Session ID'].notna().mean()),
        'sessions.type_present_ratio'     : float(df['Session Type'].notna().mean()),
        'sessions.user_session_ratio'     : float(df['User Name'].notna().mean()),
        'sessions.top_type_ratio'         : float(df['Session Type'].value_counts(normalize=True).max()),
        'sessions.create_timespan_days'   : int(time_span_series.days),
        'sessions.dup_process_count'      : int((df['Process'].value_counts() > 1).sum())
    })

    return features


def extract_scheduleduled_tasks_features(jsondump):
    df = pd.read_json(jsondump)
    now = pd.Timestamp.utcnow()

    ts = lambda col: pd.to_datetime(df[col], errors='coerce')
    lt = ts('Last Run Time')
    lst_succ = ts('Last Successful Run Time')

    total = len(df); enabled = df['Enabled'].eq(True).sum()
    null_action = df['Action'].isna().sum(); never_run = lt.isna().sum()
    future_run = (lt > now).sum()

    trig = df['Trigger Type'].dropna().value_counts(normalize=True)
    ctx  = df['Action Context'].dropna().value_counts(normalize=True)

    return {
        'scheduled.nTasks':              total,
        'scheduled.enabled_ratio':       float(enabled/total),
        'scheduled.null_action_count':   int(null_action),

        'scheduled.never_run_count':     int(never_run),
        'scheduled.future_run_count':    int(future_run),
        'scheduled.distinct_triggers':   int(df['Trigger Type'].nunique()),

        'scheduled.top_trigger_pct':     float(trig.iloc[0]) if not trig.empty else 0.0,
        'scheduled.distinct_contexts':   int(df['Action Context'].nunique()),
        'scheduled.top_context_pct':     float(ctx.iloc[0]) if not ctx.empty else 0.0,

        'scheduled.null_last_succ_run':  int(lst_succ.isna().sum()),
        'scheduled.mean_children':       float(df['__children'].apply(len).mean()),
        'scheduled.distinct_actions':    int(df['Action Type'].nunique())
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


def extract_svclist_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        "svclist.running_services_count",
        "svclist.suspended_service_ratio",
        "svclist.auto_start_services",
        "svclist.svchost_share_process_count",
        "svclist.custom_service_type_ratio",
        "svclist.services_with_no_binary",
    ]
    if df.empty:
        return {k: None for k in keys}
    
    standard_service_types = {
        "SERVICE_WIN32_OWN_PROCESS",
        "SERVICE_WIN32_SHARE_PROCESS",
        "SERVICE_KERNEL_DRIVER",
        "SERVICE_FILE_SYSTEM_DRIVER",
    }
    known_system_services = ["svchost.exe", "lsass.exe", "winlogon.exe", "services.exe"]

    def linked_to_known_binary(row):
        binary = (row.get("Binary") or "").lower()
        regval = (row.get("Binary (Registry)") or "").lower()
        return any(bin_name in binary or bin_name in regval for bin_name in known_system_services)

    share_process_mask = (df["Binary"].str.lower().fillna("").str.contains("svchost.exe") &
                          df["Type"].fillna("").str.contains("SHARE_PROCESS"))

    types_series = df["Type"].fillna("").str.strip().str.split("|")

    return {
        "svclist.running_services_count": int((df["State"] == "SERVICE_RUNNING").sum()),
        "svclist.suspended_service_ratio": float(df[df["State"] == "SERVICE_STOPPED"].apply(linked_to_known_binary, axis=1).mean()), # if not df[df["State"] == "SERVICE_STOPPED"].empty else None,
        "svclist.auto_start_services": int((df["Start"] == "SERVICE_AUTO_START").sum()),
        "svclist.svchost_share_process_count": int(share_process_mask.sum()),
        "svclist.custom_service_type_ratio": float(types_series.apply(lambda x: not set(x).issubset(standard_service_types)).mean()),
        "svclist.services_with_no_binary": int((df["Binary"].isna() & df['Binary (Registry)'].isna()).sum())
    }

def extract_timers_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'timers.total_timers',            'timers.unique_modules_count',      'timers.timers_with_symbols',
        'timers.timers_with_null_symbols','timers.periodic_timers_count',     'timers.signaled_timers_count',
        'timers.high_periodic_timer_ms',  'timers.popfx_idle_reuse_count',    'timers.max_timers_per_module',
        'timers.suspicious_module_timer_count'
    ]

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    periods = df['Period(ms)']
    periodic_mask = periods.gt(0)
    susp = df['Module'].isin(['winfsp-x64','pdc','volsnap','netbt'])

    return{
        'timers.total_timers'               : total,
        'timers.unique_modules_count'       : df['Module'].nunique(),
        'timers.timers_with_symbols'        : int(df['Symbol'].notna().sum()),
        'timers.timers_with_null_symbols'   : int(df['Symbol'].isna().sum()),
        'timers.periodic_timers_count'      : int(periodic_mask.sum()),
        'timers.signaled_timers_count'      : int((df['Signaled'] == 'Yes').sum()),
        'timers.high_periodic_timer_ms'     : float(periods[periodic_mask].max()) if periodic_mask.any() else None,
        'timers.popfx_idle_reuse_count'     : int((df['Symbol'] == 'PopFxIdleTimeoutDpcRoutine').sum()),
        'timers.max_timers_per_module'      : int(df.groupby('Module').size().max()),
        'timers.suspicious_module_timer_count': int(susp.sum())
    }

def extract_symlinkscan_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'symlinkscan.nLinks',            'symlinkscan.nFrom',                       'symlinkscan.nTo',
        'symlinkscan.Avg_Children',      'symlinkscan.null_to_ratio',               'symlinkscan.duplicate_fromname_count',
        'symlinkscan.globalroot_presence','symlinkscan.device_target_ratio',         'symlinkscan.offset_gap_stddev']

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    root_presence_mask = df['From Name'].str.upper().eq('GLOBALROOT').any() or df['To Name'].str.startswith("\\GLOBAL", na=False)

    features = {
        'symlinkscan.nLinks': int(total),
        'symlinkscan.nFrom': int(df['From Name'].nunique()),
        'symlinkscan.nTo': int(df['To Name'].nunique()),
        'symlinkscan.Avg_Children': float(df['__children'].apply(len).mean())
    }

    features.update({
        'symlinkscan.null_to_ratio': round((df['To Name'] == '').sum() / total, 4),
        'symlinkscan.duplicate_fromname_count': int(df['From Name'].duplicated().sum()),
        'symlinkscan.globalroot_presence': bool(root_presence_mask.any()),
        'symlinkscan.device_target_ratio': round(df['To Name'].str.startswith("\\Device\\", na=False).sum() / total, 4),
        'symlinkscan.offset_gap_stddev': float(df['Offset'].sort_values().diff().std())
    })

    return features

def extract_threads_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'threads.nThreads',
        'threads.null_startpath_ratio',     'threads.kernel_startaddr_ratio',
        'threads.per_process_max_threads','threads.hidden_from_thrdscan_count']

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    null_startpath_ratio     = df['StartPath'].isna().mean()
    kernel_startaddr_ratio   = df['StartAddress'].ge(0xFFFF00000000).mean()
    per_process_max_threads  = df.groupby('PID').size().max()
    thread_offsets = df['Offset']
    
    features = {
        'threads.nThreads'                 : total,
        'threads.null_startpath_ratio'     : float(null_startpath_ratio),
        'threads.kernel_startaddr_ratio'   : float(kernel_startaddr_ratio),
        'threads.per_process_max_threads'  : int(per_process_max_threads)}
    
    return [thread_offsets, features]



#TODO requires cross-plugin comparison with Threads.json
def extract_thrdscan_features(jsondump, **kwargs):
    df = pd.read_json(jsondump)

    threads_offsets = kwargs.get('thrdscan', pd.Series(dtype=object))
    null_startpath_ratio   = df['StartPath'].isna().mean()
    null_createtime_ratio  = df['CreateTime'].isna().mean()
    dup_startaddr    = (df.groupby(['PID','StartAddress']).size())
    orphan_thread_count = (set(df['Offset']) - set(threads_offsets)) if not threads_offsets.empty else None

    return {
        'thrdscan.nThreads':               len(df),           
        'thrdscan.null_startpath_ratio':   float(null_startpath_ratio),
        'thrdscan.null_createtime_ratio':  float(null_createtime_ratio),
        'thrdscan.duplicate_startaddr_ratio': float(dup_startaddr.gt(1).sum() / len(df)),
        'thrdscan.orphan_thread_count':  int(len(orphan_thread_count)) if orphan_thread_count else None
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
    keys =['syscalls.hooked_function_count',
        'syscalls.userland_hook_ratio',
        'syscalls.max_impl_discrepancy',
        'syscalls.hooked_entropy']
    if df.empty:
        return {k : None for k in keys}
    
    def _is_userland(s: str) -> bool:
        parts = s.split(':', 1)
        if len(parts) == 2:
            proc = parts[1].strip()
            return '.' in proc  
        return False

    hooked_df = df['Distinct Implementations'].fillna('').astype(bool)
    is_user_row = df['Distinct Implementations'].fillna('').astype(str).apply(
        lambda s: any(_is_userland(p.strip()) for p in s.replace(',', ';').split(';') if p.strip()))
    userland_hook_ratio = float(is_user_row.mean()) if not hooked_df.empty else 0.0

    impls = []
    hooked_series = df['Distinct Implementations'].fillna('').astype(str)
    for s in hooked_series:
        for part in [p.strip() for p in s.replace(',', ';').split(';') if p.strip()]:
            impls.append(part)

    return {
        'syscalls.hooked_function_count': int(hooked_df.sum()),
        'syscalls.userland_hook_ratio'  : float(userland_hook_ratio),
        'syscalls.max_impl_discrepancy' : int((df['Total Implementations'].max() - df['Total Implementations']).max()),
        'syscalls.hooked_entropy'       : shannon_entropy(impls),
    }



def extract_unloadedmodules_features(jsondump, known_drivers: set[str] = None):
    """
    Extracts these features from windows.unloadedmodules JSON:
      • unloaded.n_entries              : total unload records
      • unloaded.unique_driver_count    : distinct driver names
      • unloaded.repeated_driver_ratio  : (n_entries – unique_driver_count) ÷ n_entries
      • unloaded.burst_max_per_sec      : max unloads in any 1-second window
      • unloaded.non_ms_driver_ratio    : share of names NOT in `known_drivers`
    """
    df = pd.read_json(jsondump)
    keys = ['unloaded.n_entries', 'unloaded.unique_driver_count',
            'unloaded.repeated_driver_ratio', 'unloaded.burst_max_per_sec',
            'unloaded.non_ms_driver_ratio']
    if df.empty:
        return {k: None for k in keys}

    times = pd.to_datetime(df['Time'], errors='coerce', utc=True).dropna().dt.floor('s')
    known_drivers = ["dump_dumpfve.sys","dump_storahci.sys","dump_storport.sys",
                     "hwpolicy.sys","dam.sys","fwcfg.sys","dumpfve.sys","storahci.sys",
                     "storport.sys","acpi.sys","afd.sys","disk.sys","fileinfo.sys",
                     "fltmgr.sys","http.sys","ndis.sys","netio.sys","pci.sys","tcpip.sys",
                     "ntfs.sys","volmgr.sys","volsnap.sys","kdcom.dll"]

    return {
        'unloaded.n_entries'             : df.shape[0],
        'unloaded.unique_driver_count'   : df['Name'].nunique(),
        'unloaded.repeated_driver_ratio' : float((df.shape[0] - df['Name'].nunique()) / df.shape[0]),
        'unloaded.burst_max_per_sec'     : int(times.value_counts().max()) if not times.empty else None,
        'unloaded.non_ms_driver_ratio'   : float((~df["Name"].isin(known_drivers)).mean()),
    }


def extract_vadinfo_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'vadinfo.nEntries',        'vadinfo.nFile',             'vadinfo.nPID',
        'vadinfo.nParent',         'vadinfo.nProcess',          'vadinfo.Process_Malware',
        'vadinfo.Type_Vad',        'vadinfo.Type_VadS',         'vadinfo.Type_VadF',
        'vadinfo.Type_VadI',       'vadinfo.Protection_RO',      'vadinfo.Protection_RW',
        'vadinfo.Protection_NA',   'vadinfo.Protection_EWC',     'vadinfo.Protection_WC',
        'vadinfo.Protection_ERW',  'vadinfo.Avg_Children',      # V2 features
        'vadinfo.exec_ratio',      'vadinfo.large_commit_count', 'vadinfo.avg_region_size_kb',
        'vadinfo.file_backed_ratio','vadinfo.susp_ext_count'      # New features
    ]

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    features = {
        'vadinfo.nEntries': total,
        'vadinfo.nFile': int(df['File'].nunique()),
        'vadinfo.nPID': int(df['PID'].nunique()),
        'vadinfo.nParent': int(df['Parent'].nunique()),
        'vadinfo.nProcess': int(df['Process'].nunique()),
        'vadinfo.Process_Malware': int((df['Process'] == 'malware.exe').sum()),
        'vadinfo.Type_Vad': int((df['Tag'] == 'Vad ').sum()),
        'vadinfo.Type_VadS': int((df['Tag'] == 'VadS').sum()),
        'vadinfo.Type_VadF': int((df['Tag'] == 'VadF').sum()),
        'vadinfo.Type_VadI': int((df['Tag'] == 'VadI').sum()),
        'vadinfo.Protection_RO': int((df['Protection'] == 'PAGE_READONLY').sum()),
        'vadinfo.Protection_RW': int((df['Protection'] == 'PAGE_READWRITE').sum()),
        'vadinfo.Protection_NA': int((df['Protection'] == 'PAGE_NOACCESS').sum()),
        'vadinfo.Protection_EWC': int((df['Protection'] == 'PAGE_EXECUTE_WRITECOPY').sum()),
        'vadinfo.Protection_WC': int((df['Protection'] == 'PAGE_WRITECOPY').sum()),
        'vadinfo.Protection_ERW': int((df['Protection'] == 'PAGE_EXECUTE_READWRITE').sum()),
        'vadinfo.Avg_Children': float(df['__children'].apply(len).mean())
    }

    sus_entries_mask = df['File'].dropna().str.lower().apply(
                lambda f: f.endswith(('.tmp', '.dat', '.bin')) or (f and '.' not in f.split('/')[-1]))
    
    # new metrics inlined
    features.update({
        'vadinfo.exec_ratio': round(df['Protection'].str.contains('EXECUTE', na=False).sum() / total, 4),
        'vadinfo.large_commit_count': int((df['CommitCharge'] >= 100).sum()),
        'vadinfo.avg_region_size_kb': float(((df['End VPN'] - df['Start VPN'] + 1) * 4).mean()),
        'vadinfo.file_backed_ratio': round(df['File'].notna().sum() / total, 4),
        'vadinfo.susp_ext_count': int(sus_entries_mask.sum())
    })

    return features


def extract_vadwalk_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'vadwalk.Avg_Size',      'vadwalk.total_vads',       'vadwalk.max_vad_size',
        'vadwalk.std_vad_size',  'vadwalk.tag_entropy',      'vadwalk.avg_gap_kb'     # V2 & new features
    ]

    if df.empty:
        return {k: None for k in keys}

    # preparatory variables for reuse
    sizes      = df['End'] - df['Start']
    sd        = df.sort_values(['Start', 'End'])
    next_start = sd['Start'].shift(-1)
    gaps       = (next_start - sd['End']).clip(lower=0).dropna()

    features = {
        'vadwalk.Avg_Size': float(sizes.mean())
    }

    features.update({
        'vadwalk.total_vads': int(len(df)),
        'vadwalk.max_vad_size': float(sizes.max()),
        'vadwalk.std_vad_size': float(sizes.std()),
        'vadwalk.tag_entropy': float(shannon_entropy(df['Tag'])),
        'vadwalk.avg_gap_kb': float((gaps.dropna().mean() / 1024))
    })

    return features



def extract_verinfo_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'verinfo.nEntries',     'verinfo.nUniqueProg',  'verinfo.nPID',
        'verinfo.Avg_Children', 'verinfo.valid_version_ratio', 'verinfo.null_name_ratio',
        'verinfo.orphan_entry_count', 'verinfo.avg_major_version', 'verinfo.dup_base_count'
    ]

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    features = {
        'verinfo.nEntries'     : total,
        'verinfo.nUniqueProg'  : df['Name'].nunique(),
        'verinfo.nPID'         : df['PID'].nunique(),
        'verinfo.Avg_Children' : float(df['__children'].apply(len).mean())
    }

    # new metrics inlined
    features.update({
        'verinfo.valid_version_ratio'  : float(((df['Major'].notna() & df['Minor'].notna()).sum() / total)),
        'verinfo.null_name_ratio'      : float((df['Name'].isna().sum() / total)),
        'verinfo.orphan_entry_count'   : int(df['PID'].isna().sum()),
        'verinfo.avg_major_version'    : float(df['Major'].dropna().mean()) if df['Major'].notna().any() else None,
        'verinfo.dup_base_count'       : total - df['Base'].nunique()
    })

    return features

def extract_virtmap_features(jsondump):
    df = pd.read_json(jsondump)
    keys = [
        'virtmap.nEntries',           'virtmap.Avg_Offset_Size',    'virtmap.Avg_Children',
        'virtmap.unused_size_ratio',  'virtmap.zero_len_region_count', 'virtmap.nonstandard_region_count',
        'virtmap.max_region_size_mb', 'virtmap.pagedpool_fragmentation'
    ]

    if df.empty:
        return {k: None for k in keys}

    total = len(df)
    region_sizes = df['Start offset'] - df['End offset']
    total_mapped = region_sizes.sum()
    canonical = [
        'MiVaBootLoaded', 'MiVaDriverImages', 'MiVaFormerlySessionGlobalSpace',
        'MiVaHal', 'MiVaKernelStacks', 'MiVaNonPagedPool', 'MiVaPagedPool',
        'MiVaPfnDatabase', 'MiVaProcessSpace', 'MiVaSessionSpace',
        'MiVaSpecialPoolPaged', 'MiVaSystemCache', 'MiVaSystemPtes',
        'MiVaSystemPtesLarge', 'MiVaUnused'
    ]

    # V2 features
    features = {
        'virtmap.nEntries'       : total,
        'virtmap.Avg_Offset_Size': float(region_sizes.mean()),
        'virtmap.Avg_Children'   : float(df['__children'].apply(len).mean())
    }

    paged_pool_mask = region_sizes[df['Region']=='MiVaPagedPool']

    # New metrics, inlined where possible
    features.update({
        'virtmap.unused_size_ratio'     : float(region_sizes[df['Region']=='MiVaUnused'].sum() / total_mapped),
        'virtmap.zero_len_region_count' : int((df['End offset'] == 0).sum()),
        'virtmap.nonstandard_region_count': int((~df['Region'].isin(canonical)).sum()),
        'virtmap.max_region_size_mb'    : float(region_sizes.max() / (1024 * 1024)),
        'virtmap.pagedpool_fragmentation': float(paged_pool_mask.std() / paged_pool_mask.mean()),
    })

    return features

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
    keys = [
    'winsta.total_stations', 'winsta.service_station_ratio' ,
    'winsta.custom_station_count', 'winsta.session0_gui_count'    
    'winsta.name_entropy_mean']
    if df.empty:
        return {k : None for k in keys}
    
    services_series = df['Name'].fillna('').str.startswith('Service-')
    non_winsta0_series = df['Name'].fillna('').ne('WinSta0')

    return {
        'winsta.total_stations'        : df.shape[0],
        'winsta.service_station_ratio' : float(services_series.mean()),
        'winsta.custom_station_count'  : int((non_winsta0_series & ~services_series).sum()),
        'winsta.session0_gui_count'    : int((non_winsta0_series & df['SessionId'].eq(0)).sum()),
        'winsta.name_entropy_mean'     : float(df['Name'].apply(char_entropy).mean())
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
    keys = ['windows.total_window_objs',
        'windows.pid0_window_ratio',
        'windows.null_title_ratio',
        'windows.blank_process_ratio',
        'windows.avg_win_per_process',
        'windows.station_mismatch_count']
    if df.empty:
        return {k : None for k in keys}

    if df["PID"].nunique() == 1 and df["PID"].iloc[0] == 0:
        avg_windows_per_pid = None
    else:
        avg_windows_per_pid = float(df.groupby('PID').size().mean())

    return {
        'windows.total_window_objs'      : df.shape[0],
        'windows.pid0_window_ratio'      : float(df['PID'].eq(0).mean()),
        'windows.null_title_ratio'       : float(df['Window'].isna().mean()),
        'windows.blank_process_ratio'    : float(df['Process'].fillna('').eq('').mean()),
        'windows.avg_win_per_process'    : avg_windows_per_pid,
        'windows.station_mismatch_count' : int(df['Station'].fillna('').ne('WinSta0').sum()),
    }



####################################################################################
####################################################################################

####################################################################################
####################################################################################


#TODO Empty json output
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

#TODO Empty file
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

#TODO exactly the same output as scheduled tasks
def extract_registry_scheduled_tasks_features():
  return{}

#TODO creates a lot of garbage in VOLMEMLYZER Folder
def extract_dumpfiles_features(jsondump):     
    df=pd.read_json(jsondump)
    return{
        'dumpfiles.ndump': df.FileObject.size,                                                  #Number of dump files
        'dumpfiles.nCache': df.Cache.unique().size,                                             #Number of Cache
        'dumpfiles.nFile': df.FileName.unique().size,                                           #Number of distinct files
    }

# Not in the current volatility plugins
# def extract_mftscan_features(jsondump):
#     df=pd.read_json(jsondump)
#     return{
#         'mftscan.nEntriesMFT': len(df), #101
#         'mftscan.nAttributeType': df['Attribute Type'].nunique(),
#         'mftscan.nRecordType': df['Record Type'].nunique(),
#         'mftscan.AvgRecordNum': df['Record Number'].mean(),
#         'mftscan.AvgLinkCount': df['Link Count'].mean(),
#         'mftscan.0x9_typeMFT': len(df[df['MFT Type'] == '0x9']),
#         'mftscan.0xd_typeMFT': len(df[df['MFT Type'] == '0xd']),
#         'mftscan.DirInUse_typeMFT': len(df[df['MFT Type'] == 'DirInUse']),
#         'mftscan.Removed_typeMFT': len(df[df['MFT Type'] == 'Removed']),
#         'mftscan.File_typeMFT': len(df[df['MFT Type'] == 'File']),
#         'mftscan.Other_typeMFT': len(df[~df['MFT Type'].isin(['0x9','0xd','DirInUse','Removed','File'])]),
#         'mftscan.AvgChildren': df['__children'].apply(len).mean()
    # }

#TODO   Empty json output for the plugin
def extract_hollow_processes_features():
  return{}

#TODO   Empty json output for the plugin
def extract_etwpatch_features():
  return{}

#TODO   Empty json output for the plugin
def extract_crashinfo_features():
  return{}

#TODO   Empty json output for the plugin
def extract_orphan_kernel_threads_features():
  return{}

#TODO   Empty json output for the plugin
def extract_processghosting_features():
  return{}

#TODO   Empty json output for the plugin
def extract_registry_getcellroutine_features():
  return{}

#TODO   Empty json output for the plugin
def extract_suspended_threads_features():
  return{}

#TODO   Empty json output for the plugin
def extract_svcdiff_features():
  return{}

#TODO   Empty json output for the plugin
def extract_suspicious_threads_features():
  return{}