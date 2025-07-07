import pandas as pd
import json
from utils import shannon_entropy, _char_entropy, _flatten_records
from collections import Counter



def extract_winInfo_features(jsondump):
    df = pd.read_json(jsondump)
    try:
        a = bool(json.loads(df.loc[3].at["Value"].lower()))           #Is Windows a 64 Version 
        b = df.loc[8].at["Value"]                                     #Version of Windows Build
        c = int(df.loc[11].at["Value"])                               #Number of Processors
        d = bool(json.loads(df.loc[4].at["Value"].lower()))           #Is Windows Physical Address Extension (PAE) is a processor feature that enables x86 processors to access more than 4 GB of physical memory
    except:
        a = None
        b = None
        c = None
        d = None
    return{
        'info.Is64': a,
        'info.winBuild': b,
        'info.npro': c,
        'info.IsPAE': d
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
    try:
        records = json.load(jsondump)          # jsondump is an open()-handle
    except Exception:
        return {                               # keep headers stable on failure
            'cmdscan.nHistories'   : None,
            'cmdscan.nonZeroHist'  : None,
            'cmdscan.maxCmds'      : None,
            'cmdscan.appMismatch'  : None,
            'cmdscan.cmdCountRatio': None,
        }

    # ── gather one dict per history block ────────────────────────────────────
    histories = []
    for rec in records:
        if rec.get('Property') != '_COMMAND_HISTORY':
            continue

        hist = {'PID': rec.get('PID'), 'Process': rec.get('Process')}
        for child in rec.get('__children', []):
            prop = child.get('Property', '')
            dat  = child.get('Data', '')

            if prop.endswith('.Application'):
                hist['Application'] = dat
            elif prop.endswith('.CommandCount'):
                hist['CommandCount'] = int(dat or 0)
            elif prop.endswith('.CommandCountMax'):
                hist['CommandCountMax'] = int(dat or 0)

        histories.append(hist)

    if not histories:            # rare but possible
        return {
            'cmdscan.nHistories'   : 0,
            'cmdscan.nonZeroHist'  : 0,
            'cmdscan.maxCmds'      : 0,
            'cmdscan.appMismatch'  : 0,
            'cmdscan.cmdCountRatio': 0.0,
        }

    # ── compute metrics ──────────────────────────────────────────────────────
    n_hist   = len(histories)
    non_zero = sum(h.get('CommandCount', 0) > 0 for h in histories)
    max_cmds = max(h.get('CommandCount', 0) for h in histories)

    app_mis  = sum(
        1 for h in histories
        if h.get('Application', '').lower() not in ('', h.get('Process', '').lower())
    )

    ratios   = [
        h['CommandCount'] / h['CommandCountMax']
        for h in histories
        if h.get('CommandCountMax', 0) > 0
    ]
    mean_ratio = round(mean(ratios), 4) if ratios else 0.0

    return {
        'cmdscan.nHistories'   : n_hist,
        'cmdscan.nonZeroHist'  : non_zero,
        'cmdscan.maxCmds'      : max_cmds,
        'cmdscan.appMismatch'  : app_mis,
        'cmdscan.cmdCountRatio': mean_ratio,
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

    flat = list(_flatten_records(data))
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

    name_entropy = [_char_entropy(str(r.get("Name", ""))) for r in flat]
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

def extract_modules_features(jsondump):
    df = pd.read_json(jsondump)
    return {
        'modules.nmodules': df.Base.size,                                          #Number of Modules
        'modules.avgSize': df.Size.mean(),                             #Average size of the modules
        'modules.FO_enabled': df.Base.size - len(df[df["File output"]=='Disabled'])#Number of Output enabled File Output
    }

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