import argparse
import csv
import functools
import json
import subprocess
import tempfile
import os
import pandas as pd


# Extractor functions extracts features from the Volatility

def extract_winInfo_features(jsondump):
    df = pd.read_json(jsondump)
    try:
        a = bool(json.loads(df.loc[3].at["Value"].lower()))           #Is Windows a 64 Version 
        b = df.loc[8].at["Value"]                                 #Version of Windows Build
        c = int(df.loc[11].at["Value"])                               #Number of Processors
        d = bool(json.loads(df.loc[4].at["Value"].lower()))          #Is Windows Physical Address Extension (PAE) is a processor feature that enables x86 processors to access more than 4 GB of physical memory
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

def extract_pslist_features(jsondump):
    df = pd.read_json(jsondump)
    try:
        a = df.PPID.size                                           #Number of Processes
        b = df.PPID.nunique()                                  #Number of Parent Processes
        c = df.Threads.mean()                  #Average Thread count
        d = df.Handles.mean()                 #Average Handler count
        e = len(df[df["Wow64"]=="True"])                     #Number of 64-Bit Processes
        f = df.PPID.size - len(df[df["File output"]=="Disabled"]) #Number of processes with FileOutput enabled 
    except:
        a = None
        b = None
        c = None
        d = None
        e = None
        f = None
    return{
        'pslist.nproc': a,
        'pslist.nppid': b,
        'pslist.avg_threads': c,
        'pslist.avg_handlers': d,
        'pslist.nprocs64bit': e,
        'pslist.outfile': f
    }

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

VOL_MODULES = {
    'info': extract_winInfo_features,
    'pslist': extract_pslist_features,
    'dlllist': extract_dlllist_features,
    'handles': extract_handles_features,
    'ldrmodules': extract_ldrmodules_features,
    'malfind': extract_malfind_features,
    'modules': extract_modules_features,
    'callbacks': extract_callbacks_features,
    'cmdline': extract_cmdline_features,
    'devicetree': extract_devicetree_features,
    'driverirp': extract_driverirp_features,
    'drivermodule': extract_drivermodule_features,
    'driverscan': extract_driverscan_features,
    #####'dumpfiles': extract_dumpfiles_features,        # Creates Junk files in the Folder where VolMemLyzer is present [TRY NOT TO USE]
    'envars': extract_envars_features,
    'filescan': extract_filescan_features,
    'getsids': extract_getsids_features,
    'mbrscan': extract_mbrscan_features,
    #####'memmap': extract_memmap_features,             # Volatility Incompatibility [DO NOT USE]
    'mftscan': extract_mftscan_features,
    'modscan': extract_modscan_features,
    'mutantscan': extract_mutantscan_features,
    'netscan': extract_netscan_features,
    'netstat': extract_netstat_features,
    'poolscanner': extract_poolscanner_features,
    'privileges': extract_privileges_features,
    'pstree': extract_pstree_features,
    'registry.certificates': extract_registry_certificates_features,
    'registry.hivelist': extract_registry_hivelist_features,
    'registry.hivescan': extract_registry_hivescan_features,
    'registry.printkey': extract_registry_printkey_features,
    'registry.userassist': extract_registry_userassist_features,
    'sessions': extract_sessions_features,
    'skeleton_key': extract_skeleton_key_features,
    'ssdt': extract_ssdt_features,
    'statistics': extract_statistics_features,
    'svcscan': extract_svcscan_features,
    'symlinkscan': extract_symlinkscan_features,
    'vadinfo': extract_vadinfo_features,
    'vadwalk': extract_vadwalk_features,
    'verinfo': extract_verinfo_features,
    'virtmap': extract_virtmap_features

}



def invoke_volatility3(vol_py_path, memdump_path, module, output_to):
    with open(output_to,'w') as f:
        subprocess.run(['python3',vol_py_path, '-f', memdump_path, '-r=json', 'windows.'+module],stdout=f,text=True, check=True)




def write_dict_to_csv(filename, dictionary,memdump_path):
    fieldnames = list(dictionary.keys())
    
    # Check if the file already exists
    file_exists = os.path.isfile(filename)
    
    with open(filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        # Write header only if the file is empty
        if not file_exists:
            writer.writeheader()
        writer.writerow(dictionary)







def extract_all_features_from_memdump(memdump_path, CSVoutput_path, volatility_path):
    features = {}
    print('=> Outputting to', CSVoutput_path)

    with tempfile.TemporaryDirectory() as workdir:
        vol = functools.partial(invoke_volatility3, volatility_path, memdump_path)
        for module, extractor in VOL_MODULES.items():
            print('=> Executing Volatility module', repr(module))
            output_file_path = os.path.join(workdir, module)
            vol(module, output_file_path)
            with open(output_file_path, 'r') as output:
                features.update(extractor(output))
    
    features_mem = {'mem.name_extn': str(memdump_path).rsplit('/', 1)[-1]}
    features_mem.update(features)

    file_path = os.path.join(CSVoutput_path, 'output.csv')
    write_dict_to_csv(file_path,features_mem,memdump_path)

    print('=> All done')



def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-f','--memdump',default=None, help='Path to folder/directory which has all memdumps',required = True)
    p.add_argument('-o', '--output', default=None, help='Path to the folder where to output the CSV',required = True)
    p.add_argument('-V', '--volatility', default=None, help='Path to the vol.py file in Volatility folder including the extension .py',required = True)
    return p, p.parse_args()





if __name__ == '__main__':
    p, args = parse_args()

    #print(args.memdump)
    folderpath = str(args.memdump)
    file_list = sorted(os.listdir(folderpath), key=lambda x: -os.path.getmtime(os.path.join(folderpath, x)), reverse=True)

    print(folderpath)

    for filename in file_list:
        print("==> Now resolving features for : ",filename)
        print()
        file_path = os.path.join(folderpath, filename)
        #print(file_path)

        if (file_path).endswith('.raw') or (file_path).endswith('.mem') or (file_path).endswith('.vmem') or (file_path).endswith('.mddramimage'):
            extract_all_features_from_memdump((file_path), args.output, args.volatility)
