import extractors
from datetime import datetime, timezone


PID_LIST = []
IOC_KEYWORDS = ["curl", "http", "invoke-webrequest", "mimikatz"]
DUMP_TIME = datetime.now(timezone.utc)

BASE_VOL_MODULES = {'info', 'pslist', 'registry.hivelist', 'threads'}

PLUGIN_DEPENDENCIES = {
    'thrdscan': 'threads',
    'registry.hivescan': 'registry.hivelist',
    'deskscan': 'pslist',
    # 'psscan' : 'pslist',
    'amcache': 'info',
}

VOL_MODULES = {
    'info': extractors.extract_winInfo_features,
    'pslist': extractors.extract_pslist_features,
    'amcache' : extractors.extract_amcache_features,
    'bigpools' : extractors.extract_bigpools_features,
    'callbacks': extractors.extract_callbacks_features,
    'cmdline': extractors.extract_cmdline_features,
    'cmdscan' : extractors.extract_cmdscan_features, 
    'consoles' : extractors.extract_consoles_features,
    'deskscan': extractors.extract_deskscan_features,
    'devicetree': extractors.extract_devicetree_features,
    'dlllist': extractors.extract_dlllist_features,
    'driverirp': extractors.extract_driverirp_features,
    'drivermodule': extractors.extract_drivermodule_features,
    'driverscan': extractors.extract_driverscan_features,
    # 'dumpfiles': extractors.extract_dumpfiles_features,        # Creates Junk files in the Folder where VolMemLyzer is present [TRY NOT TO USE]
    'envars': extractors.extract_envars_features,
    'filescan': extractors.extract_filescan_features,
    'getservicesids': extractors.extract_getservicesids_features,
    'getsids': extractors.extract_getsids_features,
    'handles': extractors.extract_handles_features,
    'iat': extractors.extract_iat_features,
    'joblinks': extractors.extract_joblinks_features,
    'ldrmodules': extractors.extract_ldrmodules_features,
    'malfind': extractors.extract_malfind_features,
    'modscan': extractors.extract_modscan_features,
    'mbrscan': extractors.extract_mbrscan_features,
    'modules': extractors.extract_modules_features,
    'mutantscan': extractors.extract_mutantscan_features,
    'netscan': extractors.extract_netscan_features,
    # 'netstat': extractors.extract_netstat_features,           #TODO Empty file               
    'poolscanner': extractors.extract_poolscanner_features,
    'privileges': extractors.extract_privileges_features,
    'pstree': extractors.extract_pstree_features,
    'psxview': extractors.extract_psxview_features,
    'psscan' : extractors.extract_psscan_features,
    'registry_amcache': extractors.extract_registry_amcache_features,
    'registry.printkey': extractors.extract_registry_printkey_features,
    'registry.hivelist': extractors.extract_registry_hivelist_features,
    'registry.hivescan': extractors.extract_registry_hivescan_features,
    'registry.certificates': extractors.extract_registry_certificates_features,
    'registry.userassist': extractors.extract_registry_userassist_features,
    'shimcache': extractors.extract_shimcache_features,
    'skeleton_key': extractors.extract_skeleton_key_features,
    'statistics': extractors.extract_statistics_features,
    'ssdt': extractors.extract_ssdt_features,
    'sessions': extractors.extract_sessions_features,
    'scheduled_tasks': extractors.extract_scheduleduled_tasks_features,
    'svcscan': extractors.extract_svcscan_features,
    'svclist': extractors.extract_svclist_features,
    'timers': extractors.extract_timers_features,
    'symlinkscan': extractors.extract_symlinkscan_features,
    'threads': extractors.extract_threads_features,
    'thrdscan': extractors.extract_thrdscan_features,
    'unhooked_system_calls': extractors.extract_unhooked_system_calls_features,
    'unloadedmodules': extractors.extract_unloadedmodules_features,
    'vadinfo': extractors.extract_vadinfo_features,
    'vadwalk': extractors.extract_vadwalk_features,
    'verinfo': extractors.extract_verinfo_features,
    'virtmap': extractors.extract_virtmap_features,
    'windowstations': extractors.extract_windowstations_features,
    'windows.Windows': extractors.extract_windows_features,
    # 'memmap': extractors.extract_memmap_features,             # Volatility Incompatibility [DO NOT USE]
    # 'mftscan': extractors.extract_mftscan_features,
}

# Drop plugins that are known to be slow (> 1000 s)
# SLOW_PLUGINS = {
#     'callbacks', 'devicetree', 'driverirp', 'drivermodule', 'driverscan',
#     'filescan', 'modscan', 'mutantscan', 'netscan', 'poolscanner',
#     'symlinkscan',
# }

