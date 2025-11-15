from .extractors import *
from .extractors import _legacy_adapter
from .core import PluginSpec
from .extractor_registry import ExtractorRegistry

PLUGIN_SPECIFICS = [
    # name,                 extractor_fn,                                         depcles, timeout
    ("info",                 extract_winInfo_features,                 (),                          None),
    ("pslist",               extract_pslist_features,                  (), None),
    ("psscan",               extract_psscan_features,                  ("pslist",),                 None),
    ("threads",              extract_threads_features,                 (), None),
    ("thrdscan",             extract_thrdscan_features,                ("threads",),                None),
    ("deskscan",             extract_deskscan_features,                ("pslist",),                 None),
    ("amcache",              extract_amcache_features,                 ("info",),                   None),

    ("bigpools",             extract_bigpools_features,                (), None),
    ("cmdline",              extract_cmdline_features,                 (), None),
    ("cmdscan",              extract_cmdscan_features,                 (), None),
    ("consoles",             extract_consoles_features,                (), None),
    ("dlllist",              extract_dlllist_features,                 (), None),
    ("envars",               extract_envars_features,                  (), None),
    ("getservicesids",       extract_getservicesids_features,          (), None),
    ("getsids",              extract_getsids_features,                 (), None),
    ("handles",              extract_handles_features,                 (), None),
    ("iat",                  extract_iat_features,                     (), None),
    ("joblinks",             extract_joblinks_features,                (), None),
    ("ldrmodules",           extract_ldrmodules_features,              (), None),
    ("malfind",              extract_malfind_features,                 (), None),
    ("mbrscan",              extract_mbrscan_features,                 (), None),
    ("modules",              extract_modules_features,                 (), None),
    ("netstat",              extract_netstat_features,                 (), None),
    ("privileges",           extract_privileges_features,              (), None),
    ("pstree",               extract_pstree_features,                  (), None),

    ("registry.amcache",     extract_registry_amcache_features,        (), None),
    ("registry.printkey",    extract_registry_printkey_features,       (), None),
    ("registry.hivelist",    extract_registry_hivelist_features,       (), None),
    ("registry.hivescan",    extract_registry_hivescan_features,       ("registry.hivelist",),      None),
    ("registry.certificates",extract_registry_certificates_features,   (), None),
    ("registry.userassist",  extract_registry_userassist_features,     (), None),

    ("shimcache",            extract_shimcache_features,               (), None),
    ("skeleton_key",         extract_skeleton_key_features,            (), None),
    ("ssdt",                 extract_ssdt_features,                    (), None),
    ("statistics",           extract_statistics_features,              (), None),
    ("svcscan",              extract_svcscan_features,                 (), None),
    ("svclist",              extract_svclist_features,                 (), None),
    ("timers",               extract_timers_features,                  (), None),

    ("vadinfo",              extract_vadinfo_features,                 (), None),
    ("vadwalk",              extract_vadwalk_features,                 (), None),
    ("verinfo",              extract_verinfo_features,                 (), None),
    ("virtmap",              extract_virtmap_features,                 (), None),
    ("windows.Windows",      extract_windows_features,                 (), None),


    # Heavy/optional plugins (often very slow) — enable as needed:
    ("callbacks",         extract_callbacks_features,                (), None),
    ("devicetree",        extract_devicetree_features,               (), None),
    ("driverirp",         extract_driverirp_features,                (), None),
    ("drivermodule",      extract_drivermodule_features,             (), None),
    ("driverscan",        extract_driverscan_features,               (), None),
    ("filescan",          extract_filescan_features,                 (), None),
    ("modscan",           extract_modscan_features,                  (), None),
    ("mutantscan",        extract_mutantscan_features,               (), None),
    ("netscan",             extract_netscan_features,                  (), None),
    ("scheduled_tasks",     extract_netscan_features,                  (), None),

    ("poolscanner",       extract_poolscanner_features,              (), None),
    ("symlinkscan",       extract_symlinkscan_features,              (), None),
    ("psxview",           extract_psxview_features,                  (), None)
]

def parse_entries(ent):
    ent_dict = {'name': ent[0], 'func': ent[1], 'deps': ent[2], 'timeout': ent[3]}
    name = str(ent_dict['name']).strip()
    lower = name.lower()
    fqname = lower if lower.startswith("windows.") else f"windows.{lower}"
    spec = PluginSpec(name=lower, fqname=fqname, deps=tuple(ent_dict['deps']), timeout_s=ent_dict['timeout'])
    func = _legacy_adapter(ent_dict['func'])
    return spec, func



def build_registry() -> ExtractorRegistry:
    reg = ExtractorRegistry()
    for ent in PLUGIN_SPECIFICS:
        spec, func = parse_entries(ent)
        reg.register(spec, func)
    return reg            