#!/usr/bin/env python3

import argparse
import csv
import functools
import json
import sys
import subprocess
import tempfile
import os

def to_csv(outfile, header, dict_, dumpname):
    writer = csv.DictWriter(outfile, fieldnames=header)
    # writer.writeheader()
    outfile.write(os.path.basename(dumpname) + ',')
    writer.writerow(dict_)

# Extractor functions. It is assumed that the total number and names of items returned by those functions never change and all values needs to be uniquely named.
def extract_pslist_features(jsondump):
    procs = rc2kv(json.load(jsondump))
    ppids = set(p['PPID'] for p in procs)
    return {
        # # of processes
        'pslist.nproc': len(procs),
        # # of parent processes
        'pslist.nppid': len(ppids),
        # Avg. thread count
        'pslist.avg_threads': sum(p['Thds'] for p in procs) / len(procs),
        # # of 64-bit processes
        # TODO what about Linux?
        'pslist.nprocs64bit': sum(p['Wow64'] for p in procs),
	# Avg. handler count
	'pslist.avg_handlers': sum(p['Hnds'] for p in procs) / len(procs),
    }


def extract_dlllist_features(jsondump):
    dlllist = rc2kv(json.load(jsondump))
    # count # of pids in the report
    procs = len(set(l['Pid'] for l in dlllist))
    return {
        # Total # of loaded libraries of all processes
        'dlllist.ndlls': len(dlllist),
        # Avg. loaded libraries per process
        'dlllist.avg_dlls_per_proc': len(dlllist) / procs,
    }

def extract_handles_features(jsondump):
    # "columns": ["Offset(V)", "Pid", "Handle", "Access", "Type", "Details"]
    handles = rc2kv(json.load(jsondump))
    return {
        # Total # of opened handles
        'handles.nhandles': len(handles),
        # Avg. handle count per process
        'handles.avg_handles_per_proc': len(handles) / len(set(h['Pid'] for h in handles)),
        # TODO: Per-type counts?
	# # of handles of type port
	'handles.nport': sum(1 if t['Type'] == 'Port' else 0 for t in handles),
	# # of handles of type file
	'handles.nfile': sum(1 if t['Type'] == 'File' else 0 for t in handles),
	# # of handles of type event
	'handles.nevent': sum(1 if t['Type'] == 'Event' else 0 for t in handles),
	# # of handles of type desktop
	'handles.ndesktop': sum(1 if t['Type'] == 'Desktop' else 0 for t in handles),
	# # of handles of type key
	'handles.nkey': sum(1 if t['Type'] == 'Key' else 0 for t in handles),
	# # of handles of type thread
	'handles.nthread': sum(1 if t['Type'] == 'Thread' else 0 for t in handles),
	# # of handles of type directory
	'handles.ndirectory': sum(1 if t['Type'] == 'Directory' else 0 for t in handles),
	# # of handles of type semaphore
	'handles.nsemaphore': sum(1 if t['Type'] == 'Semaphore' else 0 for t in handles),
	# # of handles of type timer
	'handles.ntimer': sum(1 if t['Type'] == 'Timer' else 0 for t in handles),
	# # of handles of type section
	'handles.nsection': sum(1 if t['Type'] == 'Section' else 0 for t in handles),
	# # of handles of type mutant
	'handles.nmutant': sum(1 if t['Type'] == 'Mutant' else 0 for t in handles),
    }

def extract_ldrmodules_features(jsondump):
    ldrmodules = rc2kv(json.load(jsondump))
    return {
        # # of modules missing from load list
        'ldrmodules.not_in_load': sum(1 if m['InLoad'] == 'False' else 0 for m in ldrmodules),
        # # of modules missing from init list
        'ldrmodules.not_in_init': sum(1 if m['InInit'] == 'False' else 0 for m in ldrmodules),
        # # of modules missing from mem list
        'ldrmodules.not_in_mem': sum(1 if m['InMem'] == 'False' else 0 for m in ldrmodules),
	# avg number of modules missing from load list
        'ldrmodules.not_in_load_avg': sum(1 if m['InLoad'] == 'False' else 0 for m in ldrmodules)/ len(ldrmodules) or 1,
	# avg number of modules missing from init list
        'ldrmodules.not_in_init_avg': sum(1 if m['InInit'] == 'False' else 0 for m in ldrmodules)/ len(ldrmodules) or 1,
	# avg number of modules missing from mem list
        'ldrmodules.not_in_mem_avg': sum(1 if m['InMem'] == 'False' else 0 for m in ldrmodules)/ len(ldrmodules) or 1,
    }

def extract_malfind_features(jsondump):
    malfind = rc2kv(json.load(jsondump))
    # # of hidden code injections found by malfind
    return {
        'malfind.ninjections': len(malfind),
	'malfind.commitCharge': sum(int(dict(entry.split(': ') for entry in flags['Flags'].split(', ')).get('CommitCharge',0)) for flags in malfind),
	'malfind.protection': sum(int(dict(entry.split(': ') for entry in flags['Flags'].split(', ')).get('Protection',0)) for flags in malfind),
	'malfind.uniqueInjections': len(malfind) / len(set(h['Pid'] for h in malfind)),
    }

def extract_psxview_features(jsondump):
    psxview = rc2kv(json.load(jsondump))
    # https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal#psxview
    return {
        'psxview.not_in_pslist': sum(1 if p['pslist'] == 'False' else 0 for p in psxview),
        'psxview.not_in_eprocess_pool': sum(1 if p['psscan'] == 'False' else 0 for p in psxview),
        'psxview.not_in_ethread_pool': sum(1 if p['thrdproc'] == 'False' else 0 for p in psxview),
        'psxview.not_in_pspcid_list': sum(1 if p['pspcid'] == 'False' else 0 for p in psxview),
        'psxview.not_in_csrss_handles': sum(1 if p['csrss'] == 'False' else 0 for p in psxview),
        'psxview.not_in_session': sum(1 if p['session'] == 'False' else 0 for p in psxview),
        'psxview.not_in_deskthrd': sum(1 if p['deskthrd'] == 'False' else 0 for p in psxview),
	# avg number of false results in the psxview command	
	'psxview.not_in_pslist_false_avg': sum(1 if p['pslist'] == 'False' else 0 for p in psxview)/len(psxview),
        'psxview.not_in_eprocess_pool_false_avg': sum(1 if p['psscan'] == 'False' else 0 for p in psxview)/len(psxview),
        'psxview.not_in_ethread_pool_false_avg': sum(1 if p['thrdproc'] == 'False' else 0 for p in psxview)/len(psxview),
        'psxview.not_in_pspcid_list_false_avg': sum(1 if p['pspcid'] == 'False' else 0 for p in psxview)/len(psxview),
        'psxview.not_in_csrss_handles_false_avg': sum(1 if p['csrss'] == 'False' else 0 for p in psxview)/len(psxview),
        'psxview.not_in_session_false_avg': sum(1 if p['session'] == 'False' else 0 for p in psxview)/len(psxview),
        'psxview.not_in_deskthrd_false_avg': sum(1 if p['deskthrd'] == 'False' else 0 for p in psxview)/len(psxview),
    }

def extract_connections_features(jsondump):
    connections = rc2kv(json.load(jsondump))
    return {
        'connections.nconnections': len(connections),
        'connections.nremotes': len(set(conn['RemoteAddress'] for conn in connections)),
    }

def extract_sockets_features(jsondump):
    sockets = rc2kv(json.load(jsondump))
    return {
        'sockets.nsockets': len(sockets),
        'sockets.ntcp': sum(1 if s['Protocol'] == 'TCP' else 0 for s in sockets),
        'sockets.nudp': sum(1 if s['Protocol'] == 'UDP' else 0 for s in sockets),
    }

def extract_modules_features(jsondump):
    modules = rc2kv(json.load(jsondump))
    return {
        'modules.nmodules': len(modules)
    }

def extract_svcscan_features(jsondump):
    svcscan = rc2kv(json.load(jsondump))
    return {
        'svcscan.nservices': len(svcscan),
        'svcscan.kernel_drivers': sum(1 if s['ServiceType'] == 'SERVICE_KERNEL_DRIVER' else 0 for s in svcscan),
        'svcscan.fs_drivers': sum(1 if s['ServiceType'] == 'SERVICE_FILE_SYSTEM_DRIVER' else 0 for s in svcscan),
        'svcscan.process_services': sum(1 if s['ServiceType'] == 'SERVICE_WIN32_OWN_PROCESS' else 0 for s in svcscan),
        'svcscan.shared_process_services': sum(1 if s['ServiceType'] == 'SERVICE_WIN32_SHARE_PROCESS' else 0 for s in svcscan),
        'svcscan.interactive_process_services': sum(1 if s['ServiceType'] == 'SERVICE_INTERACTIVE_PROCESS' else 0 for s in svcscan),
        'svcscan.nactive': sum(1 if s['State'] == 'SERVICE_RUNNING' else 0 for s in svcscan),
    }

def extract_callbacks_features(jsondump):
    callbacks = rc2kv(json.load(jsondump))
    return {
        'callbacks.ncallbacks': len(callbacks),
        'callbacks.nanonymous': sum(1 if c['Module'] == 'UNKNOWN' else 0 for c in callbacks),
        'callbacks.ngeneric': sum(1 if c['Type'] == 'GenericKernelCallback' else 0 for c in callbacks),
    }

def extract_apihooks_features(jsondump):
    apihooks = rc2kv(json.load(jsondump))    
    return {
	'apihooks.nhooks': len(apihooks),
	'apihooks.nhooksInline': sum(1 if s['HookType'] == 'Inline/Trampoline' else 0 for s in apihooks),
	'apihooks.nhooksUsermode': sum(1 if s['HookMode'] == 'Usermode' else 0 for s in apihooks),
    }


VOL_MODULES = {
    'pslist': extract_pslist_features,
    'dlllist': extract_dlllist_features,
    'handles': extract_handles_features,
    'ldrmodules': extract_ldrmodules_features,
    'malfind': extract_malfind_features,
    'psxview': extract_psxview_features,
    'connections': extract_connections_features,
    'sockets': extract_sockets_features,
    'modules': extract_modules_features,
    'svcscan': extract_svcscan_features,
    'callbacks': extract_callbacks_features,
    'apihooks': extract_apihooks_features,
}

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('memdump', help='Memory dump file.')
    p.add_argument('-o', '--output', default=None, help='Path to the output CSV file.')
    p.add_argument('-V', '--volatility-exe', default='volatility', help='Name of volatility executable.')
    return p, p.parse_args()

def rc2kv(rc):
    kv = []
    keys = rc['columns']
    for r in rc['rows']:
        entry = {}
        kv.append(entry)
        for k, v in zip(keys, r):
            entry[k] = v
    return kv

def invoke_volatility(volatility_exe, memdump_path, module, output_to):
    subprocess.run([volatility_exe, '-f', memdump_path, '--output=json', '--output-file', output_to, '--', module], check=True)

def extract_all_features_from_memdump(memdump_path, output_to, volatility_exe):
    features = {}
    if output_to is None:
        output_to = '{}.csv'.format(memdump_path)
    print('=> Outputting to', output_to)

    with tempfile.TemporaryDirectory() as workdir:
        vol = functools.partial(invoke_volatility, volatility_exe, memdump_path)
        for module, extractor in VOL_MODULES.items():
            print('=> Executing Volatility module', repr(module))
            output_file_path = os.path.join(workdir, module)
            vol(module, output_file_path)
            with open(output_file_path, 'r') as output:
                features.update(extractor(output))

    with open(output_to, 'a') as f:
        to_csv(f, features.keys(), features, memdump_path)

    print('=> All done')

if __name__ == '__main__':
    p, args = parse_args()
    if not os.path.isfile(args.memdump):
        p.error('Specified memory dump does not exist or is not a file.')
	# Enter file path here
    for filename in os.listdir('/home/'):
        if filename.endswith('.raw'):
		# Enter file path here
                path_in_str = os.path.join('/home/', filename)
                extract_all_features_from_memdump(path_in_str, args.output, args.volatility_exe)
