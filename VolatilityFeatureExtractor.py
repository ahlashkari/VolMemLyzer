#!/usr/bin/env python3

import argparse
import csv
import functools
import json
import sys
import subprocess
import tempfile
import os

def to_csv(outfile, header, dict_):
    writer = csv.DictWriter(outfile, fieldnames=header)
    writer.writeheader()
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
    }

def extract_malfind_features(jsondump):
    malfind = rc2kv(json.load(jsondump))
    # # of hidden code injections found by malfind
    return {
        'malfind.ninjections': len(malfind),
    }

VOL_MODULES = {
    'pslist': extract_pslist_features,
    'dlllist': extract_dlllist_features,
    'handles': extract_handles_features,
    'ldrmodules': extract_ldrmodules_features,
    'malfind': extract_malfind_features,
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

    with open(output_to, 'w') as f:
        to_csv(f, features.keys(), features)

    print('=> All done')

if __name__ == '__main__':
    p, args = parse_args()
    extract_all_features_from_memdump(args.memdump, args.output, args.volatility_exe)
