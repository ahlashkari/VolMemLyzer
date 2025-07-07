import subprocess 
import csv
import os
import math
import pandas as pd
from collections.abc import Iterable
from collections import Counter


def invoke_volatility3(vol_py_path, memdump_path, module, output_to):
    with open(output_to,'w') as f:
        subprocess.run(['python',vol_py_path, '-f', memdump_path, '-r=json', 'windows.'+module],stdout=f,text=True, check=True)

def _char_entropy(s: str) -> float:
    """Per-string Shannon entropy (0-8 bit range for ASCII)."""
    if not s:
        return 0.0
    cnt, n = Counter(s), len(s)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())

# --------------------------------------------------------------------------- #
def _flatten_records(rows):
    """Yield every dict in the tree (top + nested __children)."""
    for r in rows:
        yield r
        for child in r.get("__children", []):
            yield from _flatten_records([child])


def shannon_entropy(obj):

    # ── normalise to a pandas Series ─────────────────────────────────────────
    if isinstance(obj, pd.Series):
        series = obj.dropna()
    elif isinstance(obj, str):
        series = pd.Series(list(obj))
    elif isinstance(obj, Iterable):
        series = pd.Series(list(obj))
    else:
        raise TypeError(f"Unsupported type for shannon_entropy: {type(obj)}")

    if series.empty:
        return 0.0

    counts = series.value_counts(normalize=True)
    return float((-counts * counts.map(math.log2)).sum())

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