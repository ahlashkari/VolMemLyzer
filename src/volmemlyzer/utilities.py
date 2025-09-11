# File: /mnt/data/utils.py
import os, csv, math, json, hashlib, re
from dataclasses import is_dataclass, asdict
from collections.abc import Mapping
from collections import Counter
from collections.abc import Iterable
import pandas as pd
import os
import re
import ntpath

RENDERER_EXT_MAP = {
    "json": "json",
    "jsonl": "jsonl",
    "pretty": "txt",
    "csv": "csv",
    "quick": "txt",
    "none": "txt",
}

def renderer_to_ext(renderer: str) -> str:
    return RENDERER_EXT_MAP.get((renderer or "").lower(), "json")

def find_artifact(outdir: str, name: str, exts: list[str]) -> str | None:
    for ext in exts:
        p = os.path.join(outdir, f"{name}.{ext}")
        if os.path.exists(p):
            return p
    return None

def _flatten_dict(d: dict, prefix: str = "", sep: str = ".") -> dict:
    """Recursively flattens a nested dict using dot-separated keys."""
    flat = {}
    for k, v in (d or {}).items():
        kk = f"{prefix}{sep}{k}" if prefix else k
        if isinstance(v, dict):
            flat.update(_flatten_dict(v, kk, sep))
        else:
            flat[kk] = v
    return flat

def _get_dumps(folder: str) -> list:
    dumps = []
    for name in os.listdir(folder):
        name_path = os.path.join(folder, name)
        if os.path.isfile(name_path) and name_path.endswith((".vmem",".raw", ".dmp", ".bin")):
            dumps.append(name_path)
        elif os.path.isdir(name_path):
            dir_dumps = _get_dumps(name_path)
            if len(dir_dumps):
                dumps += dir_dumps
        else:
            continue
    return dumps

def csv_to_json(csv_path: str, json_path: str) -> str:
    rows = []
    with open(csv_path, "r", newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    os.makedirs(os.path.dirname(os.path.abspath(json_path)), exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as out:
        json.dump(rows, out, ensure_ascii=False, indent=2)
    return json_path

def jsonl_to_json(jsonl_path: str, json_path: str) -> str:
    rows = []
    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    os.makedirs(os.path.dirname(os.path.abspath(json_path)), exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as out:
        json.dump(rows, out, ensure_ascii=False, indent=2)
    return json_path

def load_records_any(path: str):
    """
    Preview helper: load .json / .jsonl / .csv into list[dict].
    Extractors should still receive JSON arrays via the pipeline.
    """
    if not path or not os.path.exists(path):
        return []
    if path.endswith(".json"):
        return load_json_records(path)
    if path.endswith(".jsonl"):
        tmp = path + ".tmp.json"
        jsonl_to_json(path, tmp)
        try:
            with open(tmp, "r", encoding="utf-8") as f:
                return json.load(f)
        finally:
            try: os.remove(tmp)
            except Exception: pass
    if path.endswith(".csv"):
        out = []
        with open(path, "r", newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                out.append(row)
        return out
    return []


def to_builtin(obj):
    """Coerce numpy/pandas scalars into plain Python types."""
    try:
        import numpy as np
        if isinstance(obj, np.generic):
            return obj.item()
    except ImportError:
        pass
    return obj

def load_json_records(path: str):
    """Load JSON array or JSONL (auto-detect) into a list of dicts."""
    try:
        with open(path, "r", encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict) and "rows" in data:
                return data.get("rows") or []
            return data or []
    except FileNotFoundError:
        return []
    except Exception:
        return []

def cheap_image_hash(path: str) -> str:
    """Quick, cheap fingerprint: size + first/last 1MB sha256 slice."""
    try:
        st = os.stat(path)
        size = st.st_size
        h = hashlib.sha256()
        with open(path, "rb") as f:
            head = f.read(1024*1024)
            tail = b""
            if size > 2*1024*1024:
                f.seek(-1024*1024, os.SEEK_END)
                tail = f.read(1024*1024)
        h.update(str(size).encode())
        h.update(head)
        h.update(tail)
        return "quicksha256:" + h.hexdigest()
    except Exception:
        return "quicksha256:unknown"

def list_entropy(items):
    if not items:
        return 0.0
    cnt = Counter(items)
    total = sum(cnt.values())
    return -sum((c/total) * math.log2(c/total) for c in cnt.values())

def char_entropy(s: str) -> float:
    if not s:
        return 0.0
    cnt, n = Counter(s), len(s)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())

# def flatten_records(rows):
#     for r in rows:
#         yield r
#         for child in r.get("__children", []):
#             yield from flatten_records([child])

def is_non_ascii(name): 
    return any(ord(ch) > 127 for ch in name)

def shannon_entropy(obj):
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

# def not_system_path(p):
#     p = (p or "").lower()
#     return not p.startswith(("c:\\windows", "%systemroot%", "\\systemroot", "systemroot"))

    
def not_system_path(raw: str) -> bool:
    """
    Treat Program Files (both 64-bit and 32-bit) and their Common Files as system.
    Include ProgramW6432 to avoid WOW64 confusion.
    """

    def _expand_envs(s: str) -> str:
        def repl(m):
            var = m.group(1)
            return os.environ.get(var, m.group(0))
        s2 = re.sub(r"%([^%/\\]+)%", repl, s)
        return os.path.expandvars(s2)

    def _strip_device_prefix(s: str) -> str:
        if s.startswith("\\\\?\\") or s.startswith("\\\\??\\"):
            return s[4:]
        return s

    def _clean(s: str) -> str:
        s = s.strip().strip('"').strip("'")
        s = s.replace("/", "\\")
        s = _strip_device_prefix(s)
        return s
    
    def _first_pathlike_token(s: str) -> str:
        s = _clean(s)

        # 1) Try quoted path with extension
        m = re.search(r'"([A-Za-z]:\\[^"]+?\.(?:exe|dll|sys|cpl|bat|cmd|ps1|psm1|vbs|js|hta|msi|scr|com))"', s, re.I)
        if m:
            return _clean(m.group(1))

        # 2) Try unquoted drive path (ALLOW SPACES) up to extension
        m = re.search(r'([A-Za-z]:\\.+?\.(?:exe|dll|sys|cpl|bat|cmd|ps1|psm1|vbs|js|hta|msi|scr|com))\b', s, re.I)
        if m:
            return _clean(m.group(1))

        # 3) Try unquoted UNC path (ALLOW SPACES) up to extension
        m = re.search(r'(\\\\.+?\.(?:exe|dll|sys|cpl|bat|cmd|ps1|psm1|vbs|js|hta|msi|scr|com))\b', s, re.I)
        if m:
            return _clean(m.group(1))

        # 4) Fall back to previous conservative heuristic (rarely used now)
        for token in re.split(r"\s+", s, maxsplit=1):
            token = _clean(token)
            if not token:
                continue
            t0 = token.split(',', 1)[0]
            for cand in (token, t0):
                if (re.match(r"^[a-zA-Z]:\\", cand) or cand.startswith("\\\\") or
                    ("\\" in cand and re.search(r"\.(exe|dll|sys|cpl|bat|cmd|ps1|psm1|vbs|js|hta|msi|scr|com)$", cand, re.I))):
                    return cand

        return _clean(s)


    # def _first_pathlike_token(s: str) -> str:
    #     if s.count('"') >= 2:
    #         q1 = s.find('"'); q2 = s.find('"', q1 + 1)
    #         if q1 != -1 and q2 != -1:
    #             cand = _clean(s[q1+1:q2])
    #             if cand:
    #                 return cand
    #     for token in re.split(r"\s+", s, maxsplit=1):
    #         token = _clean(token)
    #         if not token:
    #             continue
    #         t0 = token.split(',', 1)[0]
    #         for cand in (token, t0):
    #             if (re.match(r"^[a-zA-Z]:\\", cand) or cand.startswith("\\\\") or
    #                 ("\\" in cand and re.search(r"\.(exe|dll|sys|cpl|bat|cmd|ps1|psm1|vbs|js|hta|msi|scr|com)$", cand, re.I))):
    #                 return cand
    #     return _clean(s)

    if not raw:
        return False

    s0 = _clean(str(raw))
    s1 = _expand_envs(s0)
    token = _first_pathlike_token(s1)
    if not token:
        return False

    token = _clean(token)
    tok_norm = ntpath.normpath(token).rstrip("\\")
    tok_lower = tok_norm.lower()

    # GUID-only "paths" like {GUID} => treat as system/benign here
    if re.fullmatch(r"\{[0-9a-fA-F\-]+\}", tok_lower):
        return False

    # UNC is non-system
    if tok_lower.startswith("\\\\"):
        return True

    m = re.match(r"^([a-z]:)\\", tok_lower)
    drive = (m.group(1) if m else "").lower()

    sysdrive = os.environ.get("SystemDrive", "c:").lower()
    windir   = _expand_envs(os.environ.get("WINDIR", os.environ.get("SystemRoot", sysdrive + "\\Windows")))
    windir   = ntpath.normpath(_clean(windir)).lower()

    # Program Files roots (cover WOW64):
    pf_env   = ntpath.normpath(_clean(_expand_envs(os.environ.get("ProgramFiles", sysdrive + "\\Program Files")))).lower()
    pf_w6432 = ntpath.normpath(_clean(_expand_envs(os.environ.get("ProgramW6432", sysdrive + "\\Program Files")))).lower()
    pfx86    = ntpath.normpath(_clean(_expand_envs(os.environ.get("ProgramFiles(x86)", sysdrive + "\\Program Files (x86)")))).lower()

    # Common Program Files roots:
    cpf_env   = ntpath.normpath(_clean(_expand_envs(os.environ.get("CommonProgramFiles", pf_env + "\\Common Files")))).lower()
    cpf_w6432 = ntpath.normpath(_clean(_expand_envs(os.environ.get("CommonProgramW6432", pf_w6432 + "\\Common Files")))).lower()
    cpf_x86   = ntpath.normpath(_clean(_expand_envs(os.environ.get("CommonProgramFiles(x86)", pfx86 + "\\Common Files")))).lower()

    pdata   = ntpath.normpath(_clean(_expand_envs(os.environ.get("ProgramData", sysdrive + "\\ProgramData")))).lower()

    # Canonical system subroots
    sys32   = ntpath.join(windir, "system32").lower()
    syswow  = ntpath.join(windir, "syswow64").lower()
    winsxs  = ntpath.join(windir, "winsxs").lower()
    # Build WindowsApps from 64-bit Program Files (store apps live there)
    winapps = ntpath.join(pf_w6432, "WindowsApps").lower()

    win_temp = ntpath.join(windir, "temp").lower()

    if drive and drive != sysdrive:
        return True

    trusted_prefixes = (
        sys32, syswow, winsxs, windir,
        pf_env, pf_w6432, pfx86,
        cpf_env, cpf_w6432, cpf_x86,
        pdata, winapps
    )

    if tok_lower.startswith(win_temp + "\\") or tok_lower == win_temp:
        return True

    if any(tok_lower.startswith(tp + "\\") or tok_lower == tp for tp in trusted_prefixes):
        return False

    return True


# def not_system_path(raw: str) -> bool:
#     """
#     - Expands %WINDIR% / %SystemRoot% (and other %VAR% envs) before checks.
#     - Tolerates command-line strings (extracts the first plausible path token).
#     - Normalizes quotes, slashes, and device prefixes (\\?\, \\??\).
#     - Considers Windows\\Temp as NON-system (exception under %WINDIR%).
#     - UNC paths (\\server\share\...) are treated as NON-system.
#     """

#     def _expand_envs(s: str) -> str:
#         # Expand %VAR% even on non-Windows Python builds
#         def repl(m):
#             var = m.group(1)
#             return os.environ.get(var, m.group(0))
#         s2 = re.sub(r"%([^%/\\]+)%", repl, s)  # expand %VAR%
#         return os.path.expandvars(s2)  # also expands $VAR if present

#     def _strip_device_prefix(s: str) -> str:
#         # Remove NT device prefixes like \\?\ or \\??\
#         if s.startswith("\\\\?\\") or s.startswith("\\\\??\\"):
#             return s[4:]
#         return s

#     def _clean(s: str) -> str:
#         s = s.strip().strip('"').strip("'")
#         s = s.replace("/", "\\")
#         s = _strip_device_prefix(s)
#         return s

#     def _first_pathlike_token(s: str) -> str:
#         # Prefer quoted segment if present
#         if s.count('"') >= 2:
#             q1 = s.find('"')
#             q2 = s.find('"', q1 + 1)
#             if q1 != -1 and q2 != -1:
#                 cand = _clean(s[q1+1:q2])
#                 if cand:
#                     return cand
#         # Otherwise, take the first whitespace-delimited token
#         # and also try comma-splits (e.g., rundll32 foo.dll,Entry)
#         for token in re.split(r"\s+", s, maxsplit=1):
#             token = _clean(token)
#             if not token:
#                 continue
#             # If token still contains ',', also try the part before comma
#             t0 = token.split(',', 1)[0]
#             for cand in (token, t0):
#                 # Heuristics: has a backslash and an extension or drive/UNC
#                 if (re.match(r"^[a-zA-Z]:\\", cand) or cand.startswith("\\\\") or
#                     ("\\" in cand and re.search(r"\.(exe|dll|sys|cpl|bat|cmd|ps1|psm1|vbs|js|hta|msi|scr|com)$", cand, re.I))):
#                     return cand
#         # Fallback: return the whole cleaned string
#         return _clean(s)

#     if not raw:
#         # Be conservative: if we can't tell, do NOT flag as non-system
#         return False

#     s0 = _clean(str(raw))
#     s1 = _expand_envs(s0)
#     token = _first_pathlike_token(s1)
#     if not token:
#         return False

#     token = _clean(token)
#     # Normalize case for comparisons (Windows is case-insensitive)
#     tok_norm = ntpath.normpath(token).rstrip("\\")
#     tok_lower = tok_norm.lower()

#     # GUID-only (COM handler) "paths" like {GUID} => treat as system/benign here
#     if re.fullmatch(r"\{[0-9a-fA-F\-]+\}", tok_lower):
#         return False

#     # UNC paths are non-system (network locations)
#     if tok_lower.startswith("\\\\"):
#         return True

#     # Drive letter?
#     m = re.match(r"^([a-z]:)\\", tok_lower)
#     drive = (m.group(1) if m else "").lower()

#     # Resolve important roots with safe defaults if envs are missing
#     sysdrive = os.environ.get("SystemDrive", "c:").lower()
#     windir   = _expand_envs(os.environ.get("WINDIR", os.environ.get("SystemRoot", sysdrive + "\\Windows")))
#     windir   = ntpath.normpath(_clean(windir)).lower()

#     pf      = ntpath.normpath(_clean(_expand_envs(os.environ.get("ProgramFiles", sysdrive + "\\Program Files")))).lower()
#     pfx86   = ntpath.normpath(_clean(_expand_envs(os.environ.get("ProgramFiles(x86)", sysdrive + "\\Program Files (x86)")))).lower()
#     pdata   = ntpath.normpath(_clean(_expand_envs(os.environ.get("ProgramData", sysdrive + "\\ProgramData")))).lower()

#     # Canonical system subroots
#     sys32   = ntpath.join(windir, "system32").lower()
#     syswow  = ntpath.join(windir, "syswow64").lower()
#     winsxs  = ntpath.join(windir, "winsxs").lower()
#     winapps = ntpath.join(pf, "WindowsApps").lower()

#     # Exception: Windows\Temp should be treated as NON-system (world-writable)
#     win_temp = ntpath.join(windir, "temp").lower()

#     # If it's on a *different* drive than SystemDrive, treat as non-system
#     if drive and drive != sysdrive:
#         return True

#     # Trusted system prefixes (anything under these is considered system)
#     trusted_prefixes = (
#         sys32, syswow, winsxs, windir, pf, pfx86, pdata, winapps
#     )

#     # If it's inside Windows\Temp => NON-system
#     if tok_lower.startswith(win_temp + "\\") or tok_lower == win_temp:
#         return True

#     # If it's under any trusted prefix => system (i.e., NOT non-system)
#     if any(tok_lower.startswith(tp + "\\") or tok_lower == tp for tp in trusted_prefixes):
#         return False

#     # Otherwise, not in system roots => NON-system
#     return True


def canonical_path_key(raw: str) -> str:
    """Produce a stable, lowercase, normpath key from a possibly messy path/command."""
    if not raw:
        return ""
    s = str(raw).strip().strip('"').strip("'").replace("/", "\\")
    # expand %ENV% and $VAR
    def repl(m): return os.environ.get(m.group(1), m.group(0))
    s = re.sub(r"%([^%/\\]+)%", repl, s)
    s = os.path.expandvars(s)
    # strip \\?\ or \\??\
    if s.startswith("\\\\?\\") or s.startswith("\\\\??\\"):
        s = s[4:]

    if s.count('"') >= 2:
        i = s.find('"'); j = s.find('"', i+1)
        if j > i:
            s = s[i+1:j]

    tok = s.split(None, 1)[0].split(",", 1)[0]
    if not tok:
        tok = s
    return ntpath.normpath(tok).rstrip("\\").lower()



def is_suspicious_path(path: str) -> bool:
    """
    Check if the path is suspicious. A path is suspicious if it is user-writable 
    and doesn't belong to legitimate system or common application directories.
    """
    path_l = path.replace("/", "\\").lower()
     
    user_dir_regex = r"c:\\users\\[^\\]+\\"
    user_paths = [
        "c:\\users\\",  # All user directories
        "c:\\users\\public\\",  # Public user directory
        "c:\\users\\appdata\\local\\programs\\",  # Common app installation paths
        "c:\\users\\appdata\\local\\microsoft\\",]  # Microsoft user app locations

    if not not_system_path(path):
        return False
    
    if any(re.match(user_dir_regex, path_l) and path_l[len(user_dir_regex):].startswith(subdir.lower()) for subdir in user_paths):
        return False  
    
    else:
        suspicious_paths = ["\\temp\\", "\\public\\", "\\downloads\\", "\\appdata\\", "\\workspace\\", "\\desktop\\"]
        return any(s in path_l for s in suspicious_paths)


def get_depth(children):
    for child in children:
        depth = 1
        if len(child['__children']) != 0:
            return get_depth(child['__children']) + depth
        else:
            return depth
    return 0

# def _to_plain_dict(obj):
#     if is_dataclass(obj):
#         return asdict(obj)
#     if isinstance(obj, Mapping):
#         return dict(obj)
#     return getattr(obj, "__dict__", {"value": obj})

# def _norm_scalar(v):
#     if v is None:
#         return ""
#     if isinstance(v, (str, int, float, bool)):
#         return v
#     iso = getattr(v, "isoformat", None)
#     if callable(iso):
#         try:
#             return iso()
#         except Exception:
#             pass
#     try:
#         return json.loads(json.dumps(v, default=str))
#     except Exception:
#         return str(v)

def _flatten_mapping(m: Mapping, parent_key: str = "") -> dict:
    out = {}
    for k, v in m.items():
        key = f"{parent_key}.{k}" if parent_key else k
        if isinstance(v, Mapping):
            out.update(_flatten_mapping(v, key))
        elif isinstance(v, list):
            # keep lists as JSON strings (generic + safe for CSV)
            out[key] = json.dumps(v, ensure_ascii=False, default=str)
        else:
            out[key] = v
    return out

# def write_mapping_to_csv(
#     feature_map: Mapping, 
#     csv_path: str, 
#     key_label: str = "key",
#     auto_strip_single_nested_prefix: bool = True,
#     strip_prefixes: tuple[str, ...] = ()
# ) -> None:
#     """
#     feature_map: { <row_key>: <row_obj>, ... } where <row_obj> can be a dataclass or mapping.
#     Produces a single CSV with:
#       - first column = key_label (the mapping key)
#       - then all top-level scalar columns (union by first appearance)
#       - then all nested (flattened) columns (union by first appearance)
#     No hardcoded field names. If exactly one top-level nested-dict column exists across all rows,
#     its prefix is stripped automatically (unless disabled).
#     You can also explicitly list prefixes to strip via strip_prefixes.
#     """
#     rows_norm = []             #
#     global_nested_topkeys = [] 
#     seen_nested_topkeys = set()
#     top_scalar_keys = []
#     seen_top_scalar = set()

#     for row_key, row_obj in feature_map.items():
#         rowd = _to_plain_dict(row_obj)
#         scalars = {}
#         blocks  = {}
#         for k, v in rowd.items():
#             if isinstance(v, Mapping):
#                 blocks[k] = dict(v)
#                 if k not in seen_nested_topkeys:
#                     global_nested_topkeys.append(k)
#                     seen_nested_topkeys.add(k)
#             else:
#                 scalars[k] = v
#                 if k not in seen_top_scalar:
#                     top_scalar_keys.append(k)
#                     seen_top_scalar.add(k)
#         rows_norm.append((row_key, scalars, blocks))

#     # Decide which prefixes to strip
#     prefixes_to_strip = set(strip_prefixes)
#     if auto_strip_single_nested_prefix and len(global_nested_topkeys) == 1:
#         prefixes_to_strip.add(global_nested_topkeys[0])

#     # -------- Second pass: flatten + build header (preserve first appearance) --------
#     nested_flat_keys = []
#     seen_nested_flat = set()

#     flat_rows = []
#     for row_key, scalars, blocks in rows_norm:
#         flat = {}
#         for k, v in scalars.items():
#             flat[k] = _norm_scalar(v)
#         for topk, submap in blocks.items():
#             prefix = "" if topk in prefixes_to_strip else topk
#             block_flat = _flatten_mapping(submap, prefix)
#             for k, v in block_flat.items():
#                 flat[k] = _norm_scalar(v)
#                 if k not in seen_nested_flat and k not in top_scalar_keys:
#                     nested_flat_keys.append(k)
#                     seen_nested_flat.add(k)
#         flat_rows.append((row_key, flat))

#     fieldnames = [key_label] + top_scalar_keys + nested_flat_keys

#     # -------- Write CSV --------
#     with open(csv_path, "w", newline="", encoding="utf-8") as f:
#         w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
#         w.writeheader()
#         for row_key, flat in flat_rows:
#             out = {key_label: row_key}
#             # Fill missing with ""
#             for k in top_scalar_keys:
#                 out[k] = _norm_scalar(flat.get(k))
#             for k in nested_flat_keys:
#                 out[k] = _norm_scalar(flat.get(k))
#             w.writerow(out)



def write_csv(filename: str, row: dict) -> None:
    row = _flatten_mapping(row)
    fieldnames = list(row.keys())
    with open(filename, mode="a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(row)


# def write_mapping_to_csv(rows: list[dict], csv_path: str, *, key_priority: list[str] | None = None) -> str:
#     """
#     Write a list of row dicts to a single CSV file at `csv_path`.

#     - Each `row` may contain a nested `features` dict; we FLATTEN that dict
#       into the top-level columns (feature keys become column names).
#     - Non-feature nested structures are left as JSON strings to preserve data
#       without exploding the schema.
#     - Header = identity/context keys (priority first) + sorted remaining keys.

#     Returns the absolute csv path written.
#     """
#     import json

#     os.makedirs(os.path.dirname(os.path.abspath(csv_path)) or ".", exist_ok=True)

#     if key_priority is None:
#         key_priority = [
#             "image_name", "image_path", "profile", "os", "arch",
#             "layer", "renderer", "timestamp", "hash",
#         ]

#     def _is_scalar(x) -> bool:
#         return isinstance(x, (str, int, float, bool)) or x is None

#     norm_rows: list[dict] = []
#     all_keys: set[str] = set()
#     for r in rows:
#         # Detach and flatten features
#         feats = r.get("features") or {}
#         if not isinstance(feats, dict):
#             feats = {}

#         flat_feats = _flatten_dict(feats)  
#         base = {}
#         for k, v in r.items():
#             if k == "features":
#                 continue
#             base[k] = v if _is_scalar(v) else json.dumps(v, ensure_ascii=False)

#         merged = {**base, **flat_feats}
#         norm_rows.append(merged)
#         all_keys.update(merged.keys())

#     # 2) Build header with stable, readable order
#     priority = [k for k in key_priority if k in all_keys]
#     remaining = sorted(k for k in all_keys if k not in priority)
#     header = priority + remaining

#     # 3) Write CSV
#     with open(csv_path, "w", newline="", encoding="utf-8") as f:
#         writer = csv.DictWriter(f, fieldnames=header, extrasaction="ignore")
#         writer.writeheader()
#         for row in norm_rows:
#             # Ensure every header exists; missing → ""
#             writer.writerow({k: row.get(k, "") for k in header})

#     return os.path.abspath(csv_path)


def write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

