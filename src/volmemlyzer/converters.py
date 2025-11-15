from __future__ import annotations
import json, csv, warnings
from typing import Callable, Optional

SUPPORTED_FORMATS = {"json", "jsonl", "csv"}

def _emit_conversion_warning(src_fmt: str, dst_fmt: str, reason: str = "") -> None:
    msg = (
        f"NOTE: Converting from {src_fmt.upper()} to {dst_fmt.upper()}. "
        "This output was produced by converting from another cached format. "
        "Minor inconsistencies with native tool output (e.g., column order/names) may occur. "
        "If you need the exact layout the tool produces, run it with --no-cache."
    )
    if reason:
        msg += f" ({reason})"
    warnings.warn(msg, UserWarning)

def _rows_from_json(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "rows" in data:
        return data["rows"]
    if isinstance(data, dict):
        return [data]
    return []

def _is_list_of_dicts(value) -> bool:
    return isinstance(value, list) and any(isinstance(x, dict) for x in value)

def _child_keys(node: dict) -> list[str]:
    keys = []
    for k, v in node.items():
        if _is_list_of_dicts(v):
            keys.append(k)
    return keys

def _flatten_mapping(m, parent_key=""):
    out = {}
    for k, v in (m or {}).items():
        if _is_list_of_dicts(v):
            continue
        key = f"{parent_key}.{k}" if parent_key else k
        if isinstance(v, dict):
            out.update(_flatten_mapping(v, key))
        elif isinstance(v, list):
            out[key] = json.dumps(v, ensure_ascii=False)
        else:
            out[key] = v
    return out

def _flatten_hierarchy_generic(rows):
    flat = []
    def walk(node, depth=0):
        if not isinstance(node, dict):
            return
        ckeys = _child_keys(node)
        parent_payload = {k: v for k, v in node.items() if k not in ckeys}
        parent_flat = _flatten_mapping(parent_payload)
        parent_flat["depth"] = depth
        flat.append(parent_flat)
        for ck in ckeys:
            children = node.get(ck) or []
            for ch in children:
                if isinstance(ch, dict):
                    walk(ch, depth+1)
    for r in rows:
        walk(r, 0)
    return flat

def _maybe_flatten_rows(rows):
    has_hierarchy = any(
        isinstance(r, dict) and any(_is_list_of_dicts(v) for v in r.values())
        for r in rows
    )
    if has_hierarchy:
        return _flatten_hierarchy_generic(rows), True
    norm = []
    for r in rows:
        if isinstance(r, dict):
            norm.append(_flatten_mapping(r))
    return norm, False

def _build_fieldnames(rows, force_depth_first: bool) -> list[str]:
    fieldnames = []
    if force_depth_first:
        fieldnames.append("depth")
    for r in rows:
        for k in r.keys():
            if force_depth_first and k == "depth":
                continue
            if k not in fieldnames:
                fieldnames.append(k)
    return fieldnames

def _json_to_jsonl(json_path: str, jsonl_path: str) -> str:
    _emit_conversion_warning("json", "jsonl")
    with open(json_path, "r", encoding="utf-8") as f, open(jsonl_path, "w", encoding="utf-8") as out:
        data = json.load(f)
        rows = _rows_from_json(data)
        rows, flattened = _maybe_flatten_rows(rows)
        for row in rows:
            if flattened and "depth" not in row:
                row = {"depth": 0, **row}
            out.write(json.dumps(row, ensure_ascii=False) + "\\n")
    return jsonl_path

def _json_to_csv(json_path: str, csv_path: str) -> str:
    _emit_conversion_warning("json", "csv")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    rows = _rows_from_json(data)
    rows, flattened = _maybe_flatten_rows(rows)
    fieldnames = _build_fieldnames(rows, force_depth_first=flattened)

    with open(csv_path, "w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            if flattened and "depth" not in r:
                r = {"depth": 0, **r}
            clean = {k: ("" if r.get(k) is None else r.get(k)) for k in fieldnames}
            w.writerow(clean)
    return csv_path

def _jsonl_to_json(jsonl_path: str, json_path: str) -> str:
    _emit_conversion_warning("jsonl", "json")
    rows = []
    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                rows.append(json.loads(s))
            except json.JSONDecodeError:
                continue
    with open(json_path, "w", encoding="utf-8") as out:
        json.dump(rows, out, ensure_ascii=False, indent=2)
    return json_path

def _jsonl_to_csv(jsonl_path: str, csv_path: str) -> str:
    _emit_conversion_warning("jsonl", "csv")
    rows = []
    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                rows.append(json.loads(s))
            except json.JSONDecodeError:
                continue
    rows, flattened = _maybe_flatten_rows(rows)
    fieldnames = _build_fieldnames(rows, force_depth_first=flattened)

    with open(csv_path, "w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            if flattened and "depth" not in r:
                r = {"depth": 0, **r}
            clean = {k: ("" if r.get(k) is None else r.get(k)) for k in fieldnames}
            w.writerow(clean)
    return csv_path

def _csv_to_json(csv_path: str, json_path: str) -> str:
    _emit_conversion_warning("csv", "json")
    rows = []
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(row)
    with open(json_path, "w", encoding="utf-8") as out:
        json.dump(rows, out, ensure_ascii=False, indent=2)
    return json_path

def _csv_to_jsonl(csv_path: str, jsonl_path: str) -> str:
    _emit_conversion_warning("csv", "jsonl")
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f, open(jsonl_path, "w", encoding="utf-8") as out:
        r = csv.DictReader(f)
        for row in r:
            out.write(json.dumps(row, ensure_ascii=False) + "\\n")
    return jsonl_path

_CONVERTERS: dict[tuple[str,str], Callable[[str,str], str]] = {
    ("json", "jsonl"): _json_to_jsonl,
    ("json", "csv"): _json_to_csv,
    ("jsonl", "json"): _jsonl_to_json,
    ("jsonl", "csv"): _jsonl_to_csv,
    ("csv", "json"): _csv_to_json,
    ("csv", "jsonl"): _csv_to_jsonl,
}

def pick_conversion(src_format: str, dst_format: str) -> tuple[str, Optional[str]]:
    s = src_format.lower()
    d = dst_format.lower()
    if s == d:
        return ("noop", None)
    fn = _CONVERTERS.get((s, d))
    if fn:
        return ("convert", f"{s}->{d}")
    return ("run", None)

def convert_artifact(src_path: str, src_format: str, dst_path: str, dst_format: str):
    decision, conv_name = pick_conversion(src_format, dst_format)
    if decision == "noop":
        return ("noop", src_path, None)
    if decision == "run":
        return ("run", None, None)
    fn = _CONVERTERS[(src_format.lower(), dst_format.lower())]
    out = fn(src_path, dst_path)
    return ("convert", out, conv_name)
