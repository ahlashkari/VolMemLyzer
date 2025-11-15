# # === PATCH 1/4: analysis.py (drop-in replacement for OverviewAnalysis) ===
# # Each workflow step is a distinct method. Steps do not auto-run the others;
# # you can call any subset in any order. The terminal output is wide, clean,
# # and academically phrased.

from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple, Iterable
import ipaddress, os, copy, re
from .extractors import extract_winInfo_features
from .utilities import load_records_any, not_system_path, cheap_image_hash, canonical_path_key
from .utilities import char_entropy, is_non_ascii, is_suspicious_path, write_json
from .pipeline import Pipeline
from .terminalUI import TerminalUI
TerminalUI.RICH_BOX = "SIMPLE"     
TerminalUI.RICH_SHOW_LINES = True   
TerminalUI.RICH_SHOW_EDGE = True    

class OverviewAnalysis:
    """Sequential memory-forensics workflow with step-by-step functions.
    Steps (match your Workflow.docx numbering):
      0) Hygiene & Bearings (windows.info)
      1) Process Census (pslist/pstree/psscan/psxview) + anomaly scoring
      2) Memory Injections (malfind)
      3) Networking (netscan deep)
      4) Persistence & User Activity (hives, run keys, tasks, userassist)
    """
    # Plugin-specific surfacing BASELINE_SCORES
    BASELINE_SCORES = {'scheduled_tasks': 3, 'userassist': 2, 'netscan': 4, 'malfind' : 4, "process" : 4}

    def run_steps(
        self,
        *,
        pipe: Pipeline,
        image_path: str,
        artifacts_dir: Optional[str] = None,
        steps: Optional[Iterable[int]] = None,
        use_cache: bool = True,
        high_level: bool = False,
        json: str = None
    ) -> Dict[str, Any]:
        TerminalUI.banner("FORENSIC OVERVIEW – STEPWISE")
        artifacts_dir = artifacts_dir or pipe._default_artifacts_dir(image_path)
        results: Dict[str, Any] = {"image": os.path.basename(image_path),
                                   "quick_hash": cheap_image_hash(image_path)}
        executed = []
        for s in (list(steps) if steps is not None else [0,1,2,3,4]):
            if s == 0:
                results["step0"] = self.step0_bearings(pipe, image_path, artifacts_dir, use_cache)
                executed.append(0)
            elif s == 1:
                results["step1"] = self.step1_processes(pipe, image_path, artifacts_dir, use_cache, high_level)
                executed.append(1)
            elif s == 2:
                results["step2"] = self.step2_injections(pipe, image_path, artifacts_dir, use_cache, high_level)
                executed.append(2)
            elif s == 3:
                results["step3"] = self.step3_network(pipe, image_path, artifacts_dir, use_cache, high_level)
                executed.append(3)
            elif s == 4:
                results["step4"] = self.step4_persistence(pipe, image_path, artifacts_dir, use_cache, high_level)
                executed.append(4)            
        results["executed_steps"] = executed
        return results

    # ---------------- Step 0 ----------------
    def step0_bearings(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool) -> Dict[str, Any]:
        TerminalUI.section("Step 0 · Hygiene & bearings")
        info_path = self._ensure_one(pipe, image_path, artifacts_dir, "info", use_cache)
        with open(info_path, 'r', encoding='utf-8') as f:
            _, res = extract_winInfo_features(f)

        win = f"Windows {res.get('info.NtMajorVersion')} version {res.get('info.winBuild')}"
        arch = "64-bit" if res.get("info.Is64") else "32-bit"

        TerminalUI.kv([
            ("Kernel Base Address", res.get("info.KernelBase")),
            ("Build", win),
            ("Architecture", arch),
            ("SystemTime", res.get("info.SystemTime")),
        ])
        return {"ok": True}

    # ---------------- Step 1 ----------------
    def step1_processes(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool, high_level: bool) -> Dict[str, Any]:
        TerminalUI.section("Step 1 · Process census (pslist/pstree/psscan/psxview)")

        enabled = ["pslist", "pstree", "psscan", "psxview"]
        action_result = pipe.run_plugin_raw(image_path=image_path, enable=enabled, use_cache=use_cache, renderer="json", outdir=artifacts_dir, strict= True)
        out_path = action_result.artifacts.get("plugins")
       
        pslist  = load_records_any(out_path.get("pslist"))
        pstree  = load_records_any(out_path.get("pstree"))
        psscan  = load_records_any(out_path.get("psscan"))
        psxview = load_records_any(out_path.get("psxview"))
    
        census = self._build_census(pslist, pstree)
        flags, susp = self._score_processes(census, psscan, psxview)

        TerminalUI.kv([
            ("pslist processes", flags.get("pslist_count")),
            ("psscan processes", flags.get("psscan_count")),
            ("psscan-only (hidden/terminated)", flags.get("hidden_count")),
            ("orphans (ppid missing)", flags.get("orphans")),
            ("psxview inconsistencies", flags.get("psxview_inconsistent")),
        ])
        rows = [[str(pid), name or "", str(ppid or ""), str(score), flags, rationale] 
                    for pid, name, ppid, score, flags, rationale in susp]
        
        if high_level:
            rows = [v for v in rows if (v[3] == 'High' or v[3] == 'Critical')]

        shown = TerminalUI.table(["PID","Name","PPID","Risk","Flags","Rationale"], rows, max_rows=25)
        return {"summary": flags, "suspicious": [
            {"pid": int(r[0]), "name": r[1], "ppid": (int(r[2]) if r[2] else None),
             "Risk": str(r[3]), "flags": r[4], "rationale": r[5]} for r in rows[:len(shown)]
        ]}

    # ---------------- Step 2 ----------------
    def step2_injections(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool, high_level: bool = False) -> Dict[str, Any]:
        TerminalUI.section("Step 2 · Memory injections (malfind)")

        if not pipe.registry.has("malfind"):
            TerminalUI.note("malfind not registered; skipping")
            return {"ok": False}
        mal_path = self._ensure_one(pipe, image_path, artifacts_dir, "malfind", use_cache)
        rows = load_records_any(mal_path)

        suspicious_regions = {}
        for row in rows:
            score, flags, rationale = self._score_injections(row)

            if score > self.BASELINE_SCORES.get('malfind', 4): 
                start_vpn = row.get("Start VPN")
                if start_vpn not in suspicious_regions:
                    suspicious_regions[start_vpn] = {
                        "process": row.get("Process"),
                        "pid": row.get("PID"),
                        "vad_tag": row.get("Tag", ""),
                        "notes": row.get("Notes", ""),
                        "commit_charge": row.get("CommitCharge"),
                        "protection": row.get("Protection"),
                        "disasm": row.get("Disasm"),
                        "hex_dump": row.get("Hexdump"),
                        "score": score,
                        "flags": flags,
                        "rationale": rationale
                    }
                else:
                    suspicious_regions[start_vpn]["score"] += score
                    suspicious_regions[start_vpn]["flags"] += ", " + flags
                    suspicious_regions[start_vpn]["rationale"] += " | " + rationale

        rows_to_display = [
            [
                str(pid),
                row["process"],
                str(row["commit_charge"]),
                str(row["pid"]),
                str(row["vad_tag"]),
                str(row["notes"]),
                int(row["score"]),
                row["rationale"]
            ]
            for pid, row in suspicious_regions.items()
        ]
        
        # rows_to_display[]
        rows_to_display.sort(key=lambda r: (-r[-2], r[0]))
        rows_to_display = [self._score_map(row, -2) for row in rows_to_display]

        if high_level:
            rows_to_display = [v for v in rows_to_display if (v[-2] == 'High' or v[-2] == 'Critical')]

        TerminalUI.table(["PID", "Process", "CommitCharge", "Start VPN", "Vad Tag" , "Notes" ,"Risk", "Rationale"], rows_to_display, max_rows=25)
        return {"suspicious_injections": list(suspicious_regions.values())}

    # ---------------- Step 3 · Networking (netscan deep, DFIR-backed) ----------------


    def step3_network(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool, high_level: bool) -> Dict[str, Any]:
        TerminalUI.section("Step 3 · Networking (netscan deep, DFIR-backed)")

        if not pipe.registry.has("netscan"):
            TerminalUI.note("netscan not registered; skipping deep view")
            return {"ok": False}

        net_path = self._ensure_one(pipe, image_path, artifacts_dir, "netscan", use_cache)
        rows = load_records_any(net_path) or []

        # ---------- light aggregations for context ----------
        per_pid = {}
        per_remote_pub = {}
        for r in rows:
            pid = str(r.get("PID") or "")
            state = str(r.get("State") or "").upper()
            fa = str(r.get("ForeignAddr") or "")
            fip = fa.split(":")[0].strip() if fa else ""
            if pid:
                per_pid[pid] = per_pid.get(pid, 0) + 1
            if state in {"ESTABLISHED", "SYN_SENT"} and fip and fip not in {"*", "0.0.0.0", "::"} and not self._is_private_ip(fip):
                per_remote_pub[fip] = per_remote_pub.get(fip, 0) + 1

        # ---------- score unique sockets ----------
        skip_states = {"CLOSED", "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK"}
        seen = set()
        suspicious: List[Dict[str, Any]] = []

        for row in rows:
            proto = str(row.get("Proto") or "")
            state = str(row.get("State") or "").upper()
            la = str(row.get("LocalAddr") or "")
            lp = str(row.get("LocalPort") or "")
            fa = str(row.get("ForeignAddr") or "")
            fp = str(row.get("ForeignPort") or "")
            owner = str(row.get("Owner") or "")
            pid = row.get("PID")

            # normalize int/str ports
            try: lp_i = int(lp)
            except: lp_i = 0
            try: fp_i = int(fp)
            except: fp_i = 0

            key = (la, lp_i, fa, fp_i, proto, state)
            if state in skip_states or key in seen:
                continue
            seen.add(key)

            row["_pid_conn_count"] = per_pid.get(str(pid or ""), 0)
            fip = fa.split(":")[0].strip() if fa else ""
            row["_same_remote_count"] = per_remote_pub.get(fip, 0)

            score, flags, rationale = self._score_network_connections(row, self._is_private_ip, self._is_loopback)
            threshold = getattr(self, "BASELINE_SCORES", {}).get("netscan", 12)
            if score >= threshold:
                suspicious.append({
                    "local_address": la,
                    "foreign_address": fa,
                    "local_port": lp_i,
                    "foreign_port": fp_i,
                    "proto": proto,
                    "state": state,
                    "owner": owner or None,
                    "pid": pid,
                    "score": int(score),
                    "flags": flags,
                    "rationale": rationale,
                })

        # ---------- render ----------
        suspicious.sort(key=lambda s: (-int(s.get("score", 0)),
                                    str(s.get("foreign_address") or ""),
                                    str(s.get("local_address") or "")))

        rows_to_display = []
        for s in suspicious:
            risk_score = int(s["score"])
            risk_label = "High" if risk_score >= 18 else "Medium" if risk_score >= 12 else "Low"
            indicator = self._indicator_from_flags(s.get("flags", []))
            rows_to_display.append([
                s.get("local_address"),
                s.get("foreign_address"),
                str(s.get("local_port")),
                str(s.get("foreign_port")),
                s.get("proto"),
                str(s.get("pid") or "—"),      
                s.get("state"),
                risk_label,
                indicator,                      
                s.get("rationale"),
            ])

        # emphasize only strong signals in high_level mode
        if high_level:
            rows_to_display = [r for r in rows_to_display if (r[7] == "High" or r[7] == "Critical")]

        TerminalUI.table(
            ["Local Address", "Foreign Address", "Local Port", "Foreign Port",
            "Proto", "PID", "State", "Risk", "Indicator", "Rationale"],
            rows_to_display, max_rows=30)
        
        return {
            "ok": True,
            "suspicious_connections": suspicious,
            "counts": {"total_rows": len(rows), "unique_scored": len(suspicious)}
        }



    def step4_persistence(self, pipe: Pipeline, image_path: str, artifacts_dir: str, use_cache: bool, high_level: bool) -> Dict[str, Any]:
        TerminalUI.section("Step 4 · Persistence & user activity (registry & tasks)")
        out: Dict[str, Any] = {}
        #Collecting *best* IoC per canonical key here to avoid duplicates.
        best: dict[str, dict] = {}

        def add_or_update(key: str, *, itype: str, indicator: str, score: int, rationale: list[str],
                        source: str, tiebreak: tuple = (0, 0)) -> None:
            """Keep the highest-score row per key; tie-break by (Count, Focus) for UA."""
            row = {
                "type": itype,
                "indicator": indicator,
                "score": int(score),
                "risk": self._risk_from_score(score),
                "why": " | ".join([w for w in rationale if w]),
                "source": source,
                "_tb": tiebreak,  # tiebreak tuple kept internal
            }
            prev = best.get(key)
            if not prev:
                best[key] = row
                return
            if row["score"] > prev["score"]:
                best[key] = row
                return
            if row["score"] == prev["score"] and row["_tb"] > prev.get("_tb", (0, 0)):
                best[key] = row

        # --- Hives: list vs scan → orphan offsets become IoCs (rare, but keep them)
        hl = hs = []
        if pipe.registry.has("registry.hivelist"):
            hl = load_records_any(self._ensure_one(pipe, image_path, artifacts_dir, "registry.hivelist", use_cache))
            out["hivelist"] = len(hl)
        if pipe.registry.has("registry.hivescan"):
            hs = load_records_any(self._ensure_one(pipe, image_path, artifacts_dir, "registry.hivescan", use_cache))
            out["hivescan"] = len(hs)

        if hl or hs:
            set_list = {int(x.get("Offset")) for x in hl if "Offset" in x}
            set_scan = {int(x.get("Offset")) for x in hs if "Offset" in x}
            missing = sorted(set_scan - set_list)
            out["orphaned"] = len(missing)
            for off in missing:
                add_or_update(
                    key=f"hive:{off}",
                    itype="registry.hive_orphan",
                    indicator=f"Offset {off}",
                    score=7,
                    rationale=["Hive page present in scan but absent from hivelist"],
                    source="registry.hivescan",
                )

        # --- Scheduled tasks (uses not_system_path in scorer; dedupe by name or action+args)
        if pipe.registry.has("scheduled_tasks"):
            tasks = load_records_any(self._ensure_one(pipe, image_path, artifacts_dir, "scheduled_tasks", use_cache))
            out["tasks"] = len(tasks)
            flagged = 0

            for t in tasks:
                s, why = self._score_scheduled_task(t)
                if s >= self.BASELINE_SCORES.get('scheduled_tasks', 8):
                    flagged += 1
                    name = str(t.get("Task Name") or "")
                    act  = str(t.get("Action") or "")
                    args = str(t.get("Action Arguments") or "")

                    # Primary key = stable task name; fallback = canonical path of action+args
                    task_name_key = name.strip().lower()
                    if task_name_key:
                        key = f"task:{task_name_key}"
                    else:
                        key = f"task:{canonical_path_key(f'{act} {args}') or (act.strip().lower() or 'unknown')}"

                    add_or_update(
                        key=key,
                        itype="scheduled_task",
                        indicator=f"{name} :: {act} {args}".strip(),
                        score=s,
                        rationale=why,
                        source="scheduled_tasks",
                    )

            TerminalUI.kv([("scheduled tasks", len(tasks)), ("suspicious tasks", flagged)])

        # --- UserAssist (executions) — dedupe by canonical path; tie-break by (Count, Focus)
        if pipe.registry.has("registry.userassist"):
            ua_tree = load_records_any(self._ensure_one(pipe, image_path, artifacts_dir, "registry.userassist", use_cache))
            ua_all  = list(self._flatten_UA_with_context(ua_tree))
            ua_vals = [r for r in ua_all if r.get("Type") == "Value"]  # actual entries

            out["userassist"] = len(ua_vals)
            flagged = 0

            for r in ua_vals:
                name = str(r.get("Name") or "")
                # Skip classic UEME noise unless it looks path-like
                if name.startswith("UEME_") and not self._seems_pathlike(name):
                    continue

                cnt  = int(r.get("Count") or 0)
                fcnt = int(r.get("Focus") or r.get("Focus Count") or 0)

                s, why = self._score_userassist_name(name)
                # small usage boost (bounded)
                if cnt or fcnt:
                    s += min(3, cnt // 5)
                    if cnt:  why.append(f"Count={cnt}")
                    if fcnt: why.append(f"Focus={fcnt}")

                if s >= self.BASELINE_SCORES.get('userassist', 6) and self._seems_pathlike(name):
                    flagged += 1
                    key = f"ua:{canonical_path_key(name) or name.strip().lower()}"
                    add_or_update(
                        key=key,
                        itype="userassist.exec",
                        indicator=name,
                        score=s,
                        rationale=why,
                        source="registry.userassist",
                        tiebreak=(cnt, fcnt),
                    )
            TerminalUI.kv([("userassist values", len(ua_vals)), ("suspicious user executions", flagged)])

        # --- Present & return (single combined table, deduped)
        iocs_sorted = sorted(best.values(), key=lambda d: (-d["score"], d["type"], d["indicator"]))
        rows = [[d["type"], d["indicator"], d["risk"], d["why"], d["source"]] for d in iocs_sorted]
        
        # emphasize only strong signals in high_level mode
        if high_level:
            rows = [r for r in rows if (r[2] == "High" or r[2] == "Critical")]

        TerminalUI.table(["Type","Indicator","Risk","Rationale","Source"], rows, max_rows=25)

        out["ioc_count"] = len(iocs_sorted)
        out["iocs"] = iocs_sorted
        return out


    # ------------------------- Scorer functions --------------------------

    def _score_processes(self, census: Dict[int, Dict[str, Any]], psscan: List[dict], psxview: List[dict]) -> Tuple[Dict[str, Any], List[Tuple[int,str,Optional[int],int,str,str]]]:
        pid_set = set(census.keys())
        psscan_pids = {self._as_int(r.get("PID") or r.get("pid")) for r in (psscan or [])}
        psscan_pids.discard(None)

        psx_false: Dict[int, List[str]] = {}
        for r in psxview or []:
            pid = self._as_int(r.get("PID") or r.get("Pid") or r.get("pid"))
            if pid is None:
                continue
            falses = []
            for k, v in r.items():
                if isinstance(v, bool) and v is False and k.upper() not in {"PID","WOW64"}:
                    falses.append(str(k))
            if falses:
                psx_false[pid] = falses

        # Build rules (additive, easy to extend)
        rows: List[List[int,str,Optional[int],int,str,str]] = []
        for pid in sorted(pid_set | psscan_pids):
            b = census.get(pid, {"pid": pid, "name": "(not in pslist)", "ppid": None, "path": "", "wow64": None})
            name = (b.get("name"))
            wow64 = b.get('wow64')
            ppid = b.get("ppid")
            path = b.get("path") or ""
            score = 0; flags: List[str] = []; reasons: List[str] = []

            if pid in psscan_pids and pid not in pid_set:
                score += 8; flags.append("HK"); reasons.append("Present in pool scan (psscan) but absent in EPROCESS list (pslist).")
            if pid in psx_false:
                score += 8; flags.append("XV"); reasons.append(f"Inconsistency across discovery sources (psxview): {', '.join(psx_false[pid])} = False.")
            if ppid and ppid not in pid_set:
                score += 8; flags.append("ZB"); reasons.append("Parent PID not present in census (orphan/zombie).")
            # Process executable path and name signals
            if is_suspicious_path(path.lower()):
                flags.append("OP")
                reasons.append(f"Executable in suspicious non-system path ({path}).")
                score += 2 

                if wow64:
                    flags.append("ww")
                    reasons.append(f"32bit Executable Running on 64bit Windows from non-system path ({path}).")
                    score += 4
                
                if name and char_entropy(name) > 3.5:  # High entropy (randomized names)
                    flags.append("OP+ENT")
                    reasons.append(f"Executable with high entropy name (appears randomized).")
                    score += 4
                
                if name and is_non_ascii(name):  # Non-ASCII names (evasion technique)
                    if is_suspicious_path(path.lower()):   
                        flags.append("UNI")
                        reasons.append(f"Executable with non-ASCII characters in the name.")
                        score += 4            
            
            else:
                if name and char_entropy(name) > 3.5:  # High entropy (randomized names)
                    flags.append("ENT")
                    reasons.append(f"Executable with high entropy name (appears randomized).")
                    score += 2
                
                if name and is_non_ascii(name):  # Non-ASCII names (evasion technique)
                        flags.append("UNI")
                        reasons.append(f"Executable with non-ASCII characters in the name.")
                        score += 2             # if is_suspicious_path(path.lower())

            ppid = census.get(pid, {}).get("ppid")
            if ppid is not None and ppid not in census:
                if is_suspicious_path(path):
                    flags.append("ZB+OP")
                    reasons.append(f"Orphan process with a suspicious path ({path}).")
                    score += 6
                else:
                    flags.append("ZB")
                    reasons.append(f"Orphan process.")
                    score += 4

            
            # Parent-child relationship check with broader critical system processes (not just winlogon)
            parent_name = census.get(ppid, {}).get("name", "").lower() if ppid else ""
            known_parent_processes = ["lsass.exe", "winlogon.exe", "smss.exe", "wininit.exe"]
            if parent_name and path:
                if parent_name in known_parent_processes:
                    if is_suspicious_path(path):
                        flags.append("OP+WP")
                        reasons.append(f"Critical system parent ({parent_name}) with child running from a suspicious path ({path}).")
                        score += 8
                    else:
                        flags.append("WP")
                        reasons.append(f"Critical system parent ({parent_name}) with child running from a suspicious path ({path}).")
                        score += 8
            
            # Check for processes running from unconventional locations (e.g., development environments)
            dev_paths = [r"\\workspace\\", r"\\venv\\", r"\\python\\", r"\\dev\\", r"\\git\\", r"\\build\\"]
            if any(s in path for s in dev_paths):
                flags.append("DEV")
                reasons.append(f"Process running from a development environment path ({path}).")
                rows.append((pid, name, ppid, score, ",".join(flags), " ".join(reasons)))
                score += 4          
            
            if score > 0 and pid and not(any(pid in r for r in rows)):
                rows.append((pid, name, ppid, score, ",".join(flags), " ".join(reasons)))

        flags = {
            "pslist_count": len(pid_set),
            "psscan_count": len(psscan_pids),
            "hidden_count": len([1 for pid in psscan_pids if pid not in pid_set]),
            "orphans": len([1 for pid, b in census.items() if b.get("ppid") and b.get("ppid") not in pid_set]),
            "psxview_inconsistent": len(psx_false),
        }
        rows.sort(key=lambda r: (-r[3], r[0]))
        rows = [self._score_map(row, -3) for row in rows]
        return flags, rows
    
    ###############################################################

    def _score_injections(self, row: Dict[str, Any]) -> Tuple[int, str, str]:
        """
        Analyze each malfind injection and score it based on both disassembly and hexdump.
        """
        score = 0
        flags = []
        rationale = []

        # Check disassembly for suspicious patterns
        disasm = row.get("Disasm", "")
        if self._is_disasm_susp(disasm):
            score += 8
            flags.append("DISASM")
            rationale.append("Suspicious disassembly detected.")

        # Check hexdump for suspicious byte patterns
        hexdump = row.get("Hexdump", "")
        if self._is_hexdump_susp(hexdump):
            score += 8
            flags.append("HEXDUMP")
            rationale.append("Suspicious byte sequence detected in hexdump.")

        # Check for private memory regions (memory not backed by a file)
        if row.get("File output") == "Disabled" and row.get("PrivateMemory") == 1:
            score += 4
            flags.append("PRV")
            rationale.append("Private memory region with no file backing.")
        
        # Commit charge analysis: high commit charge can indicate large memory allocation for injection
        commit_charge = row.get("CommitCharge", 0)
        if commit_charge > 5:
            score += 4
            flags.append("LARGE_COMMIT")
            rationale.append("High commit charge.")

        return score, ", ".join(flags), " | ".join(rationale)

    ###############################################################

    def _score_network_connections(
        self,
        row: Dict[str, Any],
        is_private_ip,
        is_loopback
    ) -> Tuple[int, List[str], str]:
        """
        DFIR-backed scoring for netscan output
        """
        score = 0
        flags: List[str] = []
        why: List[str] = []

        state = str(row.get("State") or "").upper()
        proto = str(row.get("Proto") or "")
        la = str(row.get("LocalAddr") or "")
        fa = str(row.get("ForeignAddr") or "")
        lp = str(row.get("LocalPort") or "")
        fp = str(row.get("ForeignPort") or "")
        owner = (row.get("Owner") or row.get("Process") or "") or ""
        pid = row.get("PID")

        try: lp_i = int(lp)
        except: lp_i = 0
        try: fp_i = int(fp)
        except: fp_i = 0

        lip = la.split(":")[0].strip() if la else ""
        fip = fa.split(":")[0].strip() if fa else ""
        public_remote = fip and not is_private_ip(fip)

        conn_count = int(row.get("_pid_conn_count") or 0)
        same_remote_count = int(row.get("_same_remote_count") or 0)
        owner_l = owner.lower()

        system_owners = {"system", "services.exe", "lsass.exe", "wininit.exe", "svchost.exe", "spoolsv.exe"}
        lolbin_clients = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
        # Service/admin ports that are risky to the internet from workstations
        admin_ports = {22, 23, 53, 80, 443, 445, 3389, 5985, 5986, 5900}
        # Common "okay" ports (for de-noising uncommon test)
        common_ports = {
            80, 443, 53, 123, 25, 110, 995, 143, 993, 3389, 445, 139, 22, 21, 23,
            587, 465, 389, 636, 135, 137, 138, 3306, 1433, 1521, 5432, 27017, 8080, 8443
        }
        # Ports that often show up in implants / red team demos
        suspicious_ports = {4444, 1337, 6969, 2222, 9001, 6667, 6666}

        # ---- TCP rules ----
        if proto.upper().startswith("TCP"):
            # Major: listener exposure or unexpected listener by non-system
            if state in {"LISTENING", "LISTEN"}:
                if lp_i in {3389, 445, 139} and owner_l not in system_owners:
                    score += 12; flags += ["UnexpectedListener"]; why.append(f"{owner or 'Unknown'} listening on sensitive port {lp_i}")
                # High ephemeral listener by non-system, not loopback
                if lp_i >= 49152 and owner_l and owner_l not in system_owners and not is_loopback(lip):
                    score += 10; flags += ["HighPortListener"]; why.append(f"High-port listener {lp_i} by {owner}")

            # Public ESTABLISHED with no PID (netscan orphan) – treat as major
            if state == "ESTABLISHED" and public_remote and (pid in (None, "", 0)):
                score += 12; flags += ["PublicNoPID"]; why.append(f"Public ESTABLISHED with no PID to {fip}")

            # Outbound to admin/service ports on the public internet (workstations usually shouldn't)
            if state in {"ESTABLISHED", "SYN_SENT"} and public_remote and fp_i in {445, 3389, 23}:
                score += 12; flags += ["AdminPortOutbound"]; why.append(f"Outbound to {fp_i} on public {fip}")

            # LOLBIN outbound to public
            if state in {"ESTABLISHED", "SYN_SENT"} and public_remote and owner_l in lolbin_clients:
                score += 10; flags += ["LOLBINOutbound"]; why.append(f"{owner} connecting to public {fip}")

            # Non-standard destination ports to public (MITRE T1571) vs uncommon-but-common set
            if state in {"ESTABLISHED", "SYN_SENT"} and public_remote and fp_i:
                if fp_i in suspicious_ports:
                    score += 10; flags += ["BadPort"]; why.append(f"Known suspicious dest port {fp_i}")
                elif fp_i not in common_ports:
                    score += 8; flags += ["UncommonPort"]; why.append(f"Uncommon dest port {fp_i} to public {fip}")

            # Baseline: established→public only matters with a co-signal
            cosignal = any(t in flags for t in ("UnexpectedListener","HighPortListener","AdminPortOutbound","LOLBINOutbound","BadPort","UncommonPort"))
            if state == "ESTABLISHED" and public_remote and cosignal:
                score += 6; flags += ["EstablishedPublic"]; why.append(f"Established to public IP {fip}")

        # ---- UDP rules ----
        if proto.upper().startswith("UDP"):
            # De-noise typical Windows UDP listeners
            benign_udp = {5353, 5355, 1900, 123}
            if lp_i in benign_udp and owner_l in {"svchost.exe", "system"}:
                pass  # ignore
            else:
                # UDP "any/*" sockets bound to 0.0.0.0 by odd owners get minor weight
                if la in {"0.0.0.0", "::"} and lp_i >= 49152 and owner_l and owner_l not in system_owners:
                    score += 4; flags += ["UDPAnyHighPort"]; why.append(f"Wildcard UDP high-port {lp_i} by {owner}")

        # Volume (context only; never the only reason to alert thanks to global threshold)
        if conn_count >= 50:
            score += 8; flags += ["ConnBurst"]; why.append(f"Process has {conn_count} sockets")
        elif conn_count >= 15:
            score += 6; flags += ["ManyConns"]; why.append(f"Process has {conn_count} sockets")
        if public_remote and same_remote_count >= 8:
            score += 8; flags += ["ToSameRemote"]; why.append(f"Multiple sockets to {fip}")

        # Minor: loopback pair on uncommon ports (often IPC)
        if is_loopback(lip) and fip and is_loopback(fip) and lp_i and fp_i and lp_i not in common_ports and fp_i not in common_ports:
            score += 2; flags += ["LoopbackPair"]; why.append("Loopback pair on uncommon ports")

        return int(score), flags, " | ".join(why) if why else "—"

    ################################################################
       
    def _score_scheduled_task(self, row: dict) -> tuple[int, list[str]]:
        """
        DFIR-informed scoring for Scheduled Tasks:
        (+10-12) : Risky script/obfuscation/remote content, Script payload, and Non-system/user-writable path
        (+6-8): LOLBin used with risky content
        (+1-2): User profile path, Auto-start trigger, Privileged principal, Hidden window, DLL via rundll32, COM reg via regsvr32
        """
        score, why = 0, []
        name  = str(row.get("Task Name") or "")
        act   = str(row.get("Action") or "")
        args  = str(row.get("Action Arguments") or "")
        trig  = str(row.get("Trigger Type") or "")
        princ = (str(row.get("Principal ID") or "") or str(row.get("Author") or ""))
        enabled = bool(row.get("Enabled", True))

        la = (act or "").lower()
        aa = (args or "").lower()
        na = name.lower()

        # --- classifiers ---
        lolbins = ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe",
                "rundll32.exe","regsvr32.exe","msbuild.exe","wmic.exe","bitsadmin.exe","schtasks.exe")
        script_exts = (".ps1",".vbs",".js",".jse",".wsf",".hta",".bat",".cmd",".psm1")
        risky_tokens = (
            "-enc","-encodedcommand"," frombase64string","iex ",
            "-nop","-noprofile","-w hidden","-windowstyle hidden",
            "-executionpolicy bypass","-ep bypass","powershell -e ",
            "http://","https://","bitsadmin /transfer","\\curl.exe","mshta "
        )

        is_lolbin      = any(x in la for x in lolbins)
        has_risky      = any(x in aa for x in risky_tokens)
        has_script     = any(aa.strip().endswith(ext) or ext in aa for ext in script_exts)
        has_remote_url = ("http://" in aa) or ("https://" in aa)

        def _looks_pathlike(s: str) -> bool:
            s = (s or "").lower()
            if re.match(r"^[a-z]:\\", s): return True
            if s.startswith("\\\\"): return True
            # contains a backslash and a known file extension somewhere
            if ("\\" in s or "/" in s) and re.search(r"\.(exe|dll|sys|cpl|bat|cmd|ps1|psm1|vbs|js|hta|msi|scr|com)\b", s):
                return True
            return False

        data = (act + " " + args).strip()
        try:
            non_system_payload = bool(data) and _looks_pathlike(data) and not_system_path(data)
        except Exception:
            non_system_payload = False

        in_profile_hint = any(t in ((la + aa)) for t in ("\\appdata\\","\\temp\\","\\users\\public\\","\\downloads\\","\\desktop\\"))
        autostart = any(x in trig.lower() for x in ("logon","startup","boot"))
        priv_prin = any(x in (princ or "").lower() for x in ("system","administrator","adm","local service","network service"))
        hidden    = (" hidden" in aa) or ("-w hidden" in aa) or ("-windowstyle hidden" in aa)
        rundll_dll = ("rundll32.exe" in la) and (".dll" in aa or ".dll" in la)
        regsvr_dll = ("regsvr32.exe" in la) and (".dll" in aa)

        is_microsoft_default   = na.startswith("\\microsoft\\windows\\")
        looks_system32_action  = ("\\windows\\system32" in la) or ("system32\\" in la)

        # --- MAJOR ---
        if has_risky or has_remote_url:
            score += 12; why.append("Risky script/obfuscation/remote content")
        if has_script:
            score += 10; why.append("Script payload")
        if non_system_payload:
            score += 10; why.append("Non-system/user-writable path")

        # --- Synergy ---
        if is_lolbin and (has_risky or has_script or has_remote_url or non_system_payload):
            score += 8; why.append(f"LOLBin used with risky content ({act})")
        else:
            if is_lolbin:
                score += 1; why.append(f"LOLBin action: {act}")

        # --- MINOR ---
        if in_profile_hint:
            score += 1; why.append("User profile path")
        if autostart:
            score += 1; why.append(f"Auto-start trigger: {trig}")
        if priv_prin:
            score += 1; why.append(f"Privileged principal: {princ}")
        if hidden:
            score += 1; why.append("Hidden window")
        if rundll_dll:
            score += 1; why.append("DLL via rundll32")
        if regsvr_dll:
            score += 1; why.append("COM reg via regsvr32")

        # --- Benign Microsoft/system32 cap (no major => cap to Low) ---
        no_major = not (has_risky or has_script or has_remote_url or non_system_payload)
        if is_microsoft_default and looks_system32_action and no_major:
            score = min(score, 4)
            if "Microsoft default/system32 baseline" not in why:
                why.append("Microsoft default/system32 baseline")

        # Disabled note (no negative scoring)
        if (not enabled) and no_major:
            if "Disabled" not in why:
                why.append("Disabled")

        return max(0, int(score)), why

    ########################################################

    def _score_userassist_name(self, name: str) -> tuple[int, list[str]]:
        """
        Heuristic scorer for UserAssist entries.
        - (+10~+12): known tool tokens; Temp/Downloads/Desktop/Public/Recycle/Startup; UNC/non-system drives; generic non-system path
        - (+6): script path types
        - (+1~+2): exe/dll/com; entropy/length hints
        """
        score, why = 0, []
        n = (name or '').strip()
        if not n:
            return 0, []

        n_norm = n.replace("/", "\\")
        n_lower = n_norm.lower()

        # Path-likeness
        pathlike = False
        if re.match(r"^[a-zA-Z]:\\", n_norm) or n_lower.startswith("\\\\") or n_lower.startswith("\\??\\"):
            pathlike = True
        if not pathlike and ("\\" in n_norm or "/" in n_norm):
            if re.search(r"\.(exe|dll|com|bat|cmd|ps1|vbs|js|hta|lnk)$", n_lower):
                pathlike = True
        if not pathlike:
            return 0, []

        # --- Known-Folder GUIDs that actually map to system Program Files roots (treat as system) ---
        system_kf_guids = (
            "{6d809377-6af0-444b-8957-a3773f02200e}",
            "{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}",
        )
        has_system_kf_prefix = any(n_lower.startswith(g + "\\") for g in system_kf_guids)

        # --- helpers ---
        def base_name(path: str) -> str:
            return os.path.splitext(os.path.basename(path))[0]

        def ext_name(path: str) -> str:
            return os.path.splitext(path)[1].lower()

        def any_in(hay: str, tokens: tuple[str, ...]) -> bool:
            L = hay.lower()
            return any(t in L for t in tokens)

        # MAJOR: known tools
        known_rt = (
            "mimikatz","psexec","procdump","bloodhound","sharphound","rubeus","seatbelt",
            "powersploit","empire","crackmapexec","cme","koadic","evil-winrm","lazagne",
            "winpeas","nc.exe","ncat","netcat","plink","pscp","beacon","cobaltstrike",
            "metasploit","msfvenom","pafish","sharpdpapi","sharpup","sharproast",
            "hashdump","pwdump","adfind","wce.exe","mimidrv","lsassy","kerberoast"
        )
        if any(k in n_lower for k in known_rt):
            score += 12; why.append("Matches known red-team/tool name")

        # MAJOR: location heuristics
        TEMP_TOKENS = (
            "\\temp\\", "\\appdata\\local\\temp\\", "\\tmp\\", "\\cache\\",
            "\\microsoft\\windows\\temporary internet files\\",
        )
        DOWNLOAD_TOKENS = ("\\downloads\\",)
        DESKTOP_TOKENS  = ("\\desktop\\",)
        PUBLIC_TOKENS   = ("\\users\\public\\", "\\public\\")
        RECYCLE_TOKENS  = ("\\$recycle.bin\\",)
        STARTUP_TOKENS  = ("\\start menu\\programs\\startup\\",)

        if any_in(n_lower, TEMP_TOKENS):
            score += 10; why.append("Temp-like directory")
        if any_in(n_lower, DOWNLOAD_TOKENS):
            score += 10; why.append("Downloads directory")
        if any_in(n_lower, DESKTOP_TOKENS):
            score += 8;  why.append("Desktop directory")
        if any_in(n_lower, PUBLIC_TOKENS):
            score += 8;  why.append("Public user directory")
        if any_in(n_lower, RECYCLE_TOKENS):
            score += 10; why.append("$Recycle.Bin directory")
        if any_in(n_lower, STARTUP_TOKENS):
            score += 8;  why.append("Startup folder")

        # MAJOR: non-system or network
        if (re.match(r"^[d-z]:\\", n_lower) or n_lower.startswith("\\\\")) and not has_system_kf_prefix:
            score += 10; why.append("Non-system or network location")

        # MAJOR: generic non-system
        try:
            if not has_system_kf_prefix and not_system_path(n_norm):
                if "Non-system or network location" not in why and \
                not any(tag in why for tag in ("Temp-like directory","Downloads directory","Desktop directory",
                                                "Public user directory","$Recycle.Bin directory","Startup folder")):
                    score += 8; why.append("Non-system path")
        except Exception:
            pass

        ext = ext_name(n_lower)
        location_major_present = any(tag in why for tag in (
            "Temp-like directory","Downloads directory","Desktop directory","Public user directory",
            "$Recycle.Bin directory","Startup folder","Non-system or network location","Non-system path"))

        is_non_system = False
        try:
            if not has_system_kf_prefix:
                is_non_system = not_system_path(n_norm)
        except Exception:
            pass

        if ext in (".ps1",".vbs",".js",".hta",".bat",".cmd"):
            # Scripts are major only when non-system/user-writable; otherwise minor
            if is_non_system or location_major_present:
                score += 6; why.append("Script path")
            else:
                score += 2; why.append("Script path (system)")
        elif ext in (".exe",".dll",".com"):
            if is_non_system or location_major_present:
                score += 2; why.append("Executable/library path")

        # Minor filename hints
        bn = base_name(n_lower)
        if re.search(r"[a-f0-9]{8,}", bn):
            score += 1; why.append("Hex-like name segment")
        ent = char_entropy(re.sub(r"[^a-z0-9]", "", bn))
        if len(bn) >= 6 and ent >= 4.0:
            score += 1; why.append("High-entropy basename")
        if len(bn) >= 24:
            score += 1; why.append("Unusually long name")

        return int(score), why



    # --------------------------- helper primitives -------------------------

    def _ensure_one(self, pipe: Pipeline, image_path: str, artifacts_dir: str, name: str, use_cache: bool) -> str:
        res = pipe.run_plugin_raw(image_path=image_path, enable={name}, renderer="json",
                                outdir=artifacts_dir, concurrency=1, use_cache=use_cache, strict= True)
        mp = (res.artifacts or {}).get("plugins") or {}
        return mp.get(name, os.path.join(artifacts_dir, f"{name}.json"))

    def _build_census(self, pslist: List[dict], pstree: List[dict]) -> Dict[int, Dict[str, Any]]:
        census: Dict[int, Dict[str, Any]] = {}
        for r in pslist or []:
            pid = self._as_int(r.get("PID") or r.get("Pid") or r.get("pid"))
            if pid is None:
                continue
            name = (r.get("ImageFileName")).strip()
            ppid = self._as_int(r.get("PPID") or r.get("ppid"))
            wow64 = bool(r.get("Wow64")) if r.get("Wow64") is not None else None
            start = r.get("CreateTime") or r.get("StartTime") or r.get("Start")
            census[pid] = {"pid": pid, "name": name, "ppid": ppid, "wow64": wow64, "start": start}

        for r in pstree or []:
            pid = self._as_int(r.get("PID") or r.get("Pid") or r.get("pid"))
            if pid is None or pid not in census:
                continue
            census[pid]["ppid"] = census[pid].get("ppid") or self._as_int(r.get("PPID"))
            census[pid]["path"] = census[pid].get("path") or (r.get("Path") or r.get("Cmd"))
            census[pid]["name"] = census[pid].get("name") or (r.get("ImageFileName"))
        return census
   
    def _flatten_UA_with_context(self, rows):
        """
        DFS over plugin rows, yielding each row with lightweight breadcrumbs:
        __key_path   : best-effort registry key path for this row
        __ua_guid    : UserAssist GUID (if key path matches UA pattern)
        __hive_offset: nearest Hive Offset (row or ancestor)
        """
        UA_RE = re.compile(r"UserAssist\\\{([0-9A-Fa-f-]+)\}\\Count")

        stack = [(r, r.get("Key") or r.get("Path") or None,
                r.get("Hive Offset"), None) for r in rows]
        while stack:
            r, key_path, hive_off, ua_guid = stack.pop()

            # Prefer row key/path; otherwise inherit
            row_key = r.get("Key") or r.get("Path")
            if row_key:
                key_path = row_key

            # Hive offset: inherit if missing
            if r.get("Hive Offset") is not None:
                hive_off = r.get("Hive Offset")

            # Infer UA GUID from key path when present
            if key_path:
                m = UA_RE.search(key_path)
                if m:
                    ua_guid = m.group(1)

            out = copy.copy(r)
            if key_path: out["__key_path"] = key_path
            if ua_guid:  out["__ua_guid"] = ua_guid
            if hive_off is not None:
                try:
                    out["__hive_offset"] = int(hive_off)
                except Exception:
                    out["__hive_offset"] = hive_off

            yield out

            ch = r.get("__children")
            if isinstance(ch, list) and ch:
                for c in ch:
                    stack.append((c, key_path, hive_off, ua_guid))

    
    def _indicator_from_flags(self, flags: list[str]) -> str:
        # order by importance; we’ll show at most 2
        priority = [
            "PublicNoPID", "AdminPortOutbound", "UnexpectedListener", "HighPortListener",
            "LOLBINOutbound", "BadPort", "UncommonPort", "ToSameRemote",
            "ConnBurst", "ManyConns", "UDPAnyHighPort", "LoopbackPair"
        ]
        display = {
            "PublicNoPID": "NOPID🌐",
            "AdminPortOutbound": "ADMIN↗",
            "UnexpectedListener": "SENS-LISTEN",
            "HighPortListener": "LISTEN↑",
            "LOLBINOutbound": "LOLBIN↗",
            "BadPort": "PORT⚠",
            "UncommonPort": "PORT?",
            "ToSameRemote": "FANOUT",
            "ConnBurst": "BURST",
            "ManyConns": "MANY",
            "UDPAnyHighPort": "UDP*↑",
            "LoopbackPair": "LOOP"
        }
        chosen = [display[f] for f in priority if f in (flags or [])]
        return ", ".join(chosen[:2]) if chosen else "—"


    @classmethod        
    def _score_map(cls, row: tuple, index: int) -> tuple:
        score = row[index]
        risk = cls._risk_from_score(score)
        row_list = list(row)
        row_list[index] = risk
        return tuple(row_list)

    @classmethod        
    def _risk_from_score(cls, s: int) -> str:         
        if s >= 20:
            return "Critical"
        if s >= 14:
            return "High"
        if s >= 9:
            return "Medium"
        return "Low"

    @staticmethod
    def _is_hexdump_susp(hexdump: str) -> bool:
        """
        Analyze the hexdump of a memory region to detect common malicious byte sequences.
        Returns True if suspicious patterns are found; False otherwise.
        """
        bytes_data = bytes.fromhex(hexdump.replace(" ", "").replace("\n", ""))

        # Patterns to look for in hexdump (YARA-like signatures)
        suspicious_patterns = [
            b"\x90" * 4,  # At least 4 consecutive NOPs
            b"\xfc\xe8\x8f\x00\x00\x00\x60",  # Meterpreter reverse TCP prologue
            b"\xe8[\x00-\xff]{4}[\x00-\xff]{2}",  # CALL instruction with variable offset
            b"\xeb[\x00-\xff]{1,2}",  # Short jump (JMP) with variable offset
            b"\x64\x8b\x00",  # mov edx, fs:[???]
            b"\x68\x32\x74\x91",  # Windows socket signature
            b"\x29\x80\x6b\x00",  # Self-modifying code signature
        ]
        for pattern in suspicious_patterns:
            if pattern in bytes_data:
                return True 
        return False  

    @staticmethod
    def _is_disasm_susp(disasm: str) -> bool:
        suspicious_patterns = [
            r"\s*push\s+ebp",  # Standard function prologue (often overwritten in injected code)
            r"\s*mov\s+ebp,\s+esp",  # Moving stack pointer to base pointer
            r"\s*add\s+esp,\s+0x[0-9a-f]+",  # Stack manipulation
            r"\s*(call|jmp)\s+.*",  # Unusual function calls or jumps (shellcode markers)
            r"\s*xor\s+eax,\s+eax",  # Resetting register values
            r"\s*xor\s+ecx,\s+ecx",  # Another register obfuscation pattern
            r"\s*inc\s+eax",  # Shellcode often increments eax (part of shellcode logic)
            r"\s*shl\s+eax,\s+\d+",  # Shifting register values (often used in shellcode)
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, disasm):
                return True 
        return False
    
    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return True 

    @staticmethod        
    def _is_loopback(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_loopback
        except Exception:
            return ip in {"::1"}
    
    @staticmethod        
    def _seems_pathlike(s: str) -> bool:
        if not s: return False
        ls = s.lower()
        return (
            bool(__import__("re").match(r"^[a-z]:\\", s)) or
            ls.startswith("\\??\\") or
            ("\\" in s and any(ext in ls for ext in (".exe",".dll",".ps1",".vbs",".js",".hta",".bat")))
        )
    
    @staticmethod        
    def _as_int(v) -> Optional[int]:
        try:
            return int(v)
        except Exception:
            return None

