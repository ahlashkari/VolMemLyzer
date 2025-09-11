# File: /mnt/data/core.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Any, Mapping, Dict, Tuple

# ---------- Core "record" types (stable interfaces) ----------

@dataclass(frozen=True)
class PluginSpec:
    """Static description of a plugin (what we plan to run)."""
    name: str                   # "pslist"
    fqname: str                 # "windows.pslist"
    deps: Tuple[str, ...] = ()  # ("threads",)
    timeout_s: Optional[int] = None  # Per-plugin timeout
    renderer: Optional[str] = None   # "json" | "jsonl" | "text" (None -> runner default)

@dataclass
class PluginRunResult:
    """What actually happened when we invoked vol.py for one plugin."""
    rc: int
    runtime_s: float
    output_path: str            # path to JSON/JSONL/TXT produced
    stderr_path: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ExtractResult:
    """Uniform extractor output."""
    features: Mapping[str, Any]
    context: Any = None
    metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FeatureRow:
    """One row per image (what sinks will persist)."""
    image_name: str
    features: Mapping[str, Any] = None
    image_hash: Optional[str] = None
    dump_time: Optional[str] = None
    vol_version: Optional[str] = None
    run_id: Optional[str] = None

# ---------- Higher-level analysis artifacts ----------

# @dataclass
# class Event:
#     """Timeline event derived from plugin outputs."""
#     ts: Optional[str]
#     category: str               # "process", "network", "registry", ...
#     summary: str
#     data: Dict[str, Any] = field(default_factory=dict)
#     pid: Optional[int] = None
#     ppid: Optional[int] = None
#     plugin: Optional[str] = None

# @dataclass
# class Anomaly:
#     """A flagged suspicious condition with explanation."""
#     id: str
#     title: str
#     severity: str               # "low" | "medium" | "high" | "critical"
#     score: float
#     description: str
#     evidence: Dict[str, Any] = field(default_factory=dict)
#     related_pids: List[int] = field(default_factory=list)
#     plugin: Optional[str] = None

# @dataclass
# class IOC:
#     """Indicator of Compromise found in raw/plugin outputs."""
#     type: str                   # "ip" | "domain" | "url" | "path" | "registry" | "hash"
#     value: str
#     source_plugin: str
#     first_seen: Optional[str] = None

@dataclass
class ActionResult:
    """Generic result of a pipeline action; maps artifact names to paths/objects."""
    artifacts: Dict[str, Any] = field(default_factory=dict)
