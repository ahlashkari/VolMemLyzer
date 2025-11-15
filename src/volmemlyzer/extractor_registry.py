# File: /mnt/data/extractor_registry.py
from __future__ import annotations
import logging
from typing import Dict, Tuple, List, Set, Any, Protocol
from .core import PluginSpec, ExtractResult

log = logging.getLogger(__name__)

class ExtractorFunc(Protocol):
    def __call__(self, json_path: str, *, context: Dict[str, Any]) -> ExtractResult: ...

class ExtractorRegistry:
    """Holds plugin specs and matching extractor callables."""
    def __init__(self):
        self._specs: Dict[str, PluginSpec] = {}
        self._extractors: Dict[str, ExtractorFunc] = {}

    def register(self, spec: PluginSpec, func: ExtractorFunc) -> None:
        if not spec or not func:
            raise ValueError("register() requires a PluginSpec and extractor function")
        key = spec.name.lower()
        self._specs[key] = spec
        self._extractors[key] = func

    def get(self, name: str) -> Tuple[PluginSpec, ExtractorFunc]:
        key = name.lower()
        if key not in self._specs:
            raise KeyError(f"Unknown plugin: {name!r}")
        return self._specs[key], self._extractors[key]

    def has(self, name: str) -> bool:
        key = name.lower()
        return key in self._specs
    
    def names(self) -> List[str]:
        return sorted(self._specs.keys())

    def specs(self) -> List[PluginSpec]:
        return [self._specs[n] for n in self.names()]

    def topo_layers(self, selected: Set[str]) -> List[Set[str]]:
        """Return dependency layers from the selected plugin names."""
        sel = {n.lower() for n in selected}
        unknown = [n for n in sel if n not in self._specs]
        if unknown:
            raise KeyError(f"Unknown plugins in selection: {unknown}")

        # Build dependency map and indegrees
        deps = {n: set(self._specs[n].deps) & sel for n in sel}
        indeg = {n: len(deps[n]) for n in sel}
        layer = {n for n, d in indeg.items() if d == 0}
        seen: Set[str] = set()
        layers: List[Set[str]] = []
        while layer:
            layers.append(layer)
            seen |= layer
            next_layer: Set[str] = set()
            for n in sel - seen:
                indeg[n] = len(deps[n] - seen)
                if indeg[n] == 0:
                    next_layer.add(n)
            layer = next_layer
        if seen != sel:
            remaining = sel - seen
            raise ValueError(f"Dependency cycle or unresolved deps: {remaining}")
        return layers
