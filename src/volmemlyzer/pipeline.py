# File: pipeline.py
from __future__ import annotations
import os, logging, json, csv, re
from typing import Dict, Any, Set, List, Optional, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from .core import FeatureRow, ExtractResult, ActionResult
from .runner import VolRunner
from .extractor_registry import ExtractorRegistry
from .utilities import to_builtin, renderer_to_ext, cheap_image_hash
from .converters import convert_artifact

logger = logging.getLogger(__name__)

class Pipeline:
    def __init__(self, runner: VolRunner, registry: ExtractorRegistry):
        self.runner = runner
        self.registry = registry

    # ---------- Public API ----------

    def run_plugin_raw(
        self,
        image_path: str,
        *,
        enable: Set[str] | None = None,
        drop: Set[str] | None = None,
        renderer: str = "json",
        outdir: Optional[str] = None,
        concurrency: int = 1,
        use_cache: bool = True,
        strict: bool = False
    ) -> ActionResult:
        selected = self._select(enable, drop)
        layers = self.registry.topo_layers(selected)
        outdir = outdir or self._default_artifacts_dir(image_path)
        os.makedirs(outdir, exist_ok=True)
        artifact_map: Dict[str, str] = {}

        want_ext = renderer_to_ext(renderer)
        img_name = image_path.split("\\")[-1]

        def _run_one(name: str) -> tuple[str, str]:
            spec, _ = self.registry.get(name)
            # 1) exact cache hit?
            if use_cache:
                chk = self.check_cache(outdir, spec.name, img_name, require_format=want_ext)
                if chk["ok"]:
                    src_path = chk["path"]
                    src_format = chk["format"]
                    if src_format == want_ext:
                        logger.info("Using the cached %s plugin output in the %s directory. Re-run avoided", spec.name, outdir)
                        return name, src_path
                    dst_path = os.path.join(outdir, f"{spec.name}.{want_ext}")
                    decision, out_path, used = convert_artifact(src_path, src_format, dst_path, want_ext)
                    if decision == "convert" and out_path:
                        logger.info("Converted %s: %s -> %s via %s. Re-run avoided", spec.name, src_format, want_ext, used)
                        return name, out_path

            # 3) no hit or not convertible -> run plugin with requested renderer
            run = self.runner.run_plugin(image_path, spec, renderer=renderer, output_dir=outdir)
            # VolRunner returns PluginRunResult; prefer its output path if present
            out_path = getattr(run, "output_path", os.path.join(outdir, f"{spec.name}.{want_ext}"))
            return name, out_path

        # topo-order, per-layer concurrency
        for layer in layers:
            if concurrency > 1 and len(layer) > 1:
                logger.info("Running plugins: <<{}>> in paralell".format(', '.join(map(str, layer))))
                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    futs = {pool.submit(_run_one, n): n for n in layer}
                    for fut in as_completed(futs):
                        n, p = fut.result()
                        artifact_map[n] = p
            else:
                for n in layer:
                    logger.info("Running plugin %s", n)
                    k, p = _run_one(n)
                    artifact_map[k] = p

        return ActionResult(artifacts={"raw_dir": outdir, "plugins": artifact_map})

    def run_extract_features(
        self,
        image_path: str,
        *,
        enable: Set[str] | None = None,
        drop: Set[str] | None = None,
        concurrency: int = 1,
        artifacts_dir: Optional[str] = None,
        use_cache: bool = True,
    ) -> FeatureRow:
        selected = self._select(enable, drop)
        layers = self.registry.topo_layers(selected)
        artifacts_dir = artifacts_dir or self._default_artifacts_dir(image_path)
        os.makedirs(artifacts_dir, exist_ok=True)

        features: Dict[str, Any] = {}
        context_map: Dict[str, Any] = {}

        def _task(name: str):
            spec, extractor = self.registry.get(name)

            # Always feed extractors JSON, reuse convertible cache or run -r=json.
            json_path = self._run_or_fetch_plugin_output(
                image_path, spec, artifacts_dir, target_renderer="json", use_cache=use_cache)

            dep_ctx = {dep: context_map.get(dep) for dep in spec.deps}
            extr: ExtractResult = extractor(json_path, context=dep_ctx)
            return name, extr

        for layer in layers:
            if concurrency > 1 and len(layer) > 1:
                logger.info("Running plugins: <<{}>> in paralell".format(', '.join(map(str, layer))))
                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    futs = {pool.submit(_task, n): n for n in layer}
                    for fut in as_completed(futs):
                        k, extr = fut.result()
                        if extr.context is not None:
                            context_map[k] = extr.context
                        features.update(extr.features or {})
            else:
                for n in layer:
                    logger.info("Running plugin %s", n)
                    k, extr = _task(n)
                    if extr.context is not None:
                        context_map[k] = extr.context
                    features.update(extr.features or {})

        row = FeatureRow(
            image_name=os.path.basename(image_path),
            features={k: to_builtin(v) for k, v in features.items()},
            image_hash=cheap_image_hash(image_path),
            vol_version=self.runner.get_version(),
        )
        return row


    def run_analysis_steps(
        self,
        *,
        image_path: str,
        artifacts_dir: Optional[str] = None,
        steps: Optional[Iterable[int]] = None,
        use_cache: bool = True,
        high_level: bool = False
    ) -> Dict[str, Any]:
        from .analysis import OverviewAnalysis
        eng = OverviewAnalysis()
        return eng.run_steps(
            pipe=self,
            image_path=image_path,
            artifacts_dir=artifacts_dir,
            steps=steps,
            use_cache=use_cache,
            high_level= high_level
        )
    # ---------- Core helpers ----------

    def _run_or_fetch_plugin_output(
        self,
        image_path: str,
        spec,
        artifacts_dir: str,
        target_renderer: str,
        use_cache: bool,
    ) -> str:
        """
        Return a path for `spec` rendered as `target_renderer`.
        1) If exact cached output exists -> use it.
        2) Else, if a convertible cached format exists (json/jsonl/csv) -> convert and return.
        3) Else, run the plugin with the requested renderer and return the new path.
        """
        want_ext = renderer_to_ext(target_renderer)
        img_name = image_path.split("\\")[-1]
        base = os.path.join(artifacts_dir, f"{img_name}_{spec.name}")

        # 1) exact format hit
        if use_cache:
            chk = self.check_cache(artifacts_dir, spec.name, img_name, require_format=want_ext, strict= True)
            if chk["ok"]:
                logger.info("Using the cached %s plugin output in the %s directory. Re-run avoided", spec.name, artifacts_dir)
                return chk["path"]

        # 3) no cache or not convertible -> run once with desired renderer
        run = self.runner.run_plugin(image_path, spec, renderer=target_renderer, output_dir=artifacts_dir)
        return getattr(run, "output_path", f"{base}.{want_ext}")


    # ---------- Cache validation (single source of truth) ----------

    def check_cache(
        self,
        artifacts_dir: str,
        plugin_name: str,
        img_name: str,
        *,
        require_format: Optional[str] = None,  # "json","jsonl","csv","txt"
        strict: bool = False
    ) -> Dict[str, Any]:
        import json as _json, csv as _csv, re as _re

        def _stderr_has_critical(p: str) -> bool:
            sp = p + ".stderr.txt"
            if not os.path.exists(sp): return False
            try:
                t = open(sp, "r", encoding="utf-8", errors="replace").read()
            except Exception:
                return False
            return bool(_re.search(r"(Traceback|ERROR|Exception|No suitable address space|failed)", t, _re.I))

        def _ok_json(p: str) -> bool:
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = _json.load(f)
                if isinstance(data, list): return len(data) > 0
                if isinstance(data, dict) and isinstance(data.get("rows"), list): return len(data["rows"]) > 0
                return False
            except Exception:
                return False

        def _ok_jsonl(p: str) -> bool:
            try:
                n = 0
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    for i, ln in zip(range(100), f):
                        s = ln.strip()
                        if not s: 
                            continue
                        _json.loads(s)
                        n += 1
                return n > 0
            except Exception:
                return False

        def _ok_csv(p: str) -> bool:
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    r = _csv.DictReader(f)
                    for i, row in zip(range(2), r):
                        if row: 
                            return True
                return False
            except Exception:
                return False

        def _ok_txt(p: str) -> bool:
            try:
                lines = []
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    for i, ln in zip(range(100), f):
                        s = ln.strip()
                        if s: lines.append(s)
                if not lines: return False
                joined = "\n".join(lines)
                if any(x in joined for x in ("Traceback","ERROR","Exception","No suitable address space")):
                    return False
                return True
            except Exception:
                return False

        if strict:
            candidates = [require_format]
        else:
            if require_format == 'json' or require_format == 'csv' or require_format == 'jsonl':
                candidates = ["json", "jsonl", "csv"]
            else:
                candidates = ["txt"]

        for ext in candidates:
            p = os.path.join(artifacts_dir, f"{img_name}_{plugin_name}.{ext}")
            if not os.path.exists(p): 
                continue
            ok = (ext=="json" and _ok_json(p)) or \
                 (ext=="jsonl" and _ok_jsonl(p)) or \
                 (ext=="csv" and _ok_csv(p)) or \
                 (ext in ("txt","log") and _ok_txt(p))
            if ok and not _stderr_has_critical(p):
                return {"ok": True, "path": p, "format": ext}

        return {"ok": False, "path": None, "format": None}

    # ---------- Small utilities ----------

    def _select(self, enable: Set[str] | None, drop: Set[str] | None) -> Set[str]:
        """Apply enable/drop to the registered plugin names."""
        names: Set[str] = set(self.registry.names())
        if enable:
            names &= set(enable)
        if drop:
            names -= set(drop)
        return names

    def _default_artifacts_dir(self, memory_dump_path: str) -> str:
        base = os.path.dirname(os.path.abspath(memory_dump_path))
        return os.path.join(base, ".volmemlyzer")
