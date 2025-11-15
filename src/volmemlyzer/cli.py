#!/usr/bin/env python3
"""
VolMemLyzer CLI

Modes:
  1) analyze  – run OverviewAnalysis steps over the image
  2) run      – run raw Volatility plugins (renderer, parallel, cache)
  3) extract  – extract plugin features via extractor registry
"""

from __future__ import annotations
import argparse, json, os, sys, time, logging, difflib
from dataclasses import asdict
from datetime import date
from typing import Optional, Set, List
from .utilities import write_csv, write_json, _get_dumps
from .pipeline import Pipeline
from .runner import VolRunner
from .analysis import OverviewAnalysis
from .extractor_registry import ExtractorRegistry
from .terminalUI import TerminalUI  
from rich.text import Text
try:
    from .plugins import build_registry
except Exception:
    build_registry = None  
try:
    from tqdm import tqdm
except Exception: 
    tqdm = None

log = logging.getLogger("volmemlyzer.cli")

# ------------------------ helpers ------------------------

_ALLOWED_RENDERERS = {"json", "jsonl", "csv", "pretty", "quick", "none"}

def _parse_plugins(s: Optional[str]) -> Set[str] | None:
    if not s:
        return None
    return {p.strip().lower() for p in s.split(",") if p.strip()}

def _steps_from_arg(s: Optional[str]) -> list[int] | None:
    if s is None:
        return None
    out: list[int] = []
    for tok in (x.strip().lower() for x in s.split(",") if x.strip()):
        if tok.isdigit():
            out.append(int(tok))
        else:
            alias = {
                "bearings": 0, "info": 0,
                "processes": 1, "proc": 1, "ps": 1,
                "injections": 2, "malfind": 2,
                "network": 3, "net": 3, "netscan": 3,
                "persistence": 4, "reg": 4, "tasks": 4,
                "kernel": 5, "report": 6,
            }.get(tok)
            if alias is None:
                raise ValueError(f"Unknown step token: {tok}")
            out.append(alias)
    # dedupe, preserve order
    seen = set(); dedup = []
    for v in out:
        if v not in seen:
            dedup.append(v); seen.add(v)
    return dedup

def _default_artifacts_dir(pipe: Pipeline, image_path: str) -> str:
    if hasattr(pipe, "_default_artifacts_dir"):
        return pipe._default_artifacts_dir(image_path)  
    base = os.path.splitext(os.path.abspath(image_path))[0]
    out = base + ".artifacts"
    os.makedirs(out, exist_ok=True)
    return out

def _init_pipeline(vol_path: str, default_renderer: str, timeout: Optional[int]) -> Pipeline:
    log.info("Init: vol.py=%s renderer=%s timeout=%s", vol_path, default_renderer, timeout)
    runner = VolRunner(vol_path=vol_path, default_timeout_s=timeout, default_renderer=default_renderer)
    registry: ExtractorRegistry = build_registry() if build_registry else ExtractorRegistry()
    return Pipeline(runner, registry)

def _wait_with_tqdm(label: str, fn, *args, **kwargs):
    t0 = time.perf_counter()
    if tqdm is None:
        log.info("%s …", label)
        res = fn(*args, **kwargs)
        dt = time.perf_counter() - t0
        log.info("%s ✓ done in %.2fs", label, dt)
        return res
    with tqdm(total=0, bar_format="{l_bar}{bar} {postfix}") as bar:
        bar.set_description_str(label); bar.set_postfix_str("running")
        res = fn(*args, **kwargs)
        bar.set_postfix_str("done")
    dt = time.perf_counter() - t0
    log.info("%s ✓ done in %.2fs", label, dt)
    return res

# ------------------------ CLI parser ------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="Volmemlyzer",
        description="Memory forensics CLI over Volatility 3: analysis, raw plugin runs, and feature extraction.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Global
    p.add_argument("--vol-path", default=None,
                   help="Path to volatility3 vol.py (optional; auto-detected if omitted)")
    p.add_argument("--renderer", default=os.getenv("VMY_RENDERER", "json"),
                   help=f"Renderer for raw plugin runs {sorted(_ALLOWED_RENDERERS)}")
    p.add_argument("--timeout", type=int, default=int(os.getenv("VMY_TIMEOUT", "0")) or None,
                   help="Per-plugin timeout seconds (0 disables)")
    p.add_argument("-j", "--jobs", type=int, default=1, #max(1, os.cpu_count() or 1),
                   help="Parallel workers for plugin execution")
    p.add_argument("--log-level", default=os.getenv("VMY_LOG", "INFO"),
                   choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
                   help="Set logging level for CLI and internals")
    p.add_argument("--set-vol", default=None, help= "Set the volatility path for the runtime")
    sub = p.add_subparsers(dest="mode", required=True)


    # Mode 1: analysis
    a = sub.add_parser("analyze", help="Run OverviewAnalysis workflow steps")
    a.add_argument("-i", "--image", required=True, help="Path to memory image")
    a.add_argument("-o", "--outdir", default=None, help="Artifacts directory (defaults near image)")
    a.add_argument("--steps", default=None, help="Comma list of steps (e.g. 0,1,2 or bearings,processes)")
    a.add_argument("--no-cache", action="store_true", help="Ignore cached plugin outputs")
    a.add_argument("--high-level", action="store_true",
                   help="Only surface high-risk findings when the analysis supports it")
    a.add_argument("--json", action="store_true", help="Write the summary to the outdir with json format")

    # Mode 2: run raw plugins
    r = sub.add_parser("run", help="Run raw Volatility plugins")
    r.add_argument("-i", "--image", required=True, help="Path to memory image")
    r.add_argument("-o", "--outdir", default=None, help="Artifacts directory")
    r.add_argument("--renderer", default= "json", help=f"Renderer for raw plugin runs {sorted(_ALLOWED_RENDERERS)}")
    r.add_argument("--plugins", default=None, help="Comma list of plugin names to run (e.g. pslist,psscan)")
    r.add_argument("--drop", default=None, help="Comma list of plugin names to exclude")
    r.add_argument("--no-cache", action="store_true", help="Ignore cached outputs")

    # Mode 3: extract features
    f = sub.add_parser("extract", help="Extract features for selected plugins via registry")
    f.add_argument("-i", "--image", required=True, help="Path to memory image")
    f.add_argument("-o", "--outdir", default=None, help="Artifacts directory")
    f.add_argument("-f", "--format", default=None, help="Output file format for features (json or csv)")
    f.add_argument("--plugins", default=None, help="Comma list to restrict extraction")
    f.add_argument("--drop", default=None, help="Comma list to exclude")
    f.add_argument("--no-cache", action="store_true", help="Ignore cached outputs")

    # Discoverability helpers
    l = sub.add_parser("list", help="List available plugins")
    l.add_argument("--vol", action="store_true", help="Show vol.py reported plugins")
    l.add_argument("--registry", action="store_true", help="Show registered extractors")
    l.add_argument("--grep", default=None, help="Filter names (case-insensitive substring)")
    l.add_argument("--max", type=int, default=200, help="Max items per column (0 = all)")
    return p

# ------------------------ pre-parse typo catcher ------------------------
def _gather_all_option_strings(parser: argparse.ArgumentParser) -> Set[str]:
    """Collect all short/long option strings across parser and its subparsers."""
    opts: Set[str] = set()
    for act in parser._actions:
        opts.update(act.option_strings)
        if isinstance(act, argparse._SubParsersAction):
            for sp in act.choices.values():
                for aa in sp._actions:
                    opts.update(aa.option_strings)
    return opts

def preparse_flag_lints(parser: argparse.ArgumentParser, argv: List[str]) -> None:
    """
    Catch obviously wrong flags *before* argparse raises.
    Suggest close matches for typos (e.g., --voll-path → --vol-path, --no-chache- → --no-cache).
    """
    known = _gather_all_option_strings(parser)
    bad: list[tuple[str, str | None]] = []
    tokens = [t for t in argv if t.startswith("-")]
    for tok in tokens:
        flag = tok.split("=")[0]
        if flag in known:
            continue

        trimmed = flag.rstrip("-")
        if trimmed in known:
            bad.append((flag, trimmed))
            continue
        cand = difflib.get_close_matches(flag, sorted(known), n=1, cutoff=0.6)
        bad.append((flag, cand[0] if cand else None))
    if bad:
        lines = []
        for b, sug in bad:
            if sug:
                lines.append(f"  {b}  →  did you mean {sug}?")
            else:
                lines.append(f"  {b}")
        parser.error("Unrecognized option(s):\n" + "\n".join(lines))

# ------------------------ argument validation ------------------------
def _usage_hint(mode: str) -> str:
    if mode == "run":
        return ('Example:\n'
                '  volmemlyzer --vol-path "C:\\Path\\to\\volatility3\\vol.py" --renderer json --timeout 600 -j 4 \\\n'
                '    run --image "D:\\Dumps\\host.vmem" --outdir "D:\\Dumps\\.volmemlyzer" \\\n'
                '    (--plugins pslist,pstree,psscan)/(--drop psscan) --no-cache')
    if mode == "extract":
        return ('Example:\n'
                '  volmemlyzer --vol-path "C:\\Path\\to\\volatility3\\vol.py" --renderer json -j 4 \\\n'
                '    extract --image "D:\\Dumps\\host.vmem" --outdir "D:\\Dumps\\.volmemlyzer" \\\n'
                '    (--plugins pslist,pstree,psscan) or (--drop psscan) --format "csv" --no-cache')
    # if mode == "list":
    #     return ('Example:\n'
    #             '  volmemlyzer --vol-path "C:\\Path\\to\\volatility3\\vol.py" --renderer json -j 4 \\\n'
    #             '    extract --image "D:\\Dumps\\host.vmem" --outdir "D:\\Dumps\\.volmemlyzer" \\\n'
    #             '    (--plugins pslist,pstree,psscan) or (--drop psscan) --format "csv" --no-cache')
    return ('Example:\n'
            '  volmemlyzer --vol-path "C:\\Path\\to\\volatility3\\vol.py" --renderer json --timeout 600 -j 4 \\\n'
            '    analyze --image "D:\\Dumps\\host.vmem" --outdir "D:\\Dumps\\.volmemlyzer" \\\n'
            '    --steps 0,1,2,3,4 --json --no-cache')

def handle_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """
    Validate user input, raise helpful errors (parser.error) with suggestions.
    """
    # Globals   


    if args.jobs < 1:
        parser.error("--jobs must be >= 1. Number of CPUs can not be less than zero!")
    if args.jobs > os.cpu_count():
        parser.error(f"--jobs must be less than the available number of CPUs: {os.cpu_count()}. Recommended Value is {max(1, (os.cpu_count() or 2) // 2)}")
    
    if args.timeout is not None and args.timeout < 1:
        parser.error("--timeout cannot be zero or negative")

    # vol.py path
    if args.vol_path and os.getenv("VOL_PATH") is None:
        is_vol_name = os.path.basename(args.vol_path).lower() == "vol.py"
        if not is_vol_name:
            # not fatal if they rely on PATH, but if it's a path and doesn't exist -> error
            if os.path.dirname(args.vol_path) and not os.path.exists(args.vol_path):
                parser.error(f"--vol-path does not exist: {args.vol_path}")
        elif not os.path.exists(args.vol_path):
            parser.error(f"--vol-path not found: {args.vol_path}")
        else:
            os.environ["VOL_PATH"] = args.vol_path or args.set_vol



    # Mode common
    if args.mode in {"analyze", "run"}:
        # MUST be a single file
        if not os.path.exists(args.image):
            parser.error(f"--image not found: {args.image}\n" + _usage_hint(args.mode))
        if not os.path.isfile(args.image):
            parser.error(f"--image is not a file: {args.image}\n" + _usage_hint(args.mode))

    elif args.mode == "extract":
        if not os.path.exists(args.image):
            parser.error(f"--image not found: {args.image}\n" + _usage_hint(args.mode))
        if not (os.path.isfile(args.image) or os.path.isdir(args.image)):
            parser.error(f"--image must be a file or a directory: {args.image}\n" + _usage_hint("extract"))
    
    # Mode-specific checks
    if args.mode == "analyze":
        if args.steps is not None:
            try:
                _steps_from_arg(args.steps)
            except ValueError as ve:
                parser.error(str(ve) + "\n" + _usage_hint("analyze"))

    if args.mode == "run":
        if getattr(args, "renderer", None):
            rr = args.renderer
            if rr and rr not in _ALLOWED_RENDERERS:
                sug = difflib.get_close_matches(rr, sorted(_ALLOWED_RENDERERS), n=1, cutoff=0.5)
                msg = f"run --renderer must be one of: {', '.join(sorted(_ALLOWED_RENDERERS))}"
                if sug:
                    msg += f"  (did you mean '{sug[0]}'?)"
                parser.error(msg)

    if args.mode == "extract":
        if not args.format:
            parser.error("--format is required (json or csv)\n" + _usage_hint("extract"))
        fmt = str(args.format).lower()
        if fmt not in {"json", "csv"}:
            sug = difflib.get_close_matches(fmt, ["json","csv"], n=1, cutoff=0.5)
            msg = "--format must be 'json' or 'csv'"
            if sug: msg += f"  (did you mean '{sug[0]}'?)"
            parser.error(msg)

    if args.mode == "list":
        if getattr(args, "max", None) is not None and args.max < 0:
            parser.error("--max must be >= 0 (0 means unlimited)")
        if getattr(args, "grep", None) is not None and not args.grep.strip():
            parser.error("--grep cannot be empty")

    # Suggest plugin name typos for run/extract
    if args.mode in {"run", "extract"}:
        intended = _parse_plugins(getattr(args, "plugins", None)) or set()
        dropped  = _parse_plugins(getattr(args, "drop", None)) or set()
        
        if intended and dropped:
            parser.error(f"Cannot set the enabled plugins and drop plugins simultaneously. Use either --plugins ... or --drop ...")
        
        if intended or dropped:
            pipe_tmp = _init_pipeline(args.vol_path, "json", args.timeout)
            known = set(pipe_tmp.registry.names())
            try:
                known |= set(pipe_tmp.runner.list_plugins())
            except Exception:
                pass
            errors = []
            def _suggest_one(name: str) -> str | None:
                cand = difflib.get_close_matches(name, sorted(known), n=1, cutoff=0.55)
                return cand[0] if cand else None
            for n in sorted(intended):
                if n not in known:
                    sug = _suggest_one(n)
                    errors.append(f"Unknown plugin '{n}'" + (f"  (did you mean '{sug}'?)" if sug else ""))
            for n in sorted(dropped):
                if n not in known:
                    sug = _suggest_one(n)
                    errors.append(f"Unknown drop plugin '{n}'" + (f"  (did you mean '{sug}'?)" if sug else ""))
            if errors:
                hint = _usage_hint(args.mode)
                parser.error("Plugin selection issues:\n  " + "\n  ".join(errors) + "\n" + hint)

# ------------------------ handlers ------------------------

def handle_analysis(args) -> int:
    pipe = _init_pipeline(args.vol_path, args.renderer, args.timeout)
    outdir = args.outdir or _default_artifacts_dir(pipe, args.image)
    steps = _steps_from_arg(args.steps)
    analysis_dir = os.path.join(outdir, "analysis")
    log.info("analyze: image=%s outdir=%s steps=%s cache=%s",
             args.image, outdir, (steps if steps is not None else "default"),
             "on" if not args.no_cache else "off")

    analysis = OverviewAnalysis()
    log.info("Running analysis (jobs= %s) …", args.jobs)
    res = analysis.run_steps(
        pipe=pipe,
        image_path=args.image,
        artifacts_dir=outdir,
        steps=steps,
        use_cache=(not args.no_cache),
        high_level=args.high_level,
    )
    if args.json:
        img_name = args.image.split("\\")[-1]
        analysis_file = os.path.join(analysis_dir, f"{img_name}.json")
        write_json(analysis_file, res)  
    return 0

def handle_run(args) -> int:
    pipe = _init_pipeline(args.vol_path, args.renderer, args.timeout)
    outdir = args.outdir or _default_artifacts_dir(pipe, args.image)
    enable = _parse_plugins(args.plugins)
    drop = _parse_plugins(args.drop) or None
    run_renderer = (args.renderer or getattr(args, "renderer_default", "json"))

    log.info("run: image=%s outdir=%s renderer=%s jobs=%d cache=%s",
             args.image, outdir, run_renderer, args.jobs, "on" if not args.no_cache else "off")
    if enable: log.info("run: plugins include=%s", ",".join(sorted(enable)))
    if drop:   log.info("run: plugins drop=%s", ",".join(sorted(drop)))

    ar = _wait_with_tqdm(
        f"Running plugins (jobs={args.jobs})",
        pipe.run_plugin_raw,
        image_path=args.image,
        enable=enable,
        drop=drop,
        renderer=run_renderer,
        outdir=outdir,
        concurrency=args.jobs,
        use_cache=(not args.no_cache),
    )

    print("[+] raw artifacts directory:", ar.artifacts.get("raw_dir"))
    for name, path in (ar.artifacts.get("plugins") or {}).items():
        print(f"  - {name:<20} → {path}")
    return 0


def handle_features(args) -> int:
    pipe = _init_pipeline(args.vol_path, "json", args.timeout)
    outdir = args.outdir or _default_artifacts_dir(pipe, args.image)
    feature_dir = os.path.join(outdir, "features")
    if not os.path.exists(feature_dir):
        os.makedirs(feature_dir)
    enable = _parse_plugins(args.plugins) or None
    drop = _parse_plugins(args.drop) or None

    log.info("extract: image=%s outdir=%s jobs=%d cache=%s",
            args.image, outdir, args.jobs, "on" if not args.no_cache else "off")
    
    if enable: log.info("extract: plugins include=%s", ",".join(sorted(enable)))
    if drop:   log.info("extract: plugins drop=%s", ",".join(sorted(drop)))

    if os.path.isdir(args.image):
        dumps = _get_dumps(os.path.abspath(args.image))
        if not dumps:
            log.warning("extract: no files found under directory: %s", args.image)
            return 0
        log.info("features extraction: batch over %d file(s) in %s (jobs=%d, cache=%s)",
            len(dumps), args.image, args.jobs, "on" if not args.no_cache else "off")
    else:
        dumps = [os.path.abspath(args.image)]
        log.info("features extraction for a single file: %s (jobs=%d, cache=%s)",
            args.image, args.jobs, "on" if not args.no_cache else "off")

    iter_entries = dumps if tqdm is None else tqdm(dumps, desc=f"features: {len(dumps)} file(s)")
    for img in iter_entries:
        row = _wait_with_tqdm(
            f"Extracting features (jobs={args.jobs})",
            pipe.run_extract_features,
            image_path=img,
            enable=enable,
            drop=drop,
            concurrency=args.jobs,
            artifacts_dir=outdir,
            use_cache=(not args.no_cache),
        )
        img_name = img.split("\\")[-1]
        feat_file = os.path.join(feature_dir, f"{img_name}.{args.format}")
        if args.format == 'csv':
            write_csv(feat_file, asdict(row))
        elif args.format == 'json':
            write_json(feat_file, asdict(row))
        else:
            raise ValueError(f"Unsupported feature file format {args.format}. Choose between json or csv.")
    
    log.info("extract: wrote features → %s", feature_dir)
    return 0

def handle_list(args) -> int:
    pipe = _init_pipeline(args.vol_path, "json", args.timeout)

    want_vol = args.vol or (not args.vol and not args.registry)
    want_reg = args.registry or (not args.vol and not args.registry)

    # Fetch
    try:
        vol = sorted(pipe.runner.list_plugins()) if want_vol else []
    except Exception as e:
        log.warning("list: failed to query vol.py plugins: %s", e)
        vol = []
    reg = sorted(pipe.registry.names()) if want_reg else []

    # Filter
    if args.grep:
        q = args.grep.lower()
        vol = [n for n in vol if q in n.lower()]
        reg = [n for n in reg if q in n.lower()]

    # Cap
    if args.max and args.max > 0:
        vol = vol[:args.max]
        reg = reg[:args.max]

    # Pretty table (Rich); fallback to plain text if Rich missing
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.box import SIMPLE

        console = Console(highlight=False)

        tbl = Table(box=SIMPLE, expand=True, show_header=True,
                    header_style="bold", pad_edge=False)
        if want_vol:
            tbl.add_column(f"Volatility3 plugins ({len(vol)}) as of {date.today()} ", style="cyan", ratio=1, overflow="fold")
        if want_reg:
            tbl.add_column(f"Available Plugins in VolmemLyzer registry ({len(reg)})", style="cyan", ratio=1, overflow="fold")

        rows = max(len(vol) if want_vol else 0, len(reg) if want_reg else 0)
        for i in range(rows):
            left  = vol[i] if (want_vol and i < len(vol)) else ""
            right = reg[i] if (want_reg and i < len(reg)) else ""
            if want_vol and want_reg:
                tbl.add_row(left, right)
            elif want_vol:
                tbl.add_row(left)
            else:
                tbl.add_row(right)

        console.print(Panel(tbl, title=f"Available Components", border_style="bright_blue"))
        if args.grep:
            console.print(f"[dim]Filter:[/dim] {args.grep}")
        if args.max and args.max > 0:
            console.print(f"[dim]Showing at most {args.max} per column.[/dim]")
    except Exception:
        # Plain fallback
        if want_vol:
            print(f"[vol.py] {len(vol)} plugin(s):")
            for n in vol:
                print("  -", n)
        if want_reg:
            print(f"[registry] {len(reg)} extractor(s):")
            for n in reg:
                print("  -", n)
        if not want_vol and not want_reg:
            print("Tip: use --registry and/or --vol")

    return 0



def show_help() -> None:
    """Compact top-level help: single wide 4-column table, minimal scrolling."""
    allowed = " | ".join(sorted(_ALLOWED_RENDERERS))
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        from rich.box import SIMPLE
    except Exception:
        import shutil
        w = shutil.get_terminal_size().columns
        print("VolMemLyzer — Memory forensics over Volatility 3".center(w))
        print("USAGE  volmemlyzer [GLOBAL OPTIONS] <command> [COMMAND OPTIONS]\n")
        print("[GLOBAL] --vol-path PATH | --renderer R | --timeout SEC | -j/--jobs N | --log-level L\n")
        print("[analyze]\n  -i/--image FILE (req) ; -o/--outdir DIR ; --steps LIST ; --no-cache ; --high-level ; --json\n")
        print("[run]\n  -i/--image FILE (req) ; -o/--outdir DIR ; --renderer R ; --plugins LIST ; --drop LIST ; --no-cache\n")
        print("[extract]\n  -i/--image PATH (req,file|dir) ; -o/--outdir DIR ; -f/--format FMT(json|csv, req) ; --plugins LIST ; --drop LIST ; --no-cache\n")
        print("[list]\n  --vol ; --registry")
        return

    c = Console()

    title = Text("VolMemLyzer", style="bold cyan")
    subtitle = Text("Memory forensics over Volatility 3", style="dim")
    c.print(Panel.fit(Text.assemble(title, Text("  —  "), subtitle),
                      border_style="cyan", padding=(1, 2)))

    c.print("USAGE  [bold]volmemlyzer[/] [dim][GLOBAL OPTIONS][/dim] <command> [dim][COMMAND OPTIONS][/dim]\n")

    globals_block = Text(
        "--vol-path [path]    Path to vol.py (optional)\n"
        f"--renderer [r]       Default raw renderer [{allowed}]\n"
        "--timeout [sec]      Per-plugin timeout (0 disables)\n"
        "-j, --jobs [n]       Parallel workers\n"
        "--log-level [L]      CRITICAL | ERROR | WARNING | INFO | DEBUG",
        no_wrap=False, overflow="fold"
    )
    c.print(Panel(globals_block, title="Global Options", border_style="bright_magenta", padding=(0, 1), expand= False))

    analyze_block = (
        "-i, --image FILE   required\n"
        "-o, --outdir DIR   artifacts dir\n"
        "--steps LIST       0–6 or aliases\n"
        "--no-cache         fresh runs\n"
        "--high-level       high-risk only\n"
        "--json             write analysis JSON"
    )
    run_block = (
        "-i, --image FILE   required\n"
        "-o, --outdir DIR   artifacts dir\n"
        f"--renderer R       {allowed}\n"
        "--plugins LIST     include\n"
        "--drop LIST        exclude\n"
        "--no-cache         ignore cache"
    )
    extract_block = (
        "-i, --image PATH   file or dir (required)\n"
        "-o, --outdir DIR   artifacts dir\n"
        "-f, --format FMT   json|csv (required)\n"
        "--plugins LIST     restrict\n"
        "--drop LIST        exclude\n"
        "--no-cache         ignore cache"
    )
    list_block = (
        "--vol              vol.py plugins\n"
        "--registry         extractors\n"
        "--grep STR         filter names\n"
        "--max N            cap per column\n"
        "--json             output JSON"
    )


    tbl = Table(box=SIMPLE, expand=True, show_header=True, header_style="bold", pad_edge=False)
    tbl.add_column("analyze", style="cyan", ratio=1, overflow="fold")
    tbl.add_column("run", style="cyan", ratio=1, overflow="fold")
    tbl.add_column("extract", style="cyan", ratio=1, overflow="fold")
    tbl.add_column("list", style="cyan", ratio=1, overflow="fold")
    tbl.add_row(analyze_block, run_block, extract_block, list_block)
    c.print(Panel(tbl, title="Command Options", border_style="green"))

# ------------------------ entrypoint ------------------------

def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if any(x in ("-h", "--help") for x in argv) and not any(x in {"analyze","run","extract","list"} for x in argv):
        show_help()
        return 0
    
    parser = build_parser()
    preparse_flag_lints(parser, sys.argv[1:] if argv is None else argv)

    args = parser.parse_args(argv)

    # Logging
    logging.basicConfig(
        level=getattr(logging, (args.log_level or "INFO").upper(), logging.INFO),
        format="[%(levelname)s] %(message)s",
    )
    log.debug("argv=%s", sys.argv)

    # Validate with suggestions
    handle_args(parser, args)

    try:
        if args.mode == "analyze":
            return handle_analysis(args)
        if args.mode == "run":
            return handle_run(args)
        if args.mode == "extract":
            return handle_features(args)
        if args.mode == "list":
            return handle_list(args)
        parser.error("unknown mode")
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130
    except Exception as e:
        log.exception("fatal error")
        print(f"[FATAL] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
