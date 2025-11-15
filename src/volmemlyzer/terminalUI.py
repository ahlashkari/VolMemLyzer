# terminalUI.py
from typing import List, Any, Tuple
import shutil, os

from rich.console import Console
from rich.table import Table
from rich import box


class TerminalUI:
    # ---------- visuals & layout ----------
    SAFETY_MARGIN: float = 0.95
    RICH_BOX: str = "SIMPLE"         # SIMPLE | ASCII | SQUARE | MINIMAL | SIMPLE_HEAD | HEAVY
    RICH_SHOW_LINES: bool = True     # horizontal rules between rows (solid)
    RICH_SHOW_EDGE: bool = False     # no outer frame (fits your UI vibe)
    RICH_PADDING: Tuple[int, int] = (0, 1)  # (left, right) padding inside cells
    _console: Console = Console(record=True, no_color=True)

    # Left accent bar
    ACCENT_CHAR: str = "▌"
    COLOR_HIGH: str = "red3"
    COLOR_MED: str = "dark_orange3"
    COLOR_LOW: str = "green3"
    COLOR_DEFAULT: str = "grey50"

    # ---------- unchanged helpers ----------
    @staticmethod
    def banner(title: str):
        w = shutil.get_terminal_size((120, 20)).columns
        print("═" * w)
        print(TerminalUI.center(title, w))
        print("═" * w)

    @staticmethod
    def section(title: str):
        w = shutil.get_terminal_size((120, 20)).columns
        print("\n" + "─" * w)
        print(TerminalUI.center(title, w))
        print("─" * w)

    @staticmethod
    def subsection(title: str):
        """
        Lightweight heading beneath a section, used to label multiple tables in one step.
        Keeps the same centered style as `section` but without the horizontal rules.
        """
        w = shutil.get_terminal_size((120, 20)).columns
        print("")  # blank line for breathing room
        print(TerminalUI.center(title, w))

    @staticmethod
    def kv(pairs: List[Tuple[str, Any]]):
        left = max((len(k) for k, _ in pairs), default=10)
        for k, v in pairs:
            print(f"  {k.ljust(left)} : {v}")

    @staticmethod
    def note(msg: str):
        print(f"  • {msg}")

    @staticmethod
    def center(s: str, width: int) -> str:
        s = f" {s} "
        pad = max(0, (width - len(s)) // 2)
        return (" " * pad) + s

    # ---------- Rich-based table with left accent bar ----------
    @staticmethod
    def table(headers: List[str], rows: List[List[str]], max_rows: int = 15):
        if not rows:
            TerminalUI.note("No rows to display.")
            return []

        ncols = len(headers)
        if ncols == 0:
            TerminalUI.note("No headers provided.")
            return []

        # Terminal width & safety margin
        term_w = shutil.get_terminal_size((120, 20)).columns
        w = max(20, int(term_w * TerminalUI.SAFETY_MARGIN))

        # Normalize rows to header count
        norm_rows: List[List[str]] = []
        for r in rows:
            r = [str(x) for x in r]
            norm_rows.append(r + [""] * (ncols - len(r)) if len(r) < ncols else r[:ncols])
        shown = norm_rows[:max_rows]

        # Effective column count includes the accent bar column
        ncols_eff = ncols + 1

        # Account for Rich separators (1 char each) and padding
        sep_count = ncols_eff - 1
        sep_width = sep_count * 1
        pad_left, pad_right = TerminalUI.RICH_PADDING
        pad_total = (pad_left + pad_right) * ncols_eff

        available = max(1, w - sep_width - pad_total)

        # --- sizing logic (same spirit as your custom) ---
        SOFT_MIN, HARD_MIN = 6, 3
        mins = [max(SOFT_MIN, len(str(h))) for h in headers]

        # Longest content per column (headers + shown rows)
        content_max = [len(str(headers[i])) for i in range(ncols)]
        for r in shown:
            for i in range(ncols):
                content_max[i] = max(content_max[i], len(str(r[i])))

        # Cap non-rationale columns to what they actually need; donate slack to rationale
        ideals_first = [max(mins[i], content_max[i]) for i in range(ncols - 1)]
        last_base = max(mins[-1], int(available * 0.40))
        first_sum = sum(ideals_first)

        if first_sum + last_base <= available:
            first_widths = ideals_first
            last_w = available - sum(first_widths)
        else:
            to_reduce = first_sum + last_base - available
            reducible = [max(0, ideals_first[i] - mins[i]) for i in range(ncols - 1)]
            red_total = sum(reducible)
            first_widths = ideals_first[:]

            if red_total > 0:
                # proportional reduction towards mins
                reductions = [(to_reduce * reducible[i]) // red_total for i in range(ncols - 1)]
                for i in range(ncols - 1):
                    first_widths[i] = max(mins[i], first_widths[i] - reductions[i])
                leftover_cut = to_reduce - sum(reductions)
                order = sorted(range(ncols - 1), key=lambda i: first_widths[i] - mins[i], reverse=True)
                idx = 0
                while leftover_cut > 0 and any(first_widths[j] > mins[j] for j in range(ncols - 1)):
                    j = order[idx % (ncols - 1)]
                    if first_widths[j] > mins[j]:
                        first_widths[j] -= 1
                        leftover_cut -= 1
                    idx += 1

            last_w = available - sum(first_widths)
            if last_w < mins[-1]:
                need = mins[-1] - last_w
                i = 0
                while need > 0 and any(first_widths[j] > max(HARD_MIN, mins[j]) for j in range(ncols - 1)):
                    j = i % (ncols - 1)
                    floor_j = max(HARD_MIN, mins[j])
                    if first_widths[j] > floor_j:
                        first_widths[j] -= 1
                        need -= 1
                    i += 1
                last_w = available - sum(first_widths)
                if last_w < HARD_MIN:
                    first_widths = [HARD_MIN] * (ncols - 1)
                    last_w = max(HARD_MIN, available - sum(first_widths))

        data_widths = first_widths + [last_w]  # excludes accent column

        # --- build Rich table ---
        box_map = {
            "SIMPLE": box.SIMPLE,
            "ASCII": box.ASCII,
            "SQUARE": box.SQUARE,
            "MINIMAL": box.MINIMAL,
            "SIMPLE_HEAD": box.SIMPLE_HEAD,
            "HEAVY": box.HEAVY,
        }
        chosen_box = box_map.get(TerminalUI.RICH_BOX, box.SIMPLE)

        t = Table(
            show_header=True,
            header_style="bold",      # keep headers white/bold (no color)
            box=chosen_box,
            show_lines=TerminalUI.RICH_SHOW_LINES,
            show_edge=TerminalUI.RICH_SHOW_EDGE,
            padding=TerminalUI.RICH_PADDING,
            expand=False,             # we control width
        )

        # 1) Accent column (fixed width 1, no padding inflation thanks to global calc)
        t.add_column("", min_width=1, max_width=1, no_wrap=True, overflow="crop", justify="left")

        # 2) Data columns (keep content white; rationale column stays unstyled)
        for i, (h, cw) in enumerate(zip(headers, data_widths)):
            t.add_column(str(h), min_width=mins[i], max_width=cw, overflow="fold", no_wrap=False, justify="left")

        # Determine risk column index (best-effort)
        risk_idx = TerminalUI._find_risk_col(headers)

        # Add rows with accent bar colored by risk; keep other cells unstyled (white)
        for r in shown:
            level = TerminalUI._classify_risk(risk_idx, r)
            color = TerminalUI._accent_color(level)
            accent = f"[{color}]{TerminalUI.ACCENT_CHAR}[/]"
            t.add_row(accent, *[str(x) for x in r])

        Console().print(t, width=w)  # hard cap to our safety width
        return shown

    # ---------- helpers for risk accent ----------
    @staticmethod
    def _find_risk_col(headers: List[str]) -> int:
        names = [str(h).strip().lower() for h in headers]
        for key in ("risk", "severity"):
            if key in names:
                return names.index(key)
        # numeric scores
        for key in ("risk_score", "score", "severity_score"):
            if key in names:
                return names.index(key)
        return -1

    @staticmethod
    def _classify_risk(risk_idx: int, row: List[str]) -> str:
        if risk_idx < 0 or risk_idx >= len(row):
            return "default"
        val = str(row[risk_idx]).strip().lower()

        # text labels
        if any(x in val for x in ("critical", "high", "elevated")):
            return "high"
        if "medium" in val or "moderate" in val:
            return "med"
        if "low" in val:
            return "low"

        # numeric scores: try %, 0..1, 0..100, or X/Y
        try:
            if "/" in val:
                num, den = val.split("/", 1)
                score = float(num) / max(1.0, float(den))
            else:
                v = val.replace("%", "")
                score = float(v)
                score = score / 100.0 if score > 1.0 else score
            if score >= 0.66:
                return "high"
            if score >= 0.33:
                return "med"
            return "low"
        except Exception:
            return "default"

    @staticmethod
    def _accent_color(level: str) -> str:
        if level == "high":
            return TerminalUI.COLOR_HIGH
        if level == "med":
            return TerminalUI.COLOR_MED
        if level == "low":
            return TerminalUI.COLOR_LOW
        return TerminalUI.COLOR_DEFAULT

    @classmethod
    def console(cls) -> Console:
        return cls._console

    @classmethod
    def export_text(cls) -> str:
        # exact textual rendering of everything printed so far
        return cls._console.export_text(clear=False)

    @classmethod
    def save_text(cls, path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(cls.export_text())
        return path