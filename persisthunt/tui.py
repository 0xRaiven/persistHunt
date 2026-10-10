"""Security-oriented Terminal User Interface (TUI) for PersistHunt.

Provides high-visibility terminal telemetry dashboards, ANSI color-coded
forensic dossiers, and an interactive curses-based security console without
external dependencies (pure Python standard library).
"""

import os
import sys
import shutil
from typing import Optional, List, Dict, Any, Tuple
from persisthunt.findings import Finding, Severity
from persisthunt.reporting import ScanReport, TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION

# MITRE ATT&CK Framework mappings for persistence categories
MITRE_MAPPING: Dict[str, str] = {
    "cron": "T1053.003 (Scheduled Task/Job: Cron)",
    "systemd": "T1543.002 (System Process: Systemd Service)",
    "ssh": "T1098.004 (Account Manipulation: SSH Authorized Keys)",
    "shell": "T1546.004 (Event Triggered Execution: Shell Configuration)",
    "suid": "T1548.001 (Abuse Elevation Control: SUID/SGID)",
    "process": "T1059 / T1055 (Command Execution & Memory Masquerade)",
    "account": "T1136 / T1078 (Persistence: Local Account Backdoors)",
}

# ANSI Color & Style Palettes
class Theme:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    INVERT = "\033[7m"

    # Foregrounds
    CRIT_FG = "\033[1;91m"    # Bright Red
    HIGH_FG = "\033[1;38;5;208m" if os.environ.get("TERM", "") != "dumb" else "\033[1;31m"  # Orange / Red
    MED_FG = "\033[1;93m"     # Bright Yellow
    LOW_FG = "\033[1;96m"     # Bright Cyan
    INFO_FG = "\033[0;94m"    # Blue
    SAFE_FG = "\033[1;92m"    # Bright Green
    MUTED = "\033[0;90m"      # Dark Gray / Slate
    CYAN_ACCENT = "\033[1;36m"
    WHITE_BOLD = "\033[1;97m"

    # Severity Badges
    SEV_COLORS = {
        Severity.CRITICAL: "\033[1;97;41m",    # White on Red
        Severity.HIGH: "\033[1;97;48;5;202m" if os.environ.get("TERM", "") != "dumb" else "\033[1;31m",
        Severity.MEDIUM: "\033[1;30;43m",      # Black on Yellow
        Severity.LOW: "\033[1;30;46m",         # Black on Cyan
        Severity.INFO: "\033[1;97;44m",        # White on Blue
    }

class PlainTheme:
    RESET = ""
    BOLD = ""
    DIM = ""
    UNDERLINE = ""
    INVERT = ""
    CRIT_FG = ""
    HIGH_FG = ""
    MED_FG = ""
    LOW_FG = ""
    INFO_FG = ""
    SAFE_FG = ""
    MUTED = ""
    CYAN_ACCENT = ""
    WHITE_BOLD = ""
    SEV_COLORS = {
        Severity.CRITICAL: "",
        Severity.HIGH: "",
        Severity.MEDIUM: "",
        Severity.LOW: "",
        Severity.INFO: "",
    }


def should_use_color(force_color: Optional[bool] = None) -> bool:
    """Determine whether ANSI color sequences should be emitted."""
    if force_color is not None:
        return force_color
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def format_risk_bar(score: float, max_score: float = 10.0, width: int = 24, use_color: bool = True) -> str:
    """Generate a visual risk level meter with progress blocks."""
    ratio = max(0.0, min(1.0, score / max_score if max_score > 0 else 0))
    filled = int(round(ratio * width))
    empty = width - filled

    blocks = "█" * filled + "░" * empty

    t = Theme if use_color else PlainTheme
    if score >= 8.0:
        badge = f"{t.CRIT_FG}[ CRITICAL THREAT ]{t.RESET}"
        bar_color = t.CRIT_FG
    elif score >= 5.0:
        badge = f"{t.HIGH_FG}[ HIGH RISK ]{t.RESET}"
        bar_color = t.HIGH_FG
    elif score >= 2.5:
        badge = f"{t.MED_FG}[ ELEVATED ]{t.RESET}"
        bar_color = t.MED_FG
    elif score > 0.0:
        badge = f"{t.LOW_FG}[ LOW RISK ]{t.RESET}"
        bar_color = t.LOW_FG
    else:
        badge = f"{t.SAFE_FG}[ SECURE / CLEAN ]{t.RESET}"
        bar_color = t.SAFE_FG

    return f"{bar_color}[{blocks}]{t.RESET} {t.BOLD}{score:.1f}/{max_score:.1f}{t.RESET} {badge}"


def render_tui_dashboard(report: ScanReport, use_color: Optional[bool] = None, show_findings: bool = True) -> str:
    """Render an executive-grade terminal user interface dashboard."""
    color_enabled = should_use_color(use_color)
    t = Theme if color_enabled else PlainTheme

    term_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    box_width = min(max(term_width - 2, 72), 96)

    lines: List[str] = []

    # 1. Header Banner
    top_border = "╭" + "─" * (box_width - 2) + "╮"
    bot_border = "╰" + "─" * (box_width - 2) + "╯"
    div_border = "├" + "─" * (box_width - 2) + "┤"

    lines.append(f"{t.CYAN_ACCENT}{top_border}{t.RESET}")
    title_text = f" ⌖ {TOOL_NAME.upper()} v{TOOL_VERSION} │ {TOOL_DESCRIPTION.upper()}"
    lines.append(f"{t.CYAN_ACCENT}│{t.RESET}{t.WHITE_BOLD}{title_text.ljust(box_width - 2)}{t.RESET}{t.CYAN_ACCENT}│{t.RESET}")
    lines.append(f"{t.CYAN_ACCENT}{div_border}{t.RESET}")

    # 2. Host Metadata Row
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    priv_badge = f"{t.CRIT_FG}● ROOT [UID 0]{t.RESET}" if is_root else f"{t.LOW_FG}○ UNPRIVILEGED USER{t.RESET}"
    meta_line = (
        f" Host: {t.BOLD}{report.host}{t.RESET}  │  "
        f"Privilege: {priv_badge}  │  "
        f"Timestamp: {t.MUTED}{report.timestamp[:19]}Z{t.RESET}"
    )
    lines.append(f"{t.CYAN_ACCENT}│{t.RESET} {meta_line}")
    lines.append(f"{t.CYAN_ACCENT}{div_border}{t.RESET}")

    # 3. Threat Level & Risk Gauge
    max_score = report.risk_report.max_score if report.risk_report else 10.0
    risk_bar_str = format_risk_bar(report.risk_score, max_score, width=20, use_color=color_enabled)
    lines.append(f"{t.CYAN_ACCENT}│{t.RESET}  {t.BOLD}THREAT LEVEL METER:{t.RESET}  {risk_bar_str}")

    # 4. Severity Distribution Pills
    sev_counts = report.statistics.get("severity_counts", {})
    pills = [
        f"{t.CRIT_FG}CRITICAL: {sev_counts.get('CRITICAL', 0)}{t.RESET}",
        f"{t.HIGH_FG}HIGH: {sev_counts.get('HIGH', 0)}{t.RESET}",
        f"{t.MED_FG}MEDIUM: {sev_counts.get('MEDIUM', 0)}{t.RESET}",
        f"{t.LOW_FG}LOW: {sev_counts.get('LOW', 0)}{t.RESET}",
        f"{t.INFO_FG}INFO: {sev_counts.get('INFO', 0)}{t.RESET}",
    ]
    lines.append(f"{t.CYAN_ACCENT}│{t.RESET}  {t.BOLD}FINDINGS SUMMARY  :{t.RESET}  " + "  │  ".join(pills))
    lines.append(f"{t.CYAN_ACCENT}{div_border}{t.RESET}")

    # 5. Subsystem Telemetry Status Table
    lines.append(f"{t.CYAN_ACCENT}│{t.RESET}  {t.BOLD}PERSISTENCE VECTOR TELEMETRY MATRIX:{t.RESET}")
    det_status = report.detector_status or {}
    standard_vectors = ["cron", "systemd", "ssh", "shell", "suid", "process", "account"]

    for vec in standard_vectors:
        st_info = det_status.get(vec, {})
        status_text = st_info.get("status", "successful")
        f_count = st_info.get("findings_count", 0)

        if status_text == "successful":
            st_badge = f"{t.SAFE_FG}✓ SUCCESSFUL{t.RESET}"
        elif status_text == "permission-limited":
            st_badge = f"{t.MED_FG}⚠ PERM-LIMITED{t.RESET}"
        else:
            st_badge = f"{t.CRIT_FG}✗ FAILED{t.RESET}"

        count_badge = f"{t.CRIT_FG if f_count > 0 else t.MUTED}{f_count:>2} findings{t.RESET}"
        mitre_ref = MITRE_MAPPING.get(vec, "Persistence")

        row = f"  • {vec.upper():<8} │ {st_badge:<14} │ {count_badge} │ {t.MUTED}{mitre_ref}{t.RESET}"
        lines.append(f"{t.CYAN_ACCENT}│{t.RESET}{row}")

    lines.append(f"{t.CYAN_ACCENT}{bot_border}{t.RESET}")

    # 6. Detailed Finding Dossier Feed
    if show_findings and report.findings:
        lines.append("")
        header_text = f"=== FORENSIC FINDING DOSSIER ({len(report.findings)} DETECTED) ==="
        lines.append(f"{t.WHITE_BOLD}{header_text}{t.RESET}")

        for idx, f in enumerate(report.findings, 1):
            sev_color = t.SEV_COLORS.get(f.severity, "")
            sev_badge = f"{sev_color} {f.severity.value} {t.RESET}" if color_enabled else f"[{f.severity.value}]"
            mitre_id = MITRE_MAPPING.get(f.category, f.category.upper())

            c_top = f"┌── {sev_badge} {t.WHITE_BOLD}{f.id}{t.RESET} ── {t.BOLD}{f.title}{t.RESET} "
            c_top = c_top + "─" * max(0, box_width - len(f"{f.severity.value} {f.id} {f.title}") - 10) + "┐"
            lines.append(f"\n{t.CYAN_ACCENT}{c_top}{t.RESET}")

            lines.append(f"{t.CYAN_ACCENT}│{t.RESET}  {t.BOLD}Vector    :{t.RESET} {f.category}  ({t.MUTED}{mitre_id}{t.RESET})")
            if f.location:
                lines.append(f"{t.CYAN_ACCENT}│{t.RESET}  {t.BOLD}Location  :{t.RESET} {t.UNDERLINE}{f.location}{t.RESET}")
            lines.append(f"{t.CYAN_ACCENT}│{t.RESET}  {t.BOLD}Impact    :{t.RESET} {f.description}")

            if f.evidence:
                ev_str = str(f.evidence).strip().replace("\n", " ")
                if len(ev_str) > box_width - 18:
                    ev_str = ev_str[:box_width - 21] + "..."
                lines.append(f"{t.CYAN_ACCENT}│{t.RESET}  {t.BOLD}Evidence  :{t.RESET} {t.CRIT_FG}{ev_str}{t.RESET}")

            if f.recommendation:
                lines.append(f"{t.CYAN_ACCENT}│{t.RESET}  {t.BOLD}Action    :{t.RESET} {t.SAFE_FG}{f.recommendation}{t.RESET}")

            lines.append(f"{t.CYAN_ACCENT}└" + "─" * (box_width - 2) + f"┘{t.RESET}")

    elif not report.findings:
        lines.append("")
        lines.append(f"{t.SAFE_FG}[✓] CLEAN SCAN: No persistence footholds or unauthorized anomalies discovered.{t.RESET}")

    return "\n".join(lines)


def launch_interactive_tui(report: ScanReport) -> int:
    """Launch full-screen curses interactive security browser."""
    try:
        import curses
    except ImportError:
        # Graceful fallback to rich console output when curses is missing
        sys.stdout.write(render_tui_dashboard(report, use_color=True) + "\n")
        return 0

    def _curses_main(stdscr) -> int:
        curses.curs_set(0)
        stdscr.timeout(100)

        # Initialize color pairs if supported
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_RED, -1)      # CRITICAL
            curses.init_pair(2, curses.COLOR_YELLOW, -1)   # HIGH / MEDIUM
            curses.init_pair(3, curses.COLOR_CYAN, -1)     # LOW
            curses.init_pair(4, curses.COLOR_BLUE, -1)     # INFO
            curses.init_pair(5, curses.COLOR_GREEN, -1)    # SAFE
            curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_WHITE) # SELECTED

        selected_idx = 0
        filter_sev: Optional[Severity] = None
        filter_options = [None, Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        filter_idx = 0

        while True:
            max_y, max_x = stdscr.getmaxyx()
            stdscr.clear()

            if max_y < 12 or max_x < 50:
                stdscr.addstr(0, 0, "Terminal window too small for interactive TUI. Resize window.")
                stdscr.refresh()
                key = stdscr.getch()
                if key in (ord('q'), ord('Q')):
                    break
                continue

            # Filter findings
            if filter_sev:
                display_findings = [f for f in report.findings if f.severity == filter_sev]
            else:
                display_findings = list(report.findings)

            if selected_idx >= len(display_findings) and display_findings:
                selected_idx = len(display_findings) - 1
            if not display_findings:
                selected_idx = 0

            # 1. Header Bar
            header_str = f" PERSISTHUNT v{TOOL_VERSION} │ Host: {report.host} │ Score: {report.risk_score:.1f}/10.0 │ Findings: {len(report.findings)}"
            stdscr.attron(curses.A_BOLD)
            stdscr.addnstr(0, 0, header_str.ljust(max_x), max_x)
            stdscr.attroff(curses.A_BOLD)

            # Filter indicator
            filt_name = filter_sev.value if filter_sev else "ALL"
            filter_bar = f" Filter: [{filt_name}] (Press Tab to cycle) │ Total in view: {len(display_findings)}"
            stdscr.addnstr(1, 0, filter_bar.ljust(max_x), max_x)
            stdscr.addstr(2, 0, "─" * max_x)

            # Split pane layout: Left pane (35% width), Right pane (65% width)
            left_width = min(max(32, int(max_x * 0.35)), 45)
            right_width = max_x - left_width - 3

            # Draw Vertical Separator
            for y in range(3, max_y - 2):
                stdscr.addch(y, left_width + 1, '│')

            # Render Left List
            list_height = max_y - 6
            start_idx = max(0, selected_idx - list_height // 2)
            end_idx = min(len(display_findings), start_idx + list_height)

            for i in range(start_idx, end_idx):
                f = display_findings[i]
                y = 3 + (i - start_idx)
                is_sel = (i == selected_idx)

                prefix = "▶ " if is_sel else "  "
                item_label = f"{prefix}[{f.severity.value[:4]}] {f.id}"

                if is_sel:
                    stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
                    stdscr.addnstr(y, 1, item_label.ljust(left_width), left_width)
                    stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)
                else:
                    cp = 2
                    if f.severity == Severity.CRITICAL:
                        cp = 1
                    elif f.severity == Severity.LOW:
                        cp = 3
                    elif f.severity == Severity.INFO:
                        cp = 4
                    stdscr.attron(curses.color_pair(cp))
                    stdscr.addnstr(y, 1, item_label.ljust(left_width), left_width)
                    stdscr.attroff(curses.color_pair(cp))

            if not display_findings:
                stdscr.addstr(4, 2, "No findings match filter.")

            # Render Right Detail View
            if display_findings and 0 <= selected_idx < len(display_findings):
                f = display_findings[selected_idx]
                ry = 3
                rx = left_width + 3

                stdscr.attron(curses.A_BOLD)
                stdscr.addnstr(ry, rx, f"[{f.severity.value}] {f.id} - {f.title}", right_width)
                stdscr.attroff(curses.A_BOLD)
                ry += 2

                mitre_tag = MITRE_MAPPING.get(f.category, f.category)
                stdscr.addnstr(ry, rx, f"Category   : {f.category} ({mitre_tag})", right_width); ry += 1
                if f.location:
                    stdscr.addnstr(ry, rx, f"Location   : {f.location}", right_width); ry += 1

                ry += 1
                stdscr.attron(curses.A_BOLD)
                stdscr.addnstr(ry, rx, "Description:", right_width)
                stdscr.attroff(curses.A_BOLD)
                ry += 1
                # Wrap description
                words = f.description.split()
                line = ""
                for w in words:
                    if len(line) + len(w) + 1 <= right_width:
                        line += (" " if line else "") + w
                    else:
                        if ry < max_y - 5:
                            stdscr.addnstr(ry, rx + 2, line, right_width)
                            ry += 1
                        line = w
                if line and ry < max_y - 5:
                    stdscr.addnstr(ry, rx + 2, line, right_width); ry += 1

                if f.evidence:
                    ry += 1
                    stdscr.attron(curses.A_BOLD)
                    stdscr.addnstr(ry, rx, "Evidence   :", right_width)
                    stdscr.attroff(curses.A_BOLD)
                    ry += 1
                    stdscr.addnstr(ry, rx + 2, str(f.evidence)[:right_width - 4], right_width - 2)
                    ry += 1

                if f.recommendation:
                    ry += 1
                    stdscr.attron(curses.A_BOLD | curses.color_pair(5))
                    stdscr.addnstr(ry, rx, "Remediation:", right_width)
                    stdscr.attroff(curses.A_BOLD | curses.color_pair(5))
                    ry += 1
                    stdscr.addnstr(ry, rx + 2, f.recommendation[:right_width - 4], right_width - 2)

            # Footer Status Bar
            stdscr.addstr(max_y - 2, 0, "─" * max_x)
            status_text = " [↑/↓] Navigate  │  [Tab] Cycle Filter  │  [q] Exit  │  [e] Export JSON"
            stdscr.attron(curses.A_DIM)
            stdscr.addnstr(max_y - 1, 0, status_text.ljust(max_x), max_x)
            stdscr.attroff(curses.A_DIM)

            stdscr.refresh()

            # Handle user keyboard inputs
            key = stdscr.getch()
            if key in (ord('q'), ord('Q'), 27):  # 'q' or ESC
                break
            elif key in (curses.KEY_UP, ord('k'), ord('K')):
                if selected_idx > 0:
                    selected_idx -= 1
            elif key in (curses.KEY_DOWN, ord('j'), ord('J')):
                if selected_idx < len(display_findings) - 1:
                    selected_idx += 1
            elif key in (ord('\t'),):  # Tab key cycles filter
                filter_idx = (filter_idx + 1) % len(filter_options)
                filter_sev = filter_options[filter_idx]
                selected_idx = 0
            elif key in (ord('e'), ord('E')):
                report.save_json(Path("audit_report.json"))
                stdscr.addstr(max_y - 1, 0, " [✓] Saved audit_report.json!".ljust(max_x))
                stdscr.refresh()
                curses.napms(800)

        return 0

    try:
        return curses.wrapper(_curses_main)
    except Exception:
        # Fallback to rich dashboard on any terminal environment issue
        sys.stdout.write(render_tui_dashboard(report, use_color=True) + "\n")
        return 0
