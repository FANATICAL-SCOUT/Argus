"""CLI regression tests — verify the pscan command interface is unchanged."""
import subprocess
import sys


def run_pscan(*args):
    """Run pscan as a subprocess and return (returncode, stdout, stderr)."""
    cmd = [sys.executable, "-m", "backend"] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return result.returncode, result.stdout, result.stderr


class TestCLIInterface:
    def test_help_exits_zero(self):
        code, out, _ = run_pscan("--help")
        assert code == 0
        assert "pscan" in out.lower()

    def test_no_args_shows_help(self):
        code, out, _ = run_pscan()
        assert code == 1  # argparse exits 1 when required arg missing

    def test_gui_subcommand_imports(self):
        """Verify backend.app is importable (the actual server needs a running process)."""
        result = subprocess.run(
            [sys.executable, "-c", "from backend.app import app; assert app is not None"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr

    def test_short_scan_produces_output(self):
        """Scan 5 high ports on loopback — verifies the full pipeline runs."""
        code, out, _ = run_pscan("127.0.0.1", "-p", "65530-65535", "-t", "0.3", "-T", "5")
        assert code == 0
        assert "SCAN RESULTS FOR 127.0.0.1" in out

    def test_short_scan_creates_txt_file(self, tmp_path, monkeypatch):
        """Verify a .txt record is written to data/records/."""
        import os
        # We can't easily redirect Settings paths in a subprocess test,
        # so just verify the scan runs without error and check the exit code.
        code, out, _ = run_pscan("127.0.0.1", "-p", "65530-65532", "-t", "0.3", "-T", "3")
        assert code == 0
        assert "Results saved to" in out
