"""End-to-end tests for SHROUD.

Covers the full flow for BOTH engines (protect demo -> run original vs
protected -> outputs identical) and runs the README quickstart commands
verbatim as subprocesses. The quickstart commands are copied exactly
from README.md; if the README changes, update QUICKSTART_COMMANDS here
to match, and vice versa.
"""

import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from shroud.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "shroud" / "demo"

# Verbatim README quickstart commands (run from the repo root).
QUICKSTART_COMMANDS = [
    "python3 -m shroud demo",
    "python3 -m shroud protect shroud/demo/demo.js --engine js "
    "--out /tmp/shroud-demo/protected-js",
    "node /tmp/shroud-demo/protected-js/demo.js",
    "python3 -m shroud verify shroud/demo/demo.js "
    "/tmp/shroud-demo/protected-js/demo.js",
    "python3 -m shroud protect shroud/demo/demo.py --engine py "
    "--out /tmp/shroud-demo/protected-py",
    "python3 /tmp/shroud-demo/protected-py/demo.py",
    "python3 -m shroud verify shroud/demo/demo.py "
    "/tmp/shroud-demo/protected-py/demo.py",
    "python3 -m shroud inspect /tmp/shroud-demo/protected-js/demo.js",
]


def run_file(path):
    """Run a demo file with the right interpreter; return the result."""
    if str(path).endswith(".js"):
        cmd = ["node", str(path)]
    else:
        cmd = [sys.executable, str(path)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


class TestEndToEnd(unittest.TestCase):
    def _protect_and_compare(self, engine):
        suffix = "js" if engine == "js" else "py"
        original = DEMO_DIR / ("demo.%s" % suffix)
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            code = main(
                [
                    "protect", str(original), "--engine", engine,
                    "--out", str(out_dir),
                ]
            )
            self.assertEqual(code, 0)
            protected = out_dir / ("demo.%s" % suffix)
            self.assertTrue(protected.is_file())
            before = run_file(original)
            after = run_file(protected)
            self.assertEqual(after.stdout, before.stdout)
            self.assertEqual(after.stderr, before.stderr)
            self.assertEqual(after.returncode, before.returncode)
            self.assertEqual(after.returncode, 0)

    def test_e2e_js_demo(self):
        self._protect_and_compare("js")

    def test_e2e_py_demo(self):
        self._protect_and_compare("py")

    def test_e2e_protect_directory_both_engines(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            code = main(
                ["protect", str(DEMO_DIR), "--out", str(out_dir)]
            )
            self.assertEqual(code, 0)
            for suffix in ("js", "py"):
                original = DEMO_DIR / ("demo.%s" % suffix)
                protected = out_dir / ("demo.%s" % suffix)
                self.assertTrue(protected.is_file())
                before = run_file(original)
                after = run_file(protected)
                self.assertEqual(after.stdout, before.stdout)
                self.assertEqual(after.returncode, 0)
            self.assertTrue((out_dir / "shroud_runtime.py").is_file())

    def test_readme_quickstart_commands_verbatim(self):
        for command in QUICKSTART_COMMANDS:
            result = subprocess.run(
                shlex.split(command),
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(
                result.returncode, 0,
                "quickstart command failed: %s\nstdout: %s\nstderr: %s"
                % (command, result.stdout, result.stderr),
            )
            if command.startswith("python3 -m shroud verify"):
                self.assertIn("PASS", result.stdout, command)
            if command == "python3 -m shroud demo":
                self.assertIn("JavaScript demo: MATCH", result.stdout)
                self.assertIn("Python demo: MATCH", result.stdout)


if __name__ == "__main__":
    unittest.main()
