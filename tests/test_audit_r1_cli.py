"""Regression tests for SHROUD audit round 1 — CLI + packaging (H6, H7, M5).

One test per finding. These tests were written against the unfixed
code and confirmed to FAIL there before the fixes landed in
``shroud/cli.py``.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from shroud.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent

SMALL_PY_A = "print('aaa')\n"
SMALL_PY_B = "print('bbb')\n"


def run_main(argv):
    """Run main() with captured streams; return (exit_code, out, err)."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def run_py_file(path, out_dir):
    """Run a protected .py file with the output dir on PYTHONPATH so
    the sibling ``shroud_runtime`` module is importable."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(out_dir)
    return subprocess.run(
        [sys.executable, str(path)], capture_output=True, text=True,
        timeout=30, env=env,
    )


class TestH6DirectoryProtectPreservesTree(unittest.TestCase):
    def test_nested_same_name_files_both_survive_and_run(self):
        # H6: src/x/util.py + src/y/util.py used to collide into one
        # out/util.py whose content failed the integrity check.
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            (src_dir / "x").mkdir(parents=True)
            (src_dir / "y").mkdir(parents=True)
            (src_dir / "x" / "util.py").write_text(
                "print('util-x')\n", encoding="utf-8"
            )
            (src_dir / "y" / "util.py").write_text(
                "print('util-y')\n", encoding="utf-8"
            )
            out_dir = Path(tmp) / "out"
            code, out, err = run_main(
                ["protect", str(src_dir), "--out", str(out_dir)]
            )
            self.assertEqual(code, 0, err)
            self.assertIn("Protected 2 file(s)", out)
            x_util = out_dir / "x" / "util.py"
            y_util = out_dir / "y" / "util.py"
            self.assertTrue(x_util.is_file(), "x/util.py missing")
            self.assertTrue(y_util.is_file(), "y/util.py missing")
            rx = run_py_file(x_util, out_dir)
            self.assertEqual(rx.returncode, 0, rx.stderr)
            self.assertEqual(rx.stdout, "util-x\n")
            ry = run_py_file(y_util, out_dir)
            self.assertEqual(ry.returncode, 0, ry.stderr)
            self.assertEqual(ry.stdout, "util-y\n")

    def test_nested_directory_layout_is_mirrored(self):
        # H6: a nested layout must be mirrored, not flattened — for
        # both engines (the JS engine does not create parent dirs
        # itself, so the CLI must).
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            (src_dir / "deep" / "nested").mkdir(parents=True)
            (src_dir / "deep" / "nested" / "mod.js").write_text(
                "function f() { return 42; }\nconsole.log(f());\n",
                encoding="utf-8",
            )
            (src_dir / "top.py").write_text("print('top')\n", encoding="utf-8")
            out_dir = Path(tmp) / "out"
            code, _out, err = run_main(
                ["protect", str(src_dir), "--out", str(out_dir)]
            )
            self.assertEqual(code, 0, err)
            self.assertTrue(
                (out_dir / "deep" / "nested" / "mod.js").is_file(),
                "nested JS file was not mirrored",
            )
            self.assertTrue((out_dir / "top.py").is_file())
            result = subprocess.run(
                ["node", str(out_dir / "deep" / "nested" / "mod.js")],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.stdout, "42\n")
            self.assertEqual(result.returncode, 0, result.stderr)


class TestH7ManifestCoversAllFiles(unittest.TestCase):
    def _protect_two_files(self, tmp):
        src_dir = Path(tmp) / "src"
        src_dir.mkdir()
        (src_dir / "a.py").write_text(SMALL_PY_A, encoding="utf-8")
        (src_dir / "b.py").write_text(SMALL_PY_B, encoding="utf-8")
        out_dir = Path(tmp) / "out"
        code, _out, err = run_main(
            ["protect", str(src_dir), "--out", str(out_dir)]
        )
        self.assertEqual(code, 0, err)
        return out_dir

    def test_multi_file_manifest_lists_every_protected_file(self):
        # H7: the manifest used to be written after the FIRST file, so
        # it listed only a.py.
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = self._protect_two_files(tmp)
            manifest_path = out_dir / ".shroud_manifest.json"
            self.assertTrue(manifest_path.is_file())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertIn("a.py", manifest)
            self.assertIn("b.py", manifest)

    def test_tampering_second_file_is_detected(self):
        # H7: appending to b.py used to run cleanly because b.py was
        # never in the manifest.
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = self._protect_two_files(tmp)
            tampered = out_dir / "b.py"
            with tampered.open("a", encoding="utf-8") as fh:
                fh.write("print('TAMPERED-RAN')\n")
            result = run_py_file(tampered, out_dir)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("integrity check failed", result.stderr)
            self.assertNotIn("TAMPERED-RAN", result.stdout)


class TestM5CleanErrors(unittest.TestCase):
    def test_protect_out_dir_is_existing_file(self):
        # M5 (CLI half): --out pointing at an existing file used to
        # raise an uncaught FileExistsError traceback.
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "small.py"
            src.write_text("print('hi')\n", encoding="utf-8")
            out_file = Path(tmp) / "out"
            out_file.write_text("i am a file, not a dir", encoding="utf-8")
            code, _out, err = run_main(
                ["protect", str(src), "--out", str(out_file)]
            )
            self.assertEqual(code, 1)
            self.assertTrue(err.startswith("Error:"), err)
            self.assertNotIn("Traceback", err)

    def test_protect_non_utf8_py_input(self):
        # M5 (CLI half): a latin-1-encoded .py file used to raise an
        # uncaught UnicodeDecodeError traceback.
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "latin.py"
            src.write_bytes(b"# caf\xe9\nprint('hi')\n")
            out_dir = Path(tmp) / "out"
            code, _out, err = run_main(
                ["protect", str(src), "--engine", "py", "--out", str(out_dir)]
            )
            self.assertEqual(code, 1)
            self.assertTrue(err.startswith("Error:"), err)
            self.assertNotIn("Traceback", err)

    def test_inspect_unreadable_file_reports_clean_error(self):
        # M5 (CLI half): inspect must report a clean Error: + exit 1
        # when reading the file fails.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "protected.js"
            target.write_text("console.log(1);\n", encoding="utf-8")
            with mock.patch.object(
                Path, "read_text", side_effect=OSError("boom")
            ):
                code, _out, err = run_main(["inspect", str(target)])
            self.assertEqual(code, 1)
            self.assertTrue(err.startswith("Error:"), err)
            self.assertNotIn("Traceback", err)


if __name__ == "__main__":
    unittest.main()
