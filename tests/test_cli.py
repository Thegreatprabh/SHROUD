"""Tests for the SHROUD CLI (shroud.cli / python -m shroud).

Engine-dependent tests are written against the engine contract in the
task (shroud.js.engine / shroud.py.engine). They fail while the engine
workers' code has not landed yet; that is expected and reported, not
worked around here.
"""

import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from shroud.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "shroud" / "demo"

SMALL_JS = "function add(a, b) { return a + b; }\nconsole.log(add(2, 3));\n"
SMALL_PY = "def add(a, b):\n    return a + b\n\nprint(add(2, 3))\n"


def run_main(argv):
    """Run main() with a patched sys.argv; return (exit_code, out, err)."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def run_module(argv, cwd=None):
    """Run `python -m shroud ...` as a subprocess."""
    return subprocess.run(
        [sys.executable, "-m", "shroud"] + list(argv),
        cwd=str(cwd or REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )


class TestProtect(unittest.TestCase):
    def test_protect_small_js_in_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "small.js"
            src.write_text(SMALL_JS, encoding="utf-8")
            out_dir = Path(tmp) / "out"
            code, out, err = run_main(
                ["protect", str(src), "--engine", "js", "--out", str(out_dir)]
            )
            self.assertEqual(code, 0, err)
            self.assertIn("Protected 1 file(s)", out)
            self.assertIn("JavaScript", out)
            protected = out_dir / "small.js"
            self.assertTrue(protected.is_file())
            result = subprocess.run(
                ["node", str(protected)], capture_output=True, text=True,
                timeout=30,
            )
            self.assertEqual(result.stdout, "5\n")
            self.assertEqual(result.returncode, 0)

    def test_protect_small_py_in_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "small.py"
            src.write_text(SMALL_PY, encoding="utf-8")
            out_dir = Path(tmp) / "out"
            code, out, err = run_main(
                ["protect", str(src), "--engine", "py", "--out", str(out_dir)]
            )
            self.assertEqual(code, 0, err)
            self.assertIn("Protected 1 file(s)", out)
            self.assertIn("Python", out)
            protected = out_dir / "small.py"
            self.assertTrue(protected.is_file())
            # The Python runtime module is written once per output dir.
            self.assertTrue((out_dir / "shroud_runtime.py").is_file())
            result = subprocess.run(
                [sys.executable, str(protected)], capture_output=True,
                text=True, timeout=30,
            )
            self.assertEqual(result.stdout, "5\n")
            self.assertEqual(result.returncode, 0)

    def test_protect_directory_auto_mixed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            src_dir.mkdir()
            (src_dir / "a.js").write_text(SMALL_JS, encoding="utf-8")
            (src_dir / "b.py").write_text(SMALL_PY, encoding="utf-8")
            (src_dir / "notes.txt").write_text("ignore me", encoding="utf-8")
            out_dir = Path(tmp) / "out"
            code, out, err = run_main(
                ["protect", str(src_dir), "--out", str(out_dir)]
            )
            self.assertEqual(code, 0, err)
            self.assertIn("Protected 2 file(s)", out)
            self.assertTrue((out_dir / "a.js").is_file())
            self.assertTrue((out_dir / "b.py").is_file())
            self.assertFalse((out_dir / "notes.txt").exists())
            self.assertTrue((out_dir / "shroud_runtime.py").is_file())

    def test_protect_auto_detects_engine_from_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "small.py"
            src.write_text(SMALL_PY, encoding="utf-8")
            out_dir = Path(tmp) / "out"
            code, _out, err = run_main(
                ["protect", str(src), "--out", str(out_dir)]
            )
            self.assertEqual(code, 0, err)
            self.assertTrue((out_dir / "small.py").is_file())

    def test_protect_with_config_and_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "small.py"
            src.write_text(SMALL_PY, encoding="utf-8")
            config = Path(tmp) / "cfg.yaml"
            config.write_text("seed: 7\n", encoding="utf-8")
            out_dir = Path(tmp) / "out"
            code, _out, err = run_main(
                [
                    "protect", str(src), "--engine", "py",
                    "--out", str(out_dir), "--config", str(config),
                    "--seed", "99",
                ]
            )
            self.assertEqual(code, 0, err)
            self.assertTrue((out_dir / "small.py").is_file())

    def test_protect_missing_input_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _out, err = run_main(
                ["protect", str(Path(tmp) / "nope.js"), "--out", str(Path(tmp) / "out")]
            )
            self.assertEqual(code, 1)
            self.assertTrue(err.startswith("Error:"), err)

    def test_protect_unsupported_extension_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "notes.txt"
            src.write_text("hello", encoding="utf-8")
            code, _out, err = run_main(
                ["protect", str(src), "--out", str(Path(tmp) / "out")]
            )
            self.assertEqual(code, 1)
            self.assertTrue(err.startswith("Error:"), err)

    def test_protect_bad_config_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "small.py"
            src.write_text(SMALL_PY, encoding="utf-8")
            config = Path(tmp) / "bad.yaml"
            config.write_text("js:\n  rename: maybe\n", encoding="utf-8")
            code, _out, err = run_main(
                [
                    "protect", str(src), "--out", str(Path(tmp) / "out"),
                    "--config", str(config),
                ]
            )
            self.assertEqual(code, 1)
            self.assertTrue(err.startswith("Error:"), err)

    def test_protect_via_subprocess_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "small.js"
            src.write_text(SMALL_JS, encoding="utf-8")
            out_dir = Path(tmp) / "out"
            result = run_module(
                ["protect", str(src), "--engine", "js", "--out", str(out_dir)]
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Protected 1 file(s)", result.stdout)
            self.assertTrue((out_dir / "small.js").is_file())


# Source with strings and a flattenable function, so every JS protection
# has something to act on. Used by the inspect tests below, which
# protect real output instead of hand-written marker text.
_MARKER_JS = (
    'function greet(name) { return "Hello, " + name; }\n'
    'console.log(greet("World"));\n'
)


class TestInspect(unittest.TestCase):
    def _protect_marker_js(self, tmp, config_text=None):
        src = Path(tmp) / "marker.js"
        src.write_text(_MARKER_JS, encoding="utf-8")
        out_dir = Path(tmp) / "out"
        argv = ["protect", str(src), "--engine", "js", "--out", str(out_dir)]
        if config_text is not None:
            cfg = Path(tmp) / "config.yaml"
            cfg.write_text(config_text, encoding="utf-8")
            argv += ["--config", str(cfg)]
        code, _out, err = run_main(argv)
        self.assertEqual(code, 0, err)
        return out_dir / "marker.js"

    def test_inspect_detects_js_markers(self):
        # Default config: everything on except domain lock (empty list).
        # This is the exact output the README quickstart documents.
        with tempfile.TemporaryDirectory() as tmp:
            protected = self._protect_marker_js(tmp)
            code, out, _err = run_main(["inspect", str(protected)])
            self.assertEqual(code, 0)
            self.assertIn("engine guess: js", out)
            self.assertIn("string decoder: present", out)
            self.assertIn("flattened dispatch: present", out)
            self.assertIn("domain lock: absent", out)
            self.assertIn("integrity check: present", out)
            self.assertIn("anti-debug: present", out)

    def test_inspect_domain_lock_present_when_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            protected = self._protect_marker_js(
                tmp, 'js:\n  domain_lock: ["example.com"]\n'
            )
            _code, out, _err = run_main(["inspect", str(protected)])
            self.assertIn("domain lock: present", out)

    def test_inspect_integrity_absent_when_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            protected = self._protect_marker_js(tmp, "js:\n  integrity: false\n")
            _code, out, _err = run_main(["inspect", str(protected)])
            self.assertIn("integrity check: absent", out)
            self.assertIn("string decoder: present", out)
            self.assertIn("anti-debug: present", out)

    def test_inspect_anti_debug_absent_when_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            protected = self._protect_marker_js(tmp, "js:\n  anti_debug: false\n")
            _code, out, _err = run_main(["inspect", str(protected)])
            self.assertIn("anti-debug: absent", out)
            self.assertIn("integrity check: present", out)

    def test_inspect_string_decoder_absent_when_encryption_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            protected = self._protect_marker_js(
                tmp, "js:\n  string_encryption: false\n"
            )
            _code, out, _err = run_main(["inspect", str(protected)])
            self.assertIn("string decoder: absent", out)

    def test_inspect_flatten_absent_when_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            protected = self._protect_marker_js(tmp, "js:\n  flatten: false\n")
            _code, out, _err = run_main(["inspect", str(protected)])
            self.assertIn("flattened dispatch: absent", out)

    def test_inspect_py_runtime_checks_absent_by_design(self):
        # Integrity and anti-debug for Python live in the sibling
        # shroud_runtime.py, not in the protected file itself.
        with tempfile.TemporaryDirectory() as tmp:
            src = DEMO_DIR / "demo.py"
            out_dir = Path(tmp) / "out"
            code, _out, err = run_main(
                ["protect", str(src), "--engine", "py", "--out", str(out_dir)]
            )
            self.assertEqual(code, 0, err)
            _code, out, _err = run_main(["inspect", str(out_dir / "demo.py")])
            self.assertIn("engine guess: py", out)
            self.assertIn("string decoder: present", out)
            self.assertIn("flattened dispatch: present", out)
            self.assertIn("domain lock: absent", out)
            self.assertIn("integrity check: absent", out)
            self.assertIn("anti-debug: absent", out)

    def test_inspect_detects_py_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "protected.py"
            fake.write_text(
                "from shroud_runtime import dec as shroud_runtime.dec\n"
                "__state = 0\n",
                encoding="utf-8",
            )
            code, out, _err = run_main(["inspect", str(fake)])
            self.assertEqual(code, 0)
            self.assertIn("engine guess: py", out)
            self.assertIn("string decoder: present", out)
            self.assertIn("flattened dispatch: present", out)

    def test_inspect_plain_file_reports_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / "plain.js"
            plain.write_text(SMALL_JS, encoding="utf-8")
            code, out, _err = run_main(["inspect", str(plain)])
            self.assertEqual(code, 0)
            self.assertIn("string decoder: absent", out)
            self.assertIn("domain lock: absent", out)

    def test_inspect_missing_file_fails(self):
        code, _out, err = run_main(["inspect", "/tmp/shroud-no-such-file.js"])
        self.assertEqual(code, 1)
        self.assertTrue(err.startswith("Error:"), err)

    def test_inspect_via_subprocess_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            protected = self._protect_marker_js(tmp)
            result = run_module(["inspect", str(protected)])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("string decoder: present", result.stdout)
            self.assertIn("domain lock: absent", result.stdout)


class TestVerify(unittest.TestCase):
    def _protect_demo(self, engine, tmp):
        suffix = "js" if engine == "js" else "py"
        src = DEMO_DIR / ("demo.%s" % suffix)
        out_dir = Path(tmp) / ("out-" + engine)
        code, _out, err = run_main(
            ["protect", str(src), "--engine", engine, "--out", str(out_dir)]
        )
        self.assertEqual(code, 0, err)
        return src, out_dir / ("demo.%s" % suffix)

    def test_verify_pass_on_protected_demo_js(self):
        with tempfile.TemporaryDirectory() as tmp:
            original, protected = self._protect_demo("js", tmp)
            code, out, _err = run_main(
                ["verify", str(original), str(protected)]
            )
            self.assertEqual(code, 0, out)
            self.assertIn("PASS", out)

    def test_verify_pass_on_protected_demo_py(self):
        with tempfile.TemporaryDirectory() as tmp:
            original, protected = self._protect_demo("py", tmp)
            code, out, _err = run_main(
                ["verify", str(original), str(protected)]
            )
            self.assertEqual(code, 0, out)
            self.assertIn("PASS", out)

    def test_verify_fail_on_different_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "orig.py"
            original.write_text("print('hello')\n", encoding="utf-8")
            different = Path(tmp) / "other.py"
            different.write_text("print('goodbye')\n", encoding="utf-8")
            code, out, _err = run_main(
                ["verify", str(original), str(different)]
            )
            self.assertEqual(code, 1)
            self.assertIn("FAIL", out)
            self.assertIn("hello", out)

    def test_verify_fail_on_different_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "orig.py"
            original.write_text("print('ok')\n", encoding="utf-8")
            failing = Path(tmp) / "bad.py"
            failing.write_text(
                "import sys\nprint('ok')\nsys.exit(3)\n", encoding="utf-8"
            )
            code, out, _err = run_main(
                ["verify", str(original), str(failing)]
            )
            self.assertEqual(code, 1)
            self.assertIn("FAIL", out)

    def test_verify_missing_file_fails(self):
        code, _out, err = run_main(
            ["verify", "/tmp/shroud-nope.py", "/tmp/shroud-nope2.py"]
        )
        self.assertEqual(code, 1)
        self.assertTrue(err.startswith("Error:"), err)

    def test_verify_via_subprocess_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "orig.py"
            original.write_text("print('same')\n", encoding="utf-8")
            copy = Path(tmp) / "copy.py"
            copy.write_text("print('same')\n", encoding="utf-8")
            result = run_module(["verify", str(original), str(copy)])
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("PASS", result.stdout)


class TestDemo(unittest.TestCase):
    def test_demo_all(self):
        code, out, err = run_main(["demo"])
        self.assertEqual(code, 0, err)
        self.assertIn("JavaScript demo: MATCH", out)
        self.assertIn("Python demo: MATCH", out)

    def test_demo_js_only(self):
        code, out, err = run_main(["demo", "--engine", "js"])
        self.assertEqual(code, 0, err)
        self.assertIn("JavaScript demo: MATCH", out)
        self.assertNotIn("Python demo", out)

    def test_demo_py_only(self):
        code, out, err = run_main(["demo", "--engine", "py"])
        self.assertEqual(code, 0, err)
        self.assertIn("Python demo: MATCH", out)

    def test_demo_via_subprocess_module(self):
        result = run_module(["demo", "--engine", "py"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Python demo: MATCH", result.stdout)


if __name__ == "__main__":
    unittest.main()
