"""Regression tests for SHROUD audit round 1 — Python engine + runtime.

One test per finding: M1 (``from __future__`` imports), M2 (module
``__doc__``), M5 Python half (non-UTF-8 input / manifest OSError),
M6 (quoted filenames), L2 (``sys.monitoring`` tracers). Each test
failed against the pre-fix code and passes after the fix.
"""

import ast
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from shroud.errors import ProtectionError
from shroud.py.engine import (
    protect_py,
    protect_py_dir,
    protect_py_file,
    write_runtime,
)

ALL_OFF = {
    "rename": False,
    "string_encryption": False,
    "flatten": False,
    "literal_encoding": False,
    "dead_code": False,
}

ALL_ON_SEED = {
    "rename": True,
    "string_encryption": True,
    "flatten": True,
    "literal_encoding": True,
    "dead_code": True,
    "seed": 42,
}


def _run(path, cwd, env=None):
    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    return subprocess.run(
        [sys.executable, str(path)],
        capture_output=True, text=True, timeout=30, cwd=str(cwd), env=run_env,
    )


def _run_pair(source, options):
    """Protect ``source`` in a temp dir (runtime present) and run both.

    Returns ``(original_result, protected_result, protected_source)``.
    """
    opts = dict(options)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        orig = tmp_path / "orig.py"
        prot = tmp_path / "prot.py"
        orig.write_text(source, encoding="utf-8")
        protected = protect_py(source, opts)
        prot.write_text(protected, encoding="utf-8")
        write_runtime(tmp, opts)
        return _run(orig, tmp), _run(prot, tmp), protected


# ---------------------------------------------------------------------------
# M1 — `from __future__` imports
# ---------------------------------------------------------------------------

class TestFutureImport(unittest.TestCase):
    def test_future_import_protects_and_runs(self):
        """M1: a file starting with a future import must protect and run."""
        src = (
            "from __future__ import annotations\n"
            "\n"
            "\n"
            "def greet(name: str) -> str:\n"
            "    return 'Hello, ' + name + '!'\n"
            "\n"
            "\n"
            "print(greet('World'))\n"
        )
        orig, prot, protected = _run_pair(src, dict(ALL_ON_SEED))
        self.assertEqual(orig.returncode, 0, orig.stderr)
        self.assertEqual(prot.returncode, 0, prot.stderr)
        self.assertEqual(prot.stdout, orig.stdout)
        self.assertEqual(prot.stdout, "Hello, World!\n")
        # The future import must still be at the top of the output
        # (before the runtime header), or protection would not compile.
        tree = ast.parse(protected)
        self.assertIsInstance(tree.body[0], ast.ImportFrom)
        self.assertEqual(tree.body[0].module, "__future__")


# ---------------------------------------------------------------------------
# M2 — module __doc__ preserved
# ---------------------------------------------------------------------------

class TestModuleDocstring(unittest.TestCase):
    def test_module_docstring_preserved(self):
        """M2: the module docstring must survive protection (__doc__)."""
        src = (
            '"""Module docstring here."""\n'
            "\n"
            "\n"
            "def answer():\n"
            "    return 42\n"
            "\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    print(__doc__)\n"
            "    print(answer())\n"
        )
        orig, prot, protected = _run_pair(src, dict(ALL_ON_SEED))
        self.assertEqual(orig.returncode, 0, orig.stderr)
        self.assertEqual(prot.returncode, 0, prot.stderr)
        self.assertEqual(prot.stdout, orig.stdout)
        self.assertEqual(prot.stdout, "Module docstring here.\n42\n")
        # The docstring must still be the first statement of the module.
        tree = ast.parse(protected)
        first = tree.body[0]
        self.assertIsInstance(first, ast.Expr)
        self.assertIsInstance(first.value, ast.Constant)
        self.assertEqual(first.value.value, "Module docstring here.")

    def test_future_import_docstring_and_function_behaviour(self):
        """M2: future import + docstring + function run identically and
        ``__doc__`` is preserved. (The docstring must come BEFORE the
        future import in the source: that is the only layout where
        Python treats it as the module docstring at all.)"""
        src = (
            '"""Module docstring here."""\n'
            "from __future__ import annotations\n"
            "\n"
            "\n"
            "def answer() -> int:\n"
            "    return 42\n"
            "\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    print(__doc__)\n"
            "    print(answer())\n"
        )
        orig, prot, protected = _run_pair(src, dict(ALL_ON_SEED))
        self.assertEqual(orig.returncode, 0, orig.stderr)
        self.assertEqual(prot.returncode, 0, prot.stderr)
        self.assertEqual(prot.stdout, orig.stdout)
        self.assertEqual(prot.stdout, "Module docstring here.\n42\n")
        tree = ast.parse(protected)
        # Docstring stays the first statement, future import second.
        first = tree.body[0]
        self.assertIsInstance(first, ast.Expr)
        self.assertIsInstance(first.value, ast.Constant)
        self.assertEqual(first.value.value, "Module docstring here.")
        self.assertIsInstance(tree.body[1], ast.ImportFrom)
        self.assertEqual(tree.body[1].module, "__future__")


# ---------------------------------------------------------------------------
# M6 — filenames with a single quote (and other awkward characters)
# ---------------------------------------------------------------------------

class TestQuotedFilenames(unittest.TestCase):
    def test_quoted_and_unicode_filenames_protect_and_run(self):
        """M6: protecting a directory containing ``o'brien.py`` must
        produce a valid runtime, list the file in the manifest, run,
        and still detect tampering."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src_dir = tmp_path / "src"
            src_dir.mkdir()
            files = {
                "o'brien.py": "print('obrien')\n",
                "caf\u00e9.py": "print('cafe')\n",
                "back\\slash.py": "print('backslash')\n",
            }
            for name, content in files.items():
                (src_dir / name).write_text(content, encoding="utf-8")
            dst_dir = tmp_path / "out"
            opts = dict(ALL_ON_SEED)
            written = protect_py_dir(str(src_dir), str(dst_dir), opts)
            self.assertEqual(len(written), 3)
            runtime_path = dst_dir / "shroud_runtime.py"
            self.assertTrue(runtime_path.is_file())
            # The generated runtime must be valid Python.
            runtime_text = runtime_path.read_text(encoding="utf-8")
            ast.parse(runtime_text)
            compile(runtime_text, "shroud_runtime.py", "exec")
            # Every awkward filename must be listed in the manifest.
            manifest = json.loads(
                (dst_dir / ".shroud_manifest.json").read_text(
                    encoding="utf-8"))
            for name in files:
                self.assertIn(name, manifest)
            # Every protected file must run identically to its original.
            for name, content in files.items():
                orig = _run(src_dir / name, tmp_path)
                prot = _run(dst_dir / name, dst_dir)
                self.assertEqual(orig.returncode, 0, orig.stderr)
                self.assertEqual(prot.returncode, 0, prot.stderr)
                self.assertEqual(prot.stdout, orig.stdout)
            # Tampering with the quoted file must still be detected.
            quoted = dst_dir / "o'brien.py"
            text = quoted.read_text(encoding="utf-8")
            quoted.write_text(text + "\n# tampered\n", encoding="utf-8")
            tampered = _run(quoted, dst_dir)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn("integrity", tampered.stderr.lower())


# ---------------------------------------------------------------------------
# L2 — sys.monitoring-based tracers
# ---------------------------------------------------------------------------

class TestSysMonitoringTracer(unittest.TestCase):
    def _load_runtime(self, tmp_path, anti_debug=True):
        opts = dict(ALL_ON_SEED, integrity=False, anti_debug=anti_debug)
        write_runtime(tmp_path, opts)
        spec = importlib.util.spec_from_file_location(
            "shroud_runtime_under_test", tmp_path / "shroud_runtime.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @unittest.skipUnless(hasattr(sys, "monitoring"),
                         "sys.monitoring needs Python 3.12+")
    def test_monitoring_tool_detected(self):
        """L2: a registered ``sys.monitoring`` tool must make check()
        raise, and check() must pass once the tool is freed."""
        monitoring = sys.monitoring
        tool_id = None
        for candidate in range(4):
            if monitoring.get_tool(candidate) is None:
                tool_id = candidate
                break
        if tool_id is None:
            self.skipTest("no free sys.monitoring tool id")
        with tempfile.TemporaryDirectory() as tmp:
            mod = self._load_runtime(Path(tmp), anti_debug=True)
            monitoring.use_tool_id(tool_id, "shroud-audit-test")
            try:
                with self.assertRaises(RuntimeError):
                    mod.check()
            finally:
                monitoring.free_tool_id(tool_id)
            # No tool registered any more: check() passes.
            mod.check()

    @unittest.skipUnless(hasattr(sys, "monitoring"),
                         "sys.monitoring needs Python 3.12+")
    def test_monitoring_tool_ignored_when_anti_debug_off(self):
        """L2: with anti_debug off, a registered monitoring tool must
        not raise (the flag gates the whole anti-debug check)."""
        monitoring = sys.monitoring
        tool_id = None
        for candidate in range(4):
            if monitoring.get_tool(candidate) is None:
                tool_id = candidate
                break
        if tool_id is None:
            self.skipTest("no free sys.monitoring tool id")
        with tempfile.TemporaryDirectory() as tmp:
            mod = self._load_runtime(Path(tmp), anti_debug=False)
            monitoring.use_tool_id(tool_id, "shroud-audit-test")
            try:
                mod.check()
            finally:
                monitoring.free_tool_id(tool_id)


# ---------------------------------------------------------------------------
# M5 (Python half) — uncaught exceptions become ProtectionError
# ---------------------------------------------------------------------------

class TestUncaughtExceptions(unittest.TestCase):
    def test_non_utf8_input_raises_protection_error(self):
        """M5: a latin-1-encoded .py file must raise ProtectionError
        (not an uncaught UnicodeDecodeError traceback)."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "latin1.py"
            # latin-1 bytes: 0xe9 alone is not valid UTF-8.
            src.write_bytes(b"print('caf\xe9')\n")
            dst = tmp_path / "out.py"
            with self.assertRaises(ProtectionError):
                protect_py_file(str(src), str(dst), dict(ALL_ON_SEED))

    def test_manifest_hash_oserror_raises_protection_error(self):
        """M5: an OSError while hashing files for the manifest (e.g. a
        dangling symlink) must raise ProtectionError, not escape."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Dangling symlink: rglob finds it, opening it raises
            # FileNotFoundError (an OSError).
            (tmp_path / "broken.py").symlink_to(tmp_path / "does-not-exist.py")
            with self.assertRaises(ProtectionError):
                write_runtime(tmp, dict(ALL_ON_SEED, integrity=True))


if __name__ == "__main__":
    unittest.main()
