"""Tests for the SHROUD Python engine (``shroud/py``).

One test class per transform, each verifying the transform is present
in the output AND that behaviour is preserved (original vs protected
run with ``python3`` in a temp dir with the runtime present; stdout
and exit code compared). Plus engine / runtime-check integration tests.
"""

import ast
import hashlib
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

# Test program: functions, string literals, arithmetic, if/else, loops,
# dicts/lists, a class with methods, a docstring, an f-string, and a
# comprehension that shadows an outer local.
TEST_PROGRAM = '''"""Module docstring."""


def greet(name):
    """Greet docstring."""
    return f"Hello, {name}!"


def plain():
    return "secret-plain"


def add(a, b):
    total = a + b + 42
    if total > 100:
        return total * 2
    else:
        return total - 10


def loop_sum(n):
    s = 0
    for i in range(n):
        s += i * 3
    return s


def make_dict():
    d = {"key": 123, "other": 7}
    lst = [1, 2, 3]
    return d["key"] + lst[0] + lst[2]


class Calculator:
    """Calc doc."""

    def __init__(self, base):
        self.base = base

    def compute(self, x):
        result = self.base + x * 10
        return result


def shadow():
    n = 5
    return [n * 2 for n in range(3)] + [n]


if __name__ == "__main__":
    print(greet("World"))
    print(greet.__doc__)
    print(Calculator.__doc__)
    print(plain())
    print(add(10, 20))
    print(add(100, 20))
    print(loop_sum(5))
    print(make_dict())
    c = Calculator(5)
    print(c.compute(3))
    print(shadow())
'''

EXPECTED_STDOUT = (
    "Hello, World!\n"
    "Greet docstring.\n"
    "Calc doc.\n"
    "secret-plain\n"
    "62\n"
    "324\n"
    "30\n"
    "127\n"
    "35\n"
    "[0, 2, 4, 5]\n"
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


def _only(transform, seed=42):
    """Options with only one transform on (plus a fixed seed)."""
    opts = dict(ALL_OFF)
    opts[transform] = True
    opts["seed"] = seed
    return opts


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
    The same options dict object is passed to protect and write_runtime,
    as the CLI does, so the per-build key agrees when seed is None.
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


def _assert_behaviour_preserved(testcase, source, options):
    orig, prot, protected = _run_pair(source, options)
    testcase.assertEqual(orig.returncode, 0, orig.stderr)
    testcase.assertEqual(prot.returncode, 0, prot.stderr)
    testcase.assertEqual(prot.stdout, orig.stdout)
    return protected


# ---------------------------------------------------------------------------
# Renaming
# ---------------------------------------------------------------------------

class TestRename(unittest.TestCase):
    def test_locals_and_params_renamed(self):
        protected = protect_py(TEST_PROGRAM, _only("rename"))
        names = {n.id for n in ast.walk(ast.parse(protected))
                 if isinstance(n, ast.Name)}
        # Original locals/params must be gone; deterministic _s names present.
        # ('n' is excluded: shadow()'s comprehension target legitimately
        # keeps the name 'n' — it shadows the outer local, which IS renamed.)
        for gone in ("total", "s", "i", "d", "lst", "result", "a", "b"):
            self.assertNotIn(gone, names, "local %r was not renamed" % gone)
        # The outer 'n = 5' assignment in shadow() was renamed.
        tree = ast.parse(protected)
        shadow_fn = next(n for n in tree.body
                         if isinstance(n, ast.FunctionDef) and n.name == "shadow")
        first_assign = shadow_fn.body[0]
        self.assertIsInstance(first_assign, ast.Assign)
        self.assertTrue(first_assign.targets[0].id.startswith("_s"))
        self.assertTrue(any(name.startswith("_s") for name in names))
        # Module-level names, class names, attributes, imports untouched.
        self.assertIn("Calculator", protected)
        self.assertIn("greet", protected)
        self.assertIn(".base", protected)
        self.assertIn(".compute", protected)

    def test_behaviour_preserved(self):
        _assert_behaviour_preserved(self, TEST_PROGRAM, _only("rename"))

    def test_closure_and_comprehension_shadow_not_broken(self):
        src = (
            "def outer(x):\n"
            "    def inner():\n"
            "        return x + 1\n"
            "    n = 5\n"
            "    comp = [n * 2 for n in range(3)]\n"
            "    return inner() + comp[0] + n\n"
            "print(outer(10))\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))


# ---------------------------------------------------------------------------
# String encryption
# ---------------------------------------------------------------------------

class TestStringEncryption(unittest.TestCase):
    def test_plain_strings_become_dec_calls(self):
        protected = protect_py(TEST_PROGRAM, _only("string_encryption"))
        self.assertIn("shroud_runtime.dec(", protected)
        # The plain (non-f-string) literal must not survive as a literal.
        self.assertNotIn('"secret-plain"', protected)
        self.assertNotIn("'secret-plain'", protected)
        # Dict keys are skipped, so they stay plain (unparse uses quotes).
        self.assertIn("'key'", protected)

    def test_docstrings_and_fstrings_survive(self):
        protected = protect_py(TEST_PROGRAM, _only("string_encryption"))
        self.assertIn('"""Module docstring."""', protected)
        self.assertIn('"""Greet docstring."""', protected)
        # f-string literal part survives; its {name} expression is intact.
        self.assertIn("Hello, ", protected)
        self.assertIn("f'", protected)

    def test_behaviour_preserved(self):
        _assert_behaviour_preserved(self, TEST_PROGRAM, _only("string_encryption"))


# ---------------------------------------------------------------------------
# Literal encoding
# ---------------------------------------------------------------------------

class TestLiteralEncoding(unittest.TestCase):
    def test_ints_become_arithmetic(self):
        protected = protect_py(TEST_PROGRAM, _only("literal_encoding"))
        # 42 must not survive as a bare literal; it becomes a + b.
        self.assertNotIn("42", protected)
        tree = ast.parse(protected)
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                vals = [c.value for c in (node.left, node.right)
                        if isinstance(c, ast.Constant) and type(c.value) is int]
                if len(vals) == 2 and sum(vals) == 42:
                    found = True
        self.assertTrue(found, "no arithmetic expression summing to 42")

    def test_dict_keys_not_encoded(self):
        protected = protect_py("d = {'k': 1}\nprint(d['k'])\n",
                               _only("literal_encoding"))
        self.assertIn("'k'", protected)

    def test_behaviour_preserved(self):
        _assert_behaviour_preserved(self, TEST_PROGRAM, _only("literal_encoding"))


# ---------------------------------------------------------------------------
# Control-flow flattening
# ---------------------------------------------------------------------------

class TestFlattening(unittest.TestCase):
    def test_function_becomes_state_dispatch(self):
        protected = protect_py(TEST_PROGRAM, _only("flatten"))
        self.assertIn("__state", protected)
        self.assertIn("__ret", protected)
        self.assertIn("while True:", protected)

    def test_behaviour_preserved(self):
        _assert_behaviour_preserved(self, TEST_PROGRAM, _only("flatten"))

    def test_top_level_return_uses_ret_variable(self):
        src = "def f(x):\n    if x:\n        return 1\n    return 2\nprint(f(True))\nprint(f(False))\n"
        _assert_behaviour_preserved(self, src, _only("flatten"))
        protected = protect_py(src, _only("flatten"))
        self.assertIn("__ret", protected)

    def test_generator_async_global_left_unflattened(self):
        src = (
            "def gen(n):\n"
            "    total = 0\n"
            "    for i in range(n):\n"
            "        total += i\n"
            "        yield total\n"
            "async def fetch(url):\n"
            "    return 'data:' + url\n"
            "count = 0\n"
            "def bump():\n"
            "    global count\n"
            "    count = count + 1\n"
            "    return count\n"
        )
        protected = protect_py(src, dict(ALL_ON_SEED))
        tree = ast.parse(protected)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and node.name in ("gen", "fetch", "bump"):
                segment = ast.get_source_segment(protected, node) or ""
                self.assertNotIn("__state", segment,
                                 "%s was flattened" % node.name)
                self.assertNotIn("while True:", segment,
                                 "%s was flattened" % node.name)
        self.assertIn("yield", protected)
        # ...but other transforms still protect them.
        self.assertIn("shroud_runtime.dec(", protected)

    def test_generator_async_behaviour_preserved(self):
        src = (
            "def gen(n):\n"
            "    total = 0\n"
            "    for i in range(n):\n"
            "        total += i\n"
            "        yield total\n"
            "async def fetch(url):\n"
            "    return 'data:' + url\n"
            "import asyncio\n"
            "print(list(gen(4)))\n"
            "print(asyncio.run(fetch('x')))\n"
        )
        _assert_behaviour_preserved(self, src, dict(ALL_ON_SEED))


# ---------------------------------------------------------------------------
# Dead-code injection
# ---------------------------------------------------------------------------

class TestDeadCode(unittest.TestCase):
    def test_if_false_blocks_and_junk_function_present(self):
        protected = protect_py(TEST_PROGRAM, _only("dead_code"))
        self.assertIn("if False:", protected)
        tree = ast.parse(protected)
        junk = [n for n in tree.body
                if isinstance(n, ast.FunctionDef)
                and n.name.startswith("_shroud_junk_")]
        self.assertEqual(len(junk), 1, "exactly one junk function per file")
        self.assertNotIn(junk[0].name + "(", protected.replace(
            "def %s" % junk[0].name, "", 1))

    def test_behaviour_preserved(self):
        _assert_behaviour_preserved(self, TEST_PROGRAM, _only("dead_code"))


# ---------------------------------------------------------------------------
# Engine interface
# ---------------------------------------------------------------------------

class TestEngine(unittest.TestCase):
    def test_protect_py_header(self):
        protected = protect_py(TEST_PROGRAM, dict(ALL_ON_SEED))
        # The runtime header is inserted after the module docstring
        # (and any leading `from __future__` imports), so it is not
        # necessarily the first statement — but it must be present
        # before the rest of the program. TEST_PROGRAM starts with a
        # module docstring, so the import is the second statement.
        tree = ast.parse(protected)
        self.assertIsInstance(tree.body[0], ast.Expr)  # module docstring
        header = tree.body[1]
        self.assertIsInstance(header, ast.Import)
        self.assertEqual([a.name for a in header.names], ["shroud_runtime"])
        self.assertIn("shroud_runtime.check()", protected)
        ast.parse(protected)
        compile(protected, "<shroud>", "exec")

    def test_all_transforms_off_is_parse_unparse_identity(self):
        protected = protect_py(TEST_PROGRAM, dict(ALL_OFF, seed=42))
        tree = ast.parse(protected)
        body = list(tree.body)
        # Drop the two runtime-header statements (import + check call);
        # they sit after the module docstring, not at the top.
        idx = next(
            i
            for i, node in enumerate(body)
            if isinstance(node, ast.Import)
            and any(a.name == "shroud_runtime" for a in node.names)
        )
        check = body[idx + 1]
        self.assertIsInstance(check, ast.Expr)
        self.assertIsInstance(check.value, ast.Call)
        self.assertIsInstance(check.value.func, ast.Attribute)
        self.assertEqual(check.value.func.attr, "check")
        del body[idx:idx + 2]
        tree.body = body
        self.assertEqual(ast.dump(ast.parse(TEST_PROGRAM)),
                         ast.dump(tree))

    def test_all_transforms_on_behaviour(self):
        orig, prot, _ = _run_pair(TEST_PROGRAM, dict(ALL_ON_SEED))
        self.assertEqual(orig.returncode, 0, orig.stderr)
        self.assertEqual(prot.returncode, 0, prot.stderr)
        self.assertEqual(prot.stdout, EXPECTED_STDOUT)
        self.assertEqual(orig.stdout, EXPECTED_STDOUT)

    def test_seed_determinism(self):
        first = protect_py(TEST_PROGRAM, dict(ALL_ON_SEED))
        second = protect_py(TEST_PROGRAM, dict(ALL_ON_SEED))
        self.assertEqual(first, second)
        different = protect_py(TEST_PROGRAM, dict(ALL_ON_SEED, seed=7))
        self.assertNotEqual(first, different)

    def test_seed_none_key_shared_via_options_dict(self):
        # Same options dict object for protect + write_runtime (CLI flow).
        opts = {}
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            protected = protect_py(TEST_PROGRAM, opts)
            (tmp_path / "prot.py").write_text(protected, encoding="utf-8")
            write_runtime(tmp, opts)
            result = _run(tmp_path / "prot.py", tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, EXPECTED_STDOUT)

    def test_invalid_source_raises_protection_error(self):
        with self.assertRaises(ProtectionError):
            protect_py("def broken(:\n", dict(ALL_ON_SEED))

    def test_protect_py_file_and_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src_dir = tmp_path / "src"
            (src_dir / "sub").mkdir(parents=True)
            (src_dir / "a.py").write_text(TEST_PROGRAM, encoding="utf-8")
            (src_dir / "sub" / "b.py").write_text(
                "print('bee')\n", encoding="utf-8")
            (src_dir / "notes.txt").write_text("not code\n", encoding="utf-8")
            dst_dir = tmp_path / "out"
            opts = dict(ALL_ON_SEED)
            written = protect_py_dir(str(src_dir), str(dst_dir), opts)
            self.assertEqual(len(written), 2)
            self.assertTrue((dst_dir / "a.py").is_file())
            self.assertTrue((dst_dir / "sub" / "b.py").is_file())
            self.assertTrue((dst_dir / "shroud_runtime.py").is_file())
            self.assertFalse((dst_dir / "notes.txt").exists())
            # Single-file API.
            single = tmp_path / "single.py"
            protect_py_file(str(src_dir / "a.py"), str(single), dict(ALL_ON_SEED))
            self.assertTrue(single.is_file())

    def test_write_runtime_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            opts = dict(ALL_ON_SEED, integrity=True)
            (tmp_path / "a.py").write_text(
                protect_py("print('a')\n", opts), encoding="utf-8")
            runtime = write_runtime(tmp, opts)
            self.assertEqual(runtime, str(tmp_path / "shroud_runtime.py"))
            manifest = json.loads(
                (tmp_path / ".shroud_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["a.py"],
                hashlib.sha256((tmp_path / "a.py").read_bytes()).hexdigest())
            runtime_text = (tmp_path / "shroud_runtime.py").read_text(
                encoding="utf-8")
            self.assertIn("def dec(", runtime_text)
            self.assertIn("def check(", runtime_text)
            self.assertNotIn("__SHROUD_", runtime_text)

    def test_write_runtime_manifest_empty_when_integrity_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            opts = dict(ALL_ON_SEED, integrity=False)
            (tmp_path / "a.py").write_text(
                protect_py("print('a')\n", opts), encoding="utf-8")
            write_runtime(tmp, opts)
            manifest = json.loads(
                (tmp_path / ".shroud_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest, {})


# ---------------------------------------------------------------------------
# Runtime checks: integrity, anti-debug, license
# ---------------------------------------------------------------------------

class TestRuntimeChecks(unittest.TestCase):
    def _protected_dir(self, source, options):
        """Return (tmpdir, protected_path) context-managed by the caller."""
        tmp = tempfile.TemporaryDirectory()
        tmp_path = Path(tmp.name)
        opts = dict(options)
        protected = protect_py(source, opts)
        prot = tmp_path / "prot.py"
        prot.write_text(protected, encoding="utf-8")
        write_runtime(tmp.name, opts)
        return tmp, tmp_path, prot

    def test_integrity_tamper_raises(self):
        tmp, tmp_path, prot = self._protected_dir(
            TEST_PROGRAM, dict(ALL_ON_SEED, integrity=True))
        try:
            # Tamper after protection: the manifest hash no longer matches.
            text = prot.read_text(encoding="utf-8")
            prot.write_text(text + "\n# tampered\n", encoding="utf-8")
            result = _run(prot, tmp_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("integrity", result.stderr.lower())
        finally:
            tmp.cleanup()

    def test_integrity_clean_run_passes(self):
        tmp, tmp_path, prot = self._protected_dir(
            TEST_PROGRAM, dict(ALL_ON_SEED, integrity=True))
        try:
            result = _run(prot, tmp_path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, EXPECTED_STDOUT)
        finally:
            tmp.cleanup()

    def test_anti_debug_raises_under_tracer(self):
        tmp, tmp_path, prot = self._protected_dir(
            TEST_PROGRAM, dict(ALL_ON_SEED, anti_debug=True))
        try:
            runner = tmp_path / "run_traced.py"
            runner.write_text(
                "import sys\n"
                "sys.path.insert(0, %r)\n"
                "def _tracer(frame, event, arg):\n"
                "    return _tracer\n"
                "sys.settrace(_tracer)\n"
                "try:\n"
                "    import prot\n"
                "except RuntimeError as exc:\n"
                "    print('RUNTIMEERROR:', exc)\n"
                "    sys.exit(0)\n"
                "print('NO ERROR')\n"
                "sys.exit(1)\n" % str(tmp_path),
                encoding="utf-8",
            )
            result = _run(runner, tmp_path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RUNTIMEERROR", result.stdout)
        finally:
            tmp.cleanup()

    def test_anti_debug_off_runs_under_tracer(self):
        tmp, tmp_path, prot = self._protected_dir(
            TEST_PROGRAM, dict(ALL_ON_SEED, anti_debug=False))
        try:
            runner = tmp_path / "run_traced.py"
            runner.write_text(
                "import sys\n"
                "sys.path.insert(0, %r)\n"
                "def _tracer(frame, event, arg):\n"
                "    return _tracer\n"
                "sys.settrace(_tracer)\n"
                "import prot\n"
                "print('OK')\n" % str(tmp_path),
                encoding="utf-8",
            )
            result = _run(runner, tmp_path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("OK", result.stdout)
        finally:
            tmp.cleanup()

    def test_license_binding(self):
        opts = dict(ALL_ON_SEED, license_key="s3cret-license")
        tmp, tmp_path, prot = self._protected_dir(TEST_PROGRAM, opts)
        try:
            good = _run(prot, tmp_path,
                        env={"SHROUD_LICENSE_KEY": "s3cret-license"})
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(good.stdout, EXPECTED_STDOUT)
            missing_env = dict(os.environ)
            missing_env.pop("SHROUD_LICENSE_KEY", None)
            missing = subprocess.run(
                [sys.executable, str(prot)], capture_output=True, text=True,
                timeout=30, cwd=str(tmp_path), env=missing_env)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("license", missing.stderr.lower())
            wrong = _run(prot, tmp_path,
                         env={"SHROUD_LICENSE_KEY": "wrong-key"})
            self.assertNotEqual(wrong.returncode, 0)
            self.assertIn("license", wrong.stderr.lower())
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
