"""Regression tests for SHROUD audit round 1 — Python transforms.

Findings covered (see ``~/workspace/audits/shroud-audit-round-1.md``):
  H1 — rename breaks keyword-argument calls to user functions.
  H2 — ``match`` capture patterns are never renamed (silent semantics change).
  H4 — rename breaks ``eval()``/``exec()`` with compound expressions.
  M3 — ``match`` literal patterns break protection (int and str patterns).

One regression test per finding at minimum; each test compares the
original program against the protected program (stdout + exit code)
run with ``python3`` in a temp dir with the runtime present.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from shroud.errors import ProtectionError
from shroud.py.engine import protect_py, write_runtime

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
# H1 — keyword-argument calls
# ---------------------------------------------------------------------------

class TestH1KeywordArguments(unittest.TestCase):
    def test_h1_keyword_call_to_module_function(self):
        src = (
            "def greet(name):\n"
            "    return 'Hello ' + name\n"
            "print(greet(name='World'))\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h1_keyword_call_all_transforms_on(self):
        src = (
            "def greet(name):\n"
            "    return 'Hello ' + name\n"
            "print(greet(name='World'))\n"
            "print(greet('Moon'))\n"
        )
        _assert_behaviour_preserved(self, src, dict(ALL_ON_SEED))

    def test_h1_nested_function_keyword_call(self):
        src = (
            "def outer():\n"
            "    def inner(label, count):\n"
            "        return label * count\n"
            "    return inner(label='ab', count=3)\n"
            "print(outer())\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h1_duplicate_function_name_params_not_renamed(self):
        # Same name defined twice: ambiguous callee, so the parameters
        # must stay unrenamed and the keyword call must keep working.
        # The second definition wins at runtime in both versions.
        src = (
            "def greet(name):\n"
            "    return 'first ' + name\n"
            "def greet(name):\n"
            "    return 'second ' + name\n"
            "print(greet(name='World'))\n"
        )
        protected = _assert_behaviour_preserved(
            self, src, _only("rename"))
        self.assertIn("def greet(name):", protected)

    def test_h1_method_attribute_call_with_kwargs(self):
        # Attribute calls must NOT have their kwargs renamed at the call
        # site; instead the method's parameters stay unrenamed.
        src = (
            "class Calculator:\n"
            "    def __init__(self, base):\n"
            "        self.base = base\n"
            "    def compute(self, x):\n"
            "        return self.base + x * 10\n"
            "c = Calculator(5)\n"
            "print(c.compute(x=3))\n"
            "print(c.compute(4))\n"
        )
        protected = _assert_behaviour_preserved(
            self, src, _only("rename"))
        self.assertIn("def compute(self, x):", protected)

    def test_h1_kwargs_dict_unpacking_literal(self):
        src = (
            "def greet(name):\n"
            "    return 'Hello ' + name\n"
            "print(greet(**{'name': 'World'}))\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h1_kwargs_parameter_keys_not_renamed(self):
        # **kwargs keys are runtime dict keys, not parameters.
        src = (
            "def f(a, **kwargs):\n"
            "    return a + kwargs.get('extra', 0)\n"
            "print(f(a=1, extra=2))\n"
            "print(f(10, extra=5))\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h1_local_shadowing_function_name(self):
        # A local variable shadowing the module function name is a
        # separate binding: it is renamed as a local, and the module
        # function called with kwargs outside still works.
        src = (
            "def greet(name):\n"
            "    return 'Hello ' + name\n"
            "def outer():\n"
            "    greet = 5\n"
            "    return greet + 1\n"
            "print(outer())\n"
            "print(greet(name='World'))\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h1_lambda_called_with_kwargs(self):
        # A lambda bound to a name may be called with keyword
        # arguments; its parameters must stay unrenamed, because there
        # is no registry entry for a lambda to rewrite the call site.
        src = (
            "f = lambda x: x + 1\n"
            "print(f(x=41))\n"
            "print(f(10))\n"
        )
        protected = _assert_behaviour_preserved(
            self, src, _only("rename"))
        self.assertIn("lambda x:", protected)

    def test_h1_non_literal_starstar_unpacking(self):
        # ** unpacking of a non-literal dict: the runtime dict keys
        # cannot be rewritten, so the callee's parameters must stay
        # unrenamed.
        src = (
            "def f(a):\n"
            "    return a + 1\n"
            "d = {'a': 41}\n"
            "print(f(**d))\n"
        )
        protected = _assert_behaviour_preserved(
            self, src, _only("rename"))
        self.assertIn("def f(a):", protected)

    def test_h1_method_starstar_unpacking(self):
        # A method called with ** unpacking of a dict: the method's
        # parameters must stay unrenamed, as for named kwargs.
        src = (
            "class C:\n"
            "    def m(self, x):\n"
            "        return x + 1\n"
            "d = {'x': 41}\n"
            "print(C().m(**d))\n"
        )
        protected = _assert_behaviour_preserved(
            self, src, _only("rename"))
        self.assertIn("def m(self, x):", protected)

    def test_h1_aliased_function_called_with_kwargs(self):
        # A module function aliased by direct assignment (``g = f``)
        # and called with kwargs through the alias: the callee name is
        # not in the registry, so the function's parameters must stay
        # unrenamed.
        src = (
            "def f(x):\n"
            "    return x + 1\n"
            "g = f\n"
            "print(g(x=41))\n"
            "print(f(x=10))\n"
        )
        protected = _assert_behaviour_preserved(
            self, src, _only("rename"))
        self.assertIn("def f(x):", protected)


# ---------------------------------------------------------------------------
# H2 — match capture patterns
# ---------------------------------------------------------------------------

class TestH2MatchCapture(unittest.TestCase):
    def test_h2_capture_binds_enclosing_local(self):
        # `case x:` captures into the same local `x` that was assigned
        # before the match; after the match `x` holds the captured value.
        src = (
            "def f(v):\n"
            "    x = 99\n"
            "    match v:\n"
            "        case x:\n"
            "            pass\n"
            "    return x\n"
            "print(f(10))\n"
            "print(f(99))\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h2_nested_sequence_capture(self):
        src = (
            "def f(v):\n"
            "    match v:\n"
            "        case [first, second]:\n"
            "            total = first + second\n"
            "        case _:\n"
            "            total = 0\n"
            "    return total\n"
            "print(f([3, 4]))\n"
            "print(f([1]))\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h2_capture_shadowing_outer_local(self):
        # The capture `x` in `case [x, 2]:` shadows the outer local `x`
        # when the pattern matches, and leaves it alone otherwise.
        src = (
            "def f(v):\n"
            "    x = 1\n"
            "    match v:\n"
            "        case [x, 2]:\n"
            "            y = x + 10\n"
            "        case _:\n"
            "            y = 0\n"
            "    return (x, y)\n"
            "print(f([7, 2]))\n"
            "print(f([7, 3]))\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h2_mapping_and_star_capture(self):
        src = (
            "def f(v):\n"
            "    match v:\n"
            "        case {'k': val}:\n"
            "            return val * 2\n"
            "        case [head, *rest]:\n"
            "            return head + sum(rest)\n"
            "        case _:\n"
            "            return 0\n"
            "print(f({'k': 21}))\n"
            "print(f([1, 2, 3]))\n"
            "print(f(9))\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h2_capture_all_transforms_on(self):
        src = (
            "def f(v):\n"
            "    x = 99\n"
            "    match v:\n"
            "        case x:\n"
            "            pass\n"
            "    return x\n"
            "print(f(10))\n"
        )
        _assert_behaviour_preserved(self, src, dict(ALL_ON_SEED))

    def test_h2_match_value_pattern_not_a_binding(self):
        # `case Colour.RED:` is a value pattern, not a capture: the
        # compared name must still resolve to the outer binding, and a
        # capture in a later case must still work.
        src = (
            "class Colour:\n"
            "    RED = 10\n"
            "def f(v):\n"
            "    x = 99\n"
            "    match v:\n"
            "        case Colour.RED:\n"
            "            return x\n"
            "        case x:\n"
            "            pass\n"
            "    return x\n"
            "print(f(10))\n"
            "print(f(5))\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))


# ---------------------------------------------------------------------------
# H4 — eval()/exec() with compound expressions
# ---------------------------------------------------------------------------

class TestH4EvalExec(unittest.TestCase):
    def test_h4_eval_compound_expression(self):
        src = (
            "def f():\n"
            "    x = 42\n"
            "    return eval('x + 1')\n"
            "print(f())\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h4_eval_single_name_still_works(self):
        src = (
            "def f():\n"
            "    x = 42\n"
            "    return eval('x')\n"
            "print(f())\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h4_exec_compound_expression(self):
        # Bare exec() assigns into the function's locals; the result is
        # read back via locals() (a direct `return y` is a NameError in
        # the ORIGINAL on Python 3.12 too, so it cannot be the test).
        src = (
            "def f():\n"
            "    x = 42\n"
            "    exec('y = x + 1')\n"
            "    return locals()['y']\n"
            "print(f())\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h4_getattr_string_lookup(self):
        src = (
            "class Box:\n"
            "    def __init__(self):\n"
            "        self.val = 7\n"
            "def f():\n"
            "    val = 3\n"
            "    return getattr(Box(), 'val') + val\n"
            "print(f())\n"
        )
        _assert_behaviour_preserved(self, src, _only("rename"))

    def test_h4_eval_compound_all_transforms_on(self):
        src = (
            "def f():\n"
            "    x = 42\n"
            "    return eval('x + 1')\n"
            "print(f())\n"
        )
        _assert_behaviour_preserved(self, src, dict(ALL_ON_SEED))

    def test_h4_unrelated_local_still_renamed(self):
        # The word-boundary guard must not save a local whose name only
        # appears as a substring of a longer word in a string.
        src = (
            "def f():\n"
            "    x = 42\n"
            "    xyz = 1\n"
            "    return eval('x + 1') + xyz\n"
            "print(f())\n"
        )
        protected = _assert_behaviour_preserved(self, src, _only("rename"))
        self.assertNotIn("xyz", protected.replace("def f():", ""))


# ---------------------------------------------------------------------------
# M3 — match literal patterns
# ---------------------------------------------------------------------------

class TestM3MatchLiterals(unittest.TestCase):
    def test_m3_case_int_literal(self):
        src = (
            "def f(v):\n"
            "    match v:\n"
            "        case 42:\n"
            "            return 'forty-two'\n"
            "        case _:\n"
            "            return 'other'\n"
            "print(f(42))\n"
            "print(f(7))\n"
        )
        protected = _assert_behaviour_preserved(
            self, src, _only("literal_encoding"))
        self.assertIn("case 42:", protected)

    def test_m3_case_string_literal(self):
        src = (
            "def f(v):\n"
            "    match v:\n"
            "        case 'a':\n"
            "            return 'A'\n"
            "        case _:\n"
            "            return 'other'\n"
            "print(f('a'))\n"
            "print(f('b'))\n"
        )
        protected = _assert_behaviour_preserved(
            self, src, _only("string_encryption"))
        self.assertIn("case 'a':", protected)

    def test_m3_case_list_literal_mixed(self):
        src = (
            "def f(v):\n"
            "    match v:\n"
            "        case [1, 'x']:\n"
            "            return 'hit'\n"
            "        case _:\n"
            "            return 'miss'\n"
            "print(f([1, 'x']))\n"
            "print(f([2, 'y']))\n"
        )
        _assert_behaviour_preserved(self, src, dict(ALL_ON_SEED))

    def test_m3_match_literals_all_transforms_on(self):
        src = (
            "def f(v):\n"
            "    match v:\n"
            "        case 42:\n"
            "            return 'forty-two'\n"
            "        case 'a':\n"
            "            return 'A'\n"
            "        case [1, 'x']:\n"
            "            return 'hit'\n"
            "        case -7:\n"
            "            return 'minus-seven'\n"
            "        case _:\n"
            "            return 'other'\n"
            "print(f(42))\n"
            "print(f('a'))\n"
            "print(f([1, 'x']))\n"
            "print(f(-7))\n"
            "print(f(0))\n"
        )
        protected = _assert_behaviour_preserved(self, src, dict(ALL_ON_SEED))
        self.assertIn("case 42:", protected)
        self.assertIn("case 'a':", protected)

    def test_m3_guard_and_subject_still_encoded(self):
        # Only the pattern is skipped: ints in the subject and guard
        # expressions are still ordinary expressions and may be encoded.
        src = (
            "def f(v):\n"
            "    match v + 42:\n"
            "        case 84:\n"
            "            return 'hit'\n"
            "        case _:\n"
            "            return 'miss'\n"
            "print(f(42))\n"
            "print(f(0))\n"
        )
        protected = _assert_behaviour_preserved(
            self, src, dict(ALL_ON_SEED))
        self.assertIn("case 84:", protected)


if __name__ == "__main__":
    unittest.main()
