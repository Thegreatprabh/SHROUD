"""Regression tests for SHROUD audit round 1 — JavaScript engine.

Covers H3 (eval), H5 (with), M4 (ES2020+ syntax), L1 (block-scoped
let/const in sibling blocks), L6 (case-insensitive domain lock) and the
JS half of M5 (protect_js_file error handling).

Every behaviour test checks the same thing: the original source and the
protected source run under Node with identical stdout and exit code 0.
"""

import os
import re
import subprocess
import tempfile
import unittest

from shroud.errors import ProtectionError
from shroud.js.engine import ensure_node_deps, protect_js, protect_js_file

NODE = "node"

DEFAULT_PROGRAM = '"use strict";\nconsole.log("ok");\n'


def run_node(code):
    """Run JS code under Node; return (returncode, stdout, stderr)."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".js", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        path = f.name
    try:
        result = subprocess.run(
            [NODE, path], capture_output=True, text=True, timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    finally:
        os.unlink(path)


class AuditR1JsTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_node_deps()

    def protect(self, source=None, **overrides):
        if source is None:
            source = DEFAULT_PROGRAM
        options = {"seed": 7}
        options.update(overrides)
        return protect_js(source, options)

    def assertBehaviorPreserved(self, protected, source):
        rc, out, err = run_node(protected)
        self.assertEqual(rc, 0, "protected code must exit 0: " + err)
        rc_orig, expected, err_orig = run_node(source)
        self.assertEqual(rc_orig, 0, "original must run cleanly: " + err_orig)
        self.assertEqual(out, expected)

    def assertWordAbsent(self, text, word):
        self.assertIsNone(
            re.search(r"\b" + re.escape(word) + r"\b", text),
            "expected %r to be absent from protected output" % word,
        )


class TestH3Eval(AuditR1JsTestBase):
    def test_eval_local_var(self):
        # Audit H3 repro: eval("x") on a function-local must still see it.
        src = (
            "function f() { var x = 42; return eval(\"x\"); }\n"
            "console.log(f());\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)

    def test_eval_compound_expression(self):
        src = (
            "function f() { var x = 42; return eval(\"x + 1\"); }\n"
            "console.log(f());\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)

    def test_eval_in_nested_function_sees_outer_local(self):
        # A direct eval in an inner function can see enclosing locals
        # through the scope chain, so the outer function must not rename.
        src = (
            "function outer() {\n"
            "  var x = 7;\n"
            "  function inner() { return eval(\"x\"); }\n"
            "  return inner();\n"
            "}\n"
            "console.log(outer());\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)

    def test_rename_still_applies_in_eval_free_function(self):
        # Positive control: renaming must still happen where no direct
        # eval/with is in play, and must NOT happen in the eval function.
        src = (
            "function withEval() {\n"
            "  var evalSecret = 1;\n"
            "  return eval(\"evalSecret\");\n"
            "}\n"
            "function clean() {\n"
            "  var cleanSecret = 2;\n"
            "  return cleanSecret + 1;\n"
            "}\n"
            "console.log(withEval(), clean());\n"
        )
        protected = self.protect(src)
        self.assertBehaviorPreserved(protected, src)
        # The eval function's local stays readable (dynamic lookup).
        self.assertIsNotNone(re.search(r"\bevalSecret\b", protected))
        # The eval-free function's local is still renamed.
        self.assertWordAbsent(protected, "cleanSecret")


class TestH5WithStatement(AuditR1JsTestBase):
    def test_with_statement_dynamic_scope(self):
        # Audit H5 repro: inside `with (obj)`, `x` must resolve to the
        # object's property (99), not the function-local (1). Silent
        # wrong-answer bug if the local is renamed.
        src = (
            "function f() {\n"
            "  var x = 1;\n"
            "  var obj = {x: 99};\n"
            "  with (obj) { return x; }\n"
            "}\n"
            "console.log(f());\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)


class TestM4ModernJs(AuditR1JsTestBase):
    def test_optional_chaining(self):
        src = (
            "var o = {a: 1};\n"
            "console.log(o?.a);\n"
            "console.log(o?.missing);\n"
            "console.log(o?.nested?.deep);\n"
            "console.log(null?.a);\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)

    def test_nullish_coalescing(self):
        src = (
            "var o = {a: 1};\n"
            "console.log(o?.a ?? 2);\n"
            "console.log(o?.missing ?? 2);\n"
            "console.log(null ?? 3);\n"
            "console.log(0 ?? 4);\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)

    def test_private_class_fields(self):
        src = (
            "class C {\n"
            "  #x = 5;\n"
            "  getX() { return this.#x; }\n"
            "}\n"
            "console.log(new C().getX());\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)


class TestL1SiblingBlockLet(AuditR1JsTestBase):
    def test_let_in_sibling_blocks_renamed(self):
        # Audit L1 repro: `let` declared in two sibling blocks of one
        # function must be renamed (one fresh name per block scope).
        src = (
            "function f(a) {\n"
            "  var r = 0;\n"
            "  if (a) { let blockVal = 10; r += blockVal; }\n"
            "  if (!a) { let blockVal = 20; r += blockVal; }\n"
            "  return r;\n"
            "}\n"
            "console.log(f(true), f(false));\n"
        )
        protected = self.protect(src)
        self.assertBehaviorPreserved(protected, src)
        self.assertWordAbsent(protected, "blockVal")

    def test_shadowed_let_in_inner_block(self):
        # Inner-block shadowing must still resolve to the right binding
        # once both declarations are renamed independently.
        src = (
            "function f() {\n"
            "  let val = 1;\n"
            "  let r = val;\n"
            "  if (true) { let val = 2; r += val * 10; }\n"
            "  r += val * 100;\n"
            "  return r;\n"
            "}\n"
            "console.log(f());\n"
        )
        protected = self.protect(src)
        self.assertBehaviorPreserved(protected, src)
        self.assertWordAbsent(protected, "val")


class TestL6DomainLockCase(AuditR1JsTestBase):
    def test_domain_lock_case_insensitive_allows(self):
        # Hostnames are case-insensitive: a lock entry in a different
        # case than the actual hostname must still match.
        protected = self.protect(domain_lock=["Example.COM"])
        wrapper = (
            'globalThis.location = {hostname: "example.com"};\n' + protected
        )
        rc, out, err = run_node(wrapper)
        self.assertEqual(rc, 0, err)

        protected2 = self.protect(domain_lock=["example.com"])
        wrapper2 = (
            'globalThis.location = {hostname: "EXAMPLE.COM"};\n' + protected2
        )
        rc, out, err = run_node(wrapper2)
        self.assertEqual(rc, 0, err)

    def test_domain_lock_case_insensitive_still_blocks(self):
        # A non-listed hostname must still be blocked, whatever its case.
        protected = self.protect(domain_lock=["example.com"])
        wrapper = (
            'globalThis.location = {hostname: "EVIL.COM"};\n' + protected
        )
        rc, _, err = run_node(wrapper)
        self.assertNotEqual(rc, 0)
        self.assertIn("domain not allowed", err)


class TestM5JsFileErrors(AuditR1JsTestBase):
    def test_protect_js_file_non_utf8_input_raises_protection_error(self):
        # A latin-1 file must fail with a clean ProtectionError, not a
        # raw UnicodeDecodeError traceback.
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in.js")
            dst = os.path.join(tmp, "out.js")
            with open(src, "wb") as f:
                f.write(b"var s = '\xe9';\nconsole.log('latin');\n")
            with self.assertRaises(ProtectionError):
                protect_js_file(src, dst, {"seed": 7})

    def test_protect_js_file_missing_parent_dir_created(self):
        # Parity with the Python engine: a missing destination parent
        # directory is created instead of raising FileNotFoundError.
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in.js")
            dst = os.path.join(tmp, "a", "b", "out.js")
            with open(src, "w", encoding="utf-8") as f:
                f.write("console.log(40 + 2);\n")
            protect_js_file(src, dst, {"seed": 7})
            with open(dst, encoding="utf-8") as f:
                protected = f.read()
            self.assertBehaviorPreserved(protected, "console.log(40 + 2);\n")


if __name__ == "__main__":
    unittest.main()
