"""Tests for the SHROUD JavaScript engine (shroud/js).

Every transform test checks two things: the transform is present in the
protected output AND behaviour is preserved (original vs protected run
under Node, stdout compared, exit code 0).
"""

import json
import os
import re
import subprocess
import tempfile
import unittest

from shroud.errors import ProtectionError
from shroud.js.engine import ensure_node_deps, protect_js, protect_js_file

# Exercises: functions, string literals, arithmetic, if/else, loops,
# arrays, object literals.
TEST_PROGRAM = '''"use strict";
function greet(name) {
  var msg = "Hello, " + name + "!";
  return msg;
}
function sumUpTo(n) {
  var total = 0;
  for (var i = 0; i <= n; i++) { total += i; }
  return total;
}
function classify(x) {
  if (x > 10) { return "big"; } else if (x > 5) { return "medium"; } else { return "small"; }
}
var fruits = ["apple", "banana", "cherry"];
var person = { name: "Ada", age: 36, city: "Paris" };
var doubled = [];
for (var k = 0; k < fruits.length; k++) { doubled.push(fruits[k] + fruits[k]); }
var count = 0;
while (count < 3) { count = count + 1; }
console.log(greet("World"));
console.log(sumUpTo(5));
console.log(classify(12), classify(7), classify(2));
console.log(fruits.length, fruits[1]);
console.log(person.name, person.age + 6);
console.log(doubled.join(","));
console.log(count);
console.log("done", 42);
'''

NODE = "node"


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


class JsEngineTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_node_deps()
        rc, cls.expected_stdout, stderr = run_node(TEST_PROGRAM)
        assert rc == 0, "test program itself must run cleanly: " + stderr

    def protect(self, source=TEST_PROGRAM, **overrides):
        options = {"seed": 7}
        options.update(overrides)
        return protect_js(source, options)

    def assertBehaviorPreserved(self, protected, source=TEST_PROGRAM):
        rc, out, err = run_node(protected)
        self.assertEqual(rc, 0, "protected code must exit 0: " + err)
        _, expected, _ = run_node(source)
        self.assertEqual(out, expected)

    def assertWordAbsent(self, text, word):
        self.assertIsNone(
            re.search(r"\b" + re.escape(word) + r"\b", text),
            "expected %r to be absent from protected output" % word,
        )


class TestBehaviorPreserved(JsEngineTestBase):
    def test_all_transforms_on(self):
        protected = self.protect()
        rc, out, err = run_node(protected)
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, self.expected_stdout)

    def test_protect_js_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in.js")
            dst = os.path.join(tmp, "out.js")
            with open(src, "w", encoding="utf-8") as f:
                f.write(TEST_PROGRAM)
            protect_js_file(src, dst, {"seed": 7})
            with open(dst, encoding="utf-8") as f:
                protected = f.read()
            self.assertBehaviorPreserved(protected)

    def test_invalid_js_raises(self):
        with self.assertRaises(ProtectionError):
            protect_js("function broken( {", {"seed": 1})

    def test_all_transforms_off(self):
        protected = self.protect(
            rename=False,
            string_encryption=False,
            flatten=False,
            literal_encoding=False,
            dead_code=False,
            anti_debug=False,
            integrity=False,
        )
        self.assertNotIn("_shroud_dec(0)", protected)
        self.assertNotIn("_shroud_dec(1)", protected)
        # Only the runtime's own definition of _shroud_dec remains.
        self.assertEqual(protected.count("_shroud_dec("), 1)
        self.assertBehaviorPreserved(protected)


class TestRename(JsEngineTestBase):
    def test_locals_renamed(self):
        protected = self.protect()
        self.assertIn("_0x", protected)
        # Locals unique to one function must be gone (word-boundary match,
        # so base64/hash substrings cannot false-positive).
        self.assertWordAbsent(protected, "msg")
        self.assertWordAbsent(protected, "total")
        self.assertBehaviorPreserved(protected)

    def test_globals_and_properties_untouched(self):
        protected = self.protect()
        for name in ("console", "Math", "JSON"):
            self.assertIn(name, protected)
        # Object property names and member access survive renaming.
        self.assertIn(".name", protected)
        self.assertIn(".length", protected)
        self.assertIn("person", protected)  # program-scope: never renamed
        self.assertBehaviorPreserved(protected)


class TestStringEncryption(JsEngineTestBase):
    def test_strings_encrypted(self):
        protected = self.protect()
        self.assertIn("_shroud_dec(", protected)
        self.assertNotIn('"Hello, "', protected)
        self.assertNotIn('"apple"', protected)
        self.assertNotIn('"banana"', protected)
        self.assertNotIn('"Ada"', protected)
        self.assertBehaviorPreserved(protected)

    def test_template_literals_left_alone(self):
        # Documented limit: template literals are not encrypted.
        src = "var who = 'World';\nconsole.log(`Hello ${who}!`);\n"
        protected = self.protect(src)
        # astring re-spaces the interpolation; the template itself stays.
        self.assertIsNotNone(
            re.search(r"`Hello \$\{\s*who\s*\}!`", protected)
        )
        self.assertBehaviorPreserved(protected, src)

    def test_directive_and_property_keys_untouched(self):
        protected = self.protect()
        self.assertIn("use strict", protected)
        # Object literal key "name" stays a literal key.
        self.assertIn("name:", protected)
        self.assertBehaviorPreserved(protected)


class TestFlattening(JsEngineTestBase):
    def test_functions_flattened(self):
        protected = self.protect()
        self.assertIn("switch (_shroud_state)", protected)
        self.assertIn("while (true)", protected)
        self.assertBehaviorPreserved(protected)

    def test_let_const_functions_skipped(self):
        # Functions whose top-level statements use let/const are NOT
        # flattened (switch cases share one scope).
        src = (
            "function withLet(x) {\n"
            "  let y = x * 2;\n"
            "  return y + 1;\n"
            "}\n"
            "console.log(withLet(21));\n"
        )
        protected = self.protect(src)
        self.assertNotIn("switch (_shroud_state)", protected)
        self.assertBehaviorPreserved(protected, src)

    def test_generator_and_async_skipped(self):
        src = (
            "async function fetchy() { return 5; }\n"
            "function* gen() { yield 1; yield 2; }\n"
            "fetchy().then(function (v) { let w = v + 1; console.log(w); });\n"
            "var g = gen();\n"
            "console.log(g.next().value, g.next().value);\n"
        )
        protected = self.protect(src)
        self.assertNotIn("switch (_shroud_state)", protected)
        self.assertBehaviorPreserved(protected, src)


class TestLiteralEncoding(JsEngineTestBase):
    def test_integers_become_expressions(self):
        src = "var answer = 42;\nconsole.log(answer);\n"
        protected = self.protect(
            src,
            rename=False,
            string_encryption=False,
            flatten=False,
            dead_code=False,
            anti_debug=False,
            integrity=False,
        )
        self.assertWordAbsent(protected, "42")
        self.assertIn("+", protected)
        self.assertBehaviorPreserved(protected, src)

    def test_encoding_present_in_full_output(self):
        protected = self.protect()
        # 42 (from `console.log("done", 42)`) must not survive as a literal.
        self.assertWordAbsent(protected, "42")
        self.assertBehaviorPreserved(protected)


class TestDeadCode(JsEngineTestBase):
    def test_junk_present_and_harmless(self):
        protected = self.protect()
        self.assertIn("if (false)", protected)
        self.assertIn("_shroud_junk_fn", protected)
        self.assertBehaviorPreserved(protected)


class TestAntiDebug(JsEngineTestBase):
    def test_debugger_check_present_but_never_fires_unattached(self):
        protected = self.protect()
        self.assertIn("debugger;", protected)
        self.assertIn("debugger detected", protected)
        # No debugger attached: must exit 0 with identical output.
        self.assertBehaviorPreserved(protected)

    def test_disabled(self):
        protected = self.protect(anti_debug=False)
        # The check is still in the runtime text but guarded by `if (false)`,
        # so it never executes.
        self.assertIsNotNone(
            re.search(
                r"if \(false\) \{\s*\(function \(\) \{\s*var _t0 = Date\.now\(\);",
                protected,
            )
        )
        self.assertBehaviorPreserved(protected)


class TestIntegrity(JsEngineTestBase):
    def test_untampered_passes(self):
        self.assertBehaviorPreserved(self.protect())

    def test_tampered_table_throws(self):
        protected = self.protect()
        m = re.search(r"var _shroud_table = \[(.*?)\];", protected, re.DOTALL)
        self.assertIsNotNone(m, "string table not found in output")
        entries = re.findall(r'"([^"]+)"', m.group(1))
        self.assertTrue(entries, "string table is empty")
        first = entries[0]
        flipped = ("B" if first[0] == "A" else "A") + first[1:]
        tampered = protected.replace(
            '"%s"' % first, '"%s"' % flipped, 1
        )
        self.assertNotEqual(tampered, protected)
        rc, _, err = run_node(tampered)
        self.assertNotEqual(rc, 0)
        self.assertIn("integrity", err)

    def test_integrity_off_allows_tamper(self):
        protected = self.protect(integrity=False)
        m = re.search(r"var _shroud_table = \[(.*?)\];", protected, re.DOTALL)
        entries = re.findall(r'"([^"]+)"', m.group(1))
        first = entries[0]
        flipped = ("B" if first[0] == "A" else "A") + first[1:]
        tampered = protected.replace('"%s"' % first, '"%s"' % flipped, 1)
        # No integrity check: it runs (decoding a wrong string is not a
        # startup failure); the point is only that nothing throws here.
        rc, _, _ = run_node(tampered)
        self.assertEqual(rc, 0)


class TestDomainLock(JsEngineTestBase):
    def test_blocked_domain_throws(self):
        protected = self.protect(domain_lock=["example.com"])
        wrapper = (
            'globalThis.location = {hostname: "evil.com"};\n' + protected
        )
        rc, _, err = run_node(wrapper)
        self.assertNotEqual(rc, 0)
        self.assertIn("domain not allowed", err)

    def test_allowed_domain_runs(self):
        protected = self.protect(domain_lock=["example.com"])
        wrapper = (
            'globalThis.location = {hostname: "example.com"};\n' + protected
        )
        rc, out, err = run_node(wrapper)
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, self.expected_stdout)

    def test_no_location_skips_check(self):
        # Node has no `location`: the lock must not fire there.
        protected = self.protect(domain_lock=["example.com"])
        self.assertBehaviorPreserved(protected)


class TestRoundTrip(JsEngineTestBase):
    def test_parse_generate_identical_output(self):
        node_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "shroud", "js", "node",
        )
        script = (
            "const acorn=require('acorn');"
            "const astring=require('astring');"
            "const src=%s;"
            "const outs=[];"
            "const realLog=console.log;"
            "console.log=function(){outs.push(Array.from(arguments).join(' '));};"
            "const before=outs.length;"
            "eval(src);"
            "const first=outs.slice(before);"
            "const gen=astring.generate(acorn.parse(src,{ecmaVersion:'latest'}));"
            "const mark=outs.length;"
            "eval(gen);"
            "const second=outs.slice(mark);"
            "console.log=realLog;"
            "console.log(JSON.stringify(first)===JSON.stringify(second)"
            "?'ROUNDTRIP-OK':'ROUNDTRIP-FAIL');"
            % json.dumps(TEST_PROGRAM)
        )
        result = subprocess.run(
            [NODE, "-e", script],
            capture_output=True, text=True, timeout=30, cwd=node_dir,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ROUNDTRIP-OK", result.stdout)


class TestSeedDeterminism(JsEngineTestBase):
    def test_same_seed_identical(self):
        a = self.protect()
        b = self.protect()
        self.assertEqual(a, b)

    def test_different_seed_different(self):
        a = self.protect()
        b = protect_js(TEST_PROGRAM, {"seed": 8})
        self.assertNotEqual(a, b)

    def test_no_seed_uses_fresh_key(self):
        a = protect_js(TEST_PROGRAM, {"seed": None})
        b = protect_js(TEST_PROGRAM, {"seed": None})
        self.assertNotEqual(a, b)  # fresh os.urandom key per build
        self.assertBehaviorPreserved(a)
        self.assertBehaviorPreserved(b)


class TestUseStrict(JsEngineTestBase):
    def test_use_strict_survives_first(self):
        protected = self.protect()
        self.assertIn("use strict", protected)
        first = protected.lstrip().splitlines()[0]
        self.assertIn("use strict", first)
        self.assertBehaviorPreserved(protected)


class TestScopeEdgeCases(JsEngineTestBase):
    def test_var_inside_block_renames_consistently(self):
        src = (
            "function f(flag) {\n"
            "  if (flag) { var blockVar = 5; }\n"
            "  return blockVar + 1;\n"
            "}\n"
            "console.log(f(true));\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)

    def test_param_default_referencing_outer_local(self):
        src = (
            "function outer() {\n"
            "  var dflt = 5;\n"
            "  function inner(a) { return a + dflt; }\n"
            "  function withDefault(x) { return x; }\n"
            "  return inner(1) + withDefault(dflt);\n"
            "}\n"
            "console.log(outer());\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)

    def test_param_default_value_uses_renamed_local(self):
        src = (
            "function outer() {\n"
            "  var dflt = 5;\n"
            "  function inner(a) { return a; }\n"
            "  function withDefault(x) { return x; }\n"
            "  return inner(dflt);\n"
            "}\n"
            "console.log(outer());\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)

    def test_real_param_default_value(self):
        # `a = dflt` in the parameter list must see the renamed `dflt`.
        src = (
            "function outer() {\n"
            "  var dflt = 5;\n"
            "  function inner(a = dflt) { return a; }\n"
            "  return inner();\n"
            "}\n"
            "console.log(outer());\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)

    def test_let_in_for_loop(self):
        src = (
            "var s = 0;\n"
            "for (let i = 0; i < 4; i++) { s += i; }\n"
            "console.log(s);\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)

    def test_destructuring_with_default(self):
        # Default in a destructuring pattern must see the renamed local.
        src = (
            "function f() {\n"
            "  var fallback = 9;\n"
            "  var obj = {a: 1};\n"
            "  var {a, b = fallback} = obj;\n"
            "  return a + b;\n"
            "}\n"
            "console.log(f());\n"
        )
        self.assertBehaviorPreserved(self.protect(src), src)


if __name__ == "__main__":
    unittest.main()
