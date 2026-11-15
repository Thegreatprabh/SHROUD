"""Command-line interface for SHROUD.

Entry point: ``main()`` returns an int exit code; ``python -m shroud``
and the ``shroud`` console script both call it.

Subcommands:
  protect  protect a file or directory with the JS and/or Python engine
  inspect  report which protections are present in a protected file
  verify   run an original and a protected file and compare their output
  demo     protect the bundled demos and check they still behave the same
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from shroud.config import load_config, merge_options
from shroud.errors import ConfigError, ProtectionError

__all__ = ["main"]

_DEMO_DIR = Path(__file__).resolve().parent / "demo"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _run_file(path):
    """Run a .js file with Node or a .py file with python3.

    Returns ``(stdout, stderr, returncode)`` as text. A run that times
    out is reported as returncode 124 with a note on stderr.
    """
    path = str(path)
    if path.endswith(".js"):
        cmd = ["node", path]
    elif path.endswith(".py"):
        cmd = [sys.executable, path]
    else:
        raise ProtectionError("cannot run %s: unsupported extension" % path)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
    except subprocess.TimeoutExpired:
        return "", "timed out after 30s running %s" % path, 124
    except FileNotFoundError as exc:
        raise ProtectionError("cannot run %s: %s" % (path, exc))
    return result.stdout, result.stderr, result.returncode


def _first_diff_lines(left, right, limit=5):
    """First differing lines between two texts, for a FAIL report."""
    left_lines = left.splitlines()
    right_lines = right.splitlines()
    diffs = []
    for i, (a, b) in enumerate(zip(left_lines, right_lines)):
        if a != b:
            diffs.append(
                "line %d:\n  original:  %s\n  protected: %s" % (i + 1, a, b)
            )
            if len(diffs) >= limit:
                break
    if len(left_lines) != len(right_lines) and len(diffs) < limit:
        diffs.append(
            "line counts differ: original has %d lines, protected has %d"
            % (len(left_lines), len(right_lines))
        )
    return diffs


def _engine_for_path(path):
    suffix = Path(path).suffix.lower()
    if suffix == ".js":
        return "js"
    if suffix == ".py":
        return "py"
    return None


def _load_js_engine():
    try:
        from shroud.js.engine import (  # noqa: F401
            ensure_node_deps,
            protect_js_file,
        )
    except ImportError as exc:
        raise ProtectionError("JS engine is not available: %s" % exc)
    return ensure_node_deps, protect_js_file


def _load_py_engine():
    try:
        from shroud.py.engine import protect_py_file, write_runtime  # noqa: F401
    except ImportError as exc:
        raise ProtectionError("Python engine is not available: %s" % exc)
    return protect_py_file, write_runtime


# ---------------------------------------------------------------------------
# protect
# ---------------------------------------------------------------------------

def _cmd_protect(args):
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1

    overrides = {"seed": args.seed} if args.seed is not None else {}
    input_path = Path(args.input)
    out_dir = Path(args.out)
    if not input_path.exists():
        print("Error: input not found: %s" % args.input, file=sys.stderr)
        return 1

    # Collect (source, engine) pairs.
    jobs = []
    if input_path.is_file():
        engine = args.engine
        if engine == "auto":
            engine = _engine_for_path(input_path)
            if engine is None:
                print(
                    "Error: cannot detect engine for %s "
                    "(expected a .js or .py file)" % args.input,
                    file=sys.stderr,
                )
                return 1
        jobs.append((input_path, engine))
    else:
        for root, _dirs, files in os.walk(input_path):
            for name in sorted(files):
                src = Path(root) / name
                engine = _engine_for_path(src)
                if engine is None:
                    continue
                if args.engine != "auto" and engine != args.engine:
                    continue
                jobs.append((src, engine))

    if not jobs:
        print(
            "Error: no .js or .py files found in %s" % args.input,
            file=sys.stderr,
        )
        return 1

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        js_deps_ready = False
        py_runtime_written = False
        protected = 0
        engines_used = []
        for src, engine in jobs:
            options = merge_options(config, engine, overrides)
            if engine == "js":
                if not js_deps_ready:
                    ensure_node_deps, protect_js_file = _load_js_engine()
                    ensure_node_deps()
                    js_deps_ready = True
                dst = out_dir / src.name
                protect_js_file(str(src), str(dst), options)
            else:
                protect_py_file, write_runtime = _load_py_engine()
                dst = out_dir / src.name
                protect_py_file(str(src), str(dst), options)
                if not py_runtime_written:
                    write_runtime(str(out_dir), options)
                    py_runtime_written = True
            protected += 1
            if engine not in engines_used:
                engines_used.append(engine)
    except (ProtectionError, ConfigError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1

    engine_label = " + ".join(
        {"js": "JavaScript", "py": "Python"}[e] for e in engines_used
    )
    print(
        "Protected %d file(s) with the %s engine(s) into %s"
        % (protected, engine_label, out_dir)
    )
    return 0


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------
#
# These checks are state-aware, not plain substring matches. The JS
# runtime template always contains the code for the domain lock, the
# integrity check, and the anti-debug check (guarded, dormant when the
# protection is off), so merely finding those words would report a
# protection as "present" when it is not actually active. Each check
# therefore reads the value the build substituted into the template:
# a non-empty domains list, a non-empty integrity hash, a `true`
# anti-debug guard, and a non-empty string table.


def _js_string_table_active(text):
    m = re.search(r"var _shroud_table = \[([^\]]*)\]", text)
    return bool(m and m.group(1).strip())


def _js_domains_locked(text):
    m = re.search(r"var _domains = \[([^\]]*)\]", text)
    return bool(m and m.group(1).strip())


def _js_integrity_active(text):
    m = re.search(r'var _shroud_integrity = "([^"]*)"', text)
    return bool(m and m.group(1))


def _js_anti_debug_active(text):
    m = re.search(
        r"if \((true|false)\) \{\s*\(function \(\) \{\s*var _t0 = Date\.now\(\);\s*debugger;",
        text,
    )
    return bool(m and m.group(1) == "true")


def _inspect_checks(text):
    """Return [(label, present)] for a file's text.

    Note: for protected Python files, the integrity and anti-debug
    checks live in the sibling shroud_runtime.py, not in the file
    itself, so they report absent here by design.
    """
    return [
        (
            "string decoder",
            ("_shroud_dec" in text and _js_string_table_active(text))
            or "shroud_runtime.dec" in text,
        ),
        (
            "flattened dispatch",
            "_shroud_state" in text or "__state" in text,
        ),
        ("domain lock", _js_domains_locked(text)),
        ("integrity check", _js_integrity_active(text)),
        ("anti-debug", _js_anti_debug_active(text)),
    ]


def _cmd_inspect(args):
    path = Path(args.file)
    if not path.is_file():
        print("Error: file not found: %s" % args.file, file=sys.stderr)
        return 1
    text = path.read_text(encoding="utf-8", errors="replace")

    # Engine guess from markers first, file extension as a fallback.
    if "shroud_runtime" in text or "shroud_runtime.dec" in text:
        engine = "py"
    elif "_shroud_dec" in text:
        engine = "js"
    elif path.suffix.lower() == ".py":
        engine = "py"
    elif path.suffix.lower() == ".js":
        engine = "js"
    else:
        engine = "unknown"

    print("file: %s" % args.file)
    print("engine guess: %s" % engine)
    for label, present in _inspect_checks(text):
        print("%s: %s" % (label, "present" if present else "absent"))
    return 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def _compare_runs(original, protected):
    """Run both files; return (passed, report_lines)."""
    try:
        out1, err1, code1 = _run_file(original)
        out2, err2, code2 = _run_file(protected)
    except ProtectionError as exc:
        return False, ["Error: %s" % exc]
    if out1 == out2 and err1 == err2 and code1 == code2:
        return True, []
    report = []
    if code1 != code2:
        report.append(
            "exit code differs: original=%d protected=%d" % (code1, code2)
        )
    if out1 != out2:
        report.append("stdout differs:")
        report.extend(_first_diff_lines(out1, out2))
    if err1 != err2:
        report.append("stderr differs:")
        report.extend(_first_diff_lines(err1, err2))
    return False, report


def _cmd_verify(args):
    for label, path in (("original", args.original), ("protected", args.protected)):
        if not Path(path).is_file():
            print("Error: %s file not found: %s" % (label, path), file=sys.stderr)
            return 1
    passed, report = _compare_runs(args.original, args.protected)
    if passed:
        print("PASS")
        return 0
    print("FAIL")
    for line in report:
        print(line)
    return 1


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

def _cmd_demo(args):
    wanted = ["js", "py"] if args.engine == "all" else [args.engine]
    overall_ok = True
    for engine in wanted:
        demo_src = _DEMO_DIR / ("demo.js" if engine == "js" else "demo.py")
        if not demo_src.is_file():
            print("Error: bundled demo not found: %s" % demo_src, file=sys.stderr)
            overall_ok = False
            continue
        label = "JavaScript" if engine == "js" else "Python"
        try:
            config = load_config(None)
            options = merge_options(config, engine, {})
            with tempfile.TemporaryDirectory(prefix="shroud-demo-") as tmp:
                dst = Path(tmp) / demo_src.name
                if engine == "js":
                    ensure_node_deps, protect_js_file = _load_js_engine()
                    ensure_node_deps()
                    protect_js_file(str(demo_src), str(dst), options)
                else:
                    protect_py_file, write_runtime = _load_py_engine()
                    protect_py_file(str(demo_src), str(dst), options)
                    write_runtime(tmp, options)
                orig_out, orig_err, orig_code = _run_file(demo_src)
                prot_out, prot_err, prot_code = _run_file(dst)
        except (ProtectionError, ConfigError) as exc:
            print("Error: %s" % exc, file=sys.stderr)
            overall_ok = False
            continue
        match = (
            orig_out == prot_out and orig_err == prot_err
            and orig_code == prot_code
        )
        print("--- %s demo ---" % label)
        print("original output:")
        print(orig_out, end="" if orig_out.endswith("\n") else "\n")
        print("protected output:")
        print(prot_out, end="" if prot_out.endswith("\n") else "\n")
        print("%s demo: %s" % (label, "MATCH" if match else "MISMATCH"))
        if not match:
            overall_ok = False
    return 0 if overall_ok else 1


# ---------------------------------------------------------------------------
# argument parsing / entry point
# ---------------------------------------------------------------------------

def _build_parser():
    parser = argparse.ArgumentParser(
        prog="shroud",
        description="SHROUD — protect JavaScript and Python code.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_protect = sub.add_parser("protect", help="protect a file or directory")
    p_protect.add_argument("input", help=".js/.py file or a directory")
    p_protect.add_argument(
        "--engine", choices=["js", "py", "auto"], default="auto",
        help="engine to use (default: auto, by file extension)",
    )
    p_protect.add_argument("--out", required=True, help="output directory")
    p_protect.add_argument("--config", default=None, help="YAML config file")
    p_protect.add_argument("--seed", type=int, default=None,
                           help="seed for deterministic protection")
    p_protect.set_defaults(func=_cmd_protect)

    p_inspect = sub.add_parser(
        "inspect", help="detect which protections a file contains"
    )
    p_inspect.add_argument("file", help="protected file to inspect")
    p_inspect.set_defaults(func=_cmd_inspect)

    p_verify = sub.add_parser(
        "verify", help="compare the behaviour of an original and a protected file"
    )
    p_verify.add_argument("original", help="original file")
    p_verify.add_argument("protected", help="protected file")
    p_verify.set_defaults(func=_cmd_verify)

    p_demo = sub.add_parser(
        "demo", help="protect the bundled demo(s) and compare their output"
    )
    p_demo.add_argument(
        "--engine", choices=["js", "py", "all"], default="all",
        help="which demo to run (default: all)",
    )
    p_demo.set_defaults(func=_cmd_demo)

    return parser


def main(argv=None):
    """CLI entry point. Returns an int exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
