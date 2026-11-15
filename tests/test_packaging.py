"""Tests for SHROUD packaging (pyproject.toml package-data).

Regression test for the wheel-packaging defect: the built wheel
``shroud-0.1.0-py3-none-any.whl`` shipped without the JavaScript engine's
data files (``shroud/js/runtime.js`` and ``shroud/js/node/protect.js``,
``package.json``, ``package-lock.json``) because ``pyproject.toml`` only
declared ``shroud = ["demo/*"]``. The JS engine locates those files via
``Path(__file__)`` (``shroud/js/engine.py``) and ``protect.js`` reads
``../runtime.js``, so a non-editable ``pip install shroud`` broke the JS
engine; only editable installs worked because they link to the source tree.

The test builds a real wheel from a clean copy of the repo in a temp dir
and asserts the files are inside it, so it fails on the old package-data
and passes after the fix.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Files the JS engine needs next to the installed package (see
# shroud/js/engine.py: _NODE_DIR/_PROTECT_JS and shroud/js/node/protect.js
# reading ../runtime.js; ensure_node_deps() runs `npm install` in the node
# dir, which needs package.json + package-lock.json).
REQUIRED_WHEEL_FILES = (
    "shroud/js/runtime.js",
    "shroud/js/node/protect.js",
    "shroud/js/node/package.json",
    "shroud/js/node/package-lock.json",
)

# Copy the repo to a temp dir for the wheel build, leaving out the venv,
# build artefacts and the (gitignored, auto-installed) node_modules.
_COPY_IGNORE = shutil.ignore_patterns(
    ".venv", "build", "*.egg-info", "__pycache__", "node_modules",
    ".git", "dist",
)


def _build_wheel(src_dir, out_dir):
    """Build a wheel from ``src_dir`` into ``out_dir``; return its path."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(src_dir),
         "--no-deps", "-w", str(out_dir)],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise AssertionError(
            "pip wheel failed:\n" + result.stdout + "\n" + result.stderr
        )
    wheels = sorted(pathlib.Path(out_dir).glob("*.whl"))
    if not wheels:
        raise AssertionError(f"no wheel produced in {out_dir}")
    return wheels[0]


class TestWheelPackaging(unittest.TestCase):
    def test_wheel_contains_js_data_files(self):
        with tempfile.TemporaryDirectory(prefix="shroud-wheel-") as tmp:
            tmp = pathlib.Path(tmp)
            src = tmp / "src"
            out = tmp / "out"
            out.mkdir()
            shutil.copytree(REPO_ROOT, src, ignore=_COPY_IGNORE)
            wheel_path = _build_wheel(src, out)
            with zipfile.ZipFile(wheel_path) as zf:
                names = set(zf.namelist())
            missing = [f for f in REQUIRED_WHEEL_FILES if f not in names]
            self.assertEqual(
                missing, [],
                f"wheel {wheel_path.name} is missing JS data files: "
                f"{missing} (wheel contents: {sorted(names)})",
            )

    def test_wheel_does_not_bundle_node_modules(self):
        # The node_modules tree is auto-installed by ensure_node_deps() on
        # first use and must not be swept into the wheel by the
        # package-data globs.
        with tempfile.TemporaryDirectory(prefix="shroud-wheel-") as tmp:
            tmp = pathlib.Path(tmp)
            src = tmp / "src"
            out = tmp / "out"
            out.mkdir()
            shutil.copytree(REPO_ROOT, src, ignore=_COPY_IGNORE)
            wheel_path = _build_wheel(src, out)
            with zipfile.ZipFile(wheel_path) as zf:
                leaked = [n for n in zf.namelist()
                          if n.startswith("shroud/js/node/node_modules/")]
            self.assertEqual(
                leaked, [],
                f"wheel {wheel_path.name} bundles node_modules: {leaked[:5]}",
            )


def _run(cmd, timeout, **kwargs):
    """Run ``cmd``; raise AssertionError with output on failure."""
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, **kwargs
    )
    if result.returncode != 0:
        raise AssertionError(
            "command failed (%s): %s\nstdout:\n%s\nstderr:\n%s"
            % (result.returncode, " ".join(str(c) for c in cmd),
               result.stdout, result.stderr)
        )
    return result


def _npm_reachable():
    """True when the npm registry answers (needed for the JS engine's
    first-use `npm install` inside the installed wheel)."""
    try:
        result = subprocess.run(
            ["npm", "ping", "--registry", "https://registry.npmjs.org"],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class TestInstalledWheelEndToEnd(unittest.TestCase):
    def test_installed_wheel_protects_py_and_js(self):
        # L5: file-presence checks cannot catch a packaging regression
        # that breaks the installed CLI (missing entry point, missing
        # data files at runtime, missing dependency). Install the built
        # wheel into a fresh venv (non-editable, as a user would) and
        # run `shroud protect` there for both engines.
        with tempfile.TemporaryDirectory(prefix="shroud-installed-") as tmp:
            tmp = pathlib.Path(tmp)
            src = tmp / "src"
            out = tmp / "out"
            out.mkdir()
            shutil.copytree(REPO_ROOT, src, ignore=_COPY_IGNORE)
            wheel_path = _build_wheel(src, out)

            venv_dir = tmp / "venv"
            # venv creation + pip install is slow; generous timeouts.
            _run([sys.executable, "-m", "venv", str(venv_dir)], timeout=300)
            venv_python = venv_dir / "bin" / "python"
            _run(
                [str(venv_python), "-m", "pip", "install", "--quiet",
                 str(wheel_path)],
                timeout=600,
            )
            shroud_bin = venv_dir / "bin" / "shroud"
            self.assertTrue(
                shroud_bin.is_file(),
                "installed wheel provides no `shroud` console script",
            )

            work = tmp / "work"
            work.mkdir()
            (work / "small.py").write_text(
                "def add(a, b):\n    return a + b\n\nprint(add(2, 3))\n",
                encoding="utf-8",
            )
            out_dir = work / "out"
            result = _run(
                [str(shroud_bin), "protect", str(work / "small.py"),
                 "--engine", "py", "--out", str(out_dir)],
                timeout=300,
            )
            self.assertIn("Protected 1 file(s)", result.stdout)
            self.assertTrue((out_dir / "small.py").is_file())
            self.assertTrue((out_dir / "shroud_runtime.py").is_file())
            ran = _run(
                [str(venv_python), str(out_dir / "small.py")],
                timeout=60, cwd=str(out_dir),
            )
            self.assertEqual(ran.stdout, "5\n")

            # JS engine in the installed wheel: its first use runs
            # `npm install` inside the installed package dir, so it
            # needs the npm registry. Skip only the JS half when the
            # registry is unreachable (the Python half above already
            # proves the installed CLI works).
            if not _npm_reachable():
                print("npm registry unreachable; skipping JS half of "
                      "installed-wheel test")
                return
            (work / "small.js").write_text(
                "function add(a, b) { return a + b; }\n"
                "console.log(add(2, 3));\n",
                encoding="utf-8",
            )
            js_out = work / "out-js"
            result = _run(
                [str(shroud_bin), "protect", str(work / "small.js"),
                 "--engine", "js", "--out", str(js_out)],
                timeout=300,
            )
            self.assertIn("Protected 1 file(s)", result.stdout)
            ran = _run(
                ["node", str(js_out / "small.js")], timeout=60,
            )
            self.assertEqual(ran.stdout, "5\n")


if __name__ == "__main__":
    unittest.main()
