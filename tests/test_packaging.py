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


if __name__ == "__main__":
    unittest.main()
