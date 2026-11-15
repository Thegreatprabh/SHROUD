"""Python wrapper for the SHROUD JavaScript engine.

The real transforms live in Node (``shroud/js/node/protect.js``) on the
acorn AST; this module validates the environment, derives the per-build
string-encryption key, and shells out to Node.

Honest limit: protection raises the cost of reversal, it does not make it
impossible. The key and the encrypted-string table ship inside the output.
"""

import json
import os
import random
import shutil
import subprocess
import tempfile
from pathlib import Path

from shroud.errors import ProtectionError

_NODE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "node")
_PROTECT_JS = os.path.join(_NODE_DIR, "protect.js")
_REQUIRED_PKGS = ("acorn", "astring")

DEFAULT_OPTIONS = {
    "rename": True,
    "string_encryption": True,
    "flatten": True,
    "literal_encoding": True,
    "dead_code": True,
    "anti_debug": True,
    "integrity": True,
    "domain_lock": [],
    "seed": None,
}


def _merge_options(options):
    merged = dict(DEFAULT_OPTIONS)
    if options:
        unknown = set(options) - set(DEFAULT_OPTIONS) - {"key"}
        if unknown:
            raise ProtectionError(
                "unknown protect_js option(s): " + ", ".join(sorted(unknown))
            )
        merged.update(options)
    if merged["domain_lock"] is None:
        merged["domain_lock"] = []
    if not isinstance(merged["domain_lock"], (list, tuple)):
        raise ProtectionError("domain_lock must be a list of hostnames")
    merged["domain_lock"] = [str(h) for h in merged["domain_lock"]]
    return merged


def ensure_node_deps():
    """Make sure Node, npm and the acorn/astring deps are available.

    Installs the Node deps automatically (``npm install``) when
    ``node_modules`` is missing. Raises ProtectionError with install
    instructions when Node/npm are absent or the install fails.
    """
    node = shutil.which("node")
    npm = shutil.which("npm")
    if not node or not npm:
        raise ProtectionError(
            "Node.js and npm are required for the JavaScript engine but were "
            "not found on PATH. Install Node.js >= 18 from "
            "https://nodejs.org/ and make sure `node` and `npm` are on PATH."
        )
    missing = [
        pkg
        for pkg in _REQUIRED_PKGS
        if not os.path.isdir(os.path.join(_NODE_DIR, "node_modules", pkg))
    ]
    if not missing:
        return
    result = subprocess.run(
        [npm, "install", "--prefix", _NODE_DIR],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ProtectionError(
            "Failed to install JavaScript engine dependencies "
            f"({', '.join(missing)}) in {_NODE_DIR}: "
            f"{result.stderr.strip() or result.stdout.strip()}. "
            "Try running `npm install` in that directory manually."
        )
    for pkg in missing:
        if not os.path.isdir(os.path.join(_NODE_DIR, "node_modules", pkg)):
            raise ProtectionError(
                f"npm install reported success but {pkg} is still missing "
                f"from {_NODE_DIR}/node_modules."
            )


def _derive_key(seed):
    """Per-build XOR key: deterministic from the seed, else fresh random.

    The key is never hardcoded; it is generated per build and embedded in
    the runtime so the protected file can decode its own strings.
    """
    if seed is not None:
        rng = random.Random(seed)
        return bytes(rng.randrange(256) for _ in range(16))
    return os.urandom(16)


def protect_js(source: str, options: dict) -> str:
    """Protect a JavaScript source string; return the protected source."""
    opts = _merge_options(options)
    ensure_node_deps()
    node_opts = dict(opts)
    node_opts["key"] = _derive_key(opts["seed"]).hex()
    with tempfile.TemporaryDirectory(prefix="shroud-js-") as tmp:
        src_path = os.path.join(tmp, "input.js")
        dst_path = os.path.join(tmp, "output.js")
        opt_path = os.path.join(tmp, "options.json")
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(source)
        with open(opt_path, "w", encoding="utf-8") as f:
            json.dump(node_opts, f)
        result = subprocess.run(
            [shutil.which("node"), _PROTECT_JS,
             "--input", src_path, "--output", dst_path,
             "--options", opt_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ProtectionError(
                "JavaScript protection failed: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        if not os.path.exists(dst_path):
            raise ProtectionError(
                "JavaScript protection failed: Node exited 0 but produced "
                "no output file."
            )
        with open(dst_path, encoding="utf-8") as f:
            return f.read()


def protect_js_file(src_path, dst_path, options) -> None:
    """Protect the file at ``src_path`` and write the result to ``dst_path``.

    The destination parent directory is created when missing (parity
    with the Python engine). Read/write failures raise ProtectionError.
    """
    src = Path(src_path)
    dst = Path(dst_path)
    try:
        source = src.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ProtectionError("cannot read %s: %s" % (src, exc)) from exc
    protected = protect_js(source, options)
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(protected, encoding="utf-8")
    except OSError as exc:
        raise ProtectionError("cannot write %s: %s" % (dst, exc)) from exc
