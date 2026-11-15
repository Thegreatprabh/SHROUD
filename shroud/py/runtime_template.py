"""Source template for the delivered ``shroud_runtime.py`` module.

Placeholders (substituted at build time by ``engine.write_runtime``):
  ``__SHROUD_KEY__``                base64-encoded decryption key bytes
  ``__SHROUD_LICENSE_HASH__``       hex sha256 of the license key, or empty
  ``__SHROUD_INTEGRITY_MANIFEST__`` repr() of the JSON string
  {relative_path: sha256}, or repr("") when integrity is off — the
  placeholder sits UNQUOTED in the template (``= __SHROUD_...__``)
  because the repr supplies the quotes, so filenames containing
  quotes, backslashes or unicode stay valid Python
  ``__SHROUD_ANTI_DEBUG__``         ``True`` or ``False``

Honest limit: this runtime protects code by raising the cost of reversal,
not by making it impossible. The key lives in this delivered file; a
determined attacker with full access can eventually extract it.
"""

RUNTIME_TEMPLATE = '''"""SHROUD runtime — decryption and integrity checks for protected code.

Honest limit: protection raises the cost of reversal; it does not make
reversal impossible. The decryption key is embedded in this file.
"""

import base64
import hashlib
import json
import os
import sys

_SHROUD_KEY = base64.b64decode("__SHROUD_KEY__")
_SHROUD_LICENSE_HASH = "__SHROUD_LICENSE_HASH__"
_SHROUD_INTEGRITY_MANIFEST = __SHROUD_INTEGRITY_MANIFEST__
_SHROUD_ANTI_DEBUG = __SHROUD_ANTI_DEBUG__


def dec(s: str) -> str:
    """Base64-decode then XOR with the embedded key, returning the string."""
    raw = base64.b64decode(s.encode("ascii"))
    key = _SHROUD_KEY
    if not key:
        return raw.decode("utf-8")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)).decode("utf-8")


def check() -> None:
    """Run the enabled protections; pass silently in a normal run.

    (a) Anti-debug: raise if a tracer/debugger is attached.
    (b) Integrity: re-hash the listed files relative to this module's
        directory and raise on any mismatch (fail closed).
    (c) License: if a license hash is set, require env var
        SHROUD_LICENSE_KEY whose sha256 matches it.
    Any disabled/empty check is skipped.
    """
    if _SHROUD_ANTI_DEBUG and sys.gettrace() is not None:
        raise RuntimeError("SHROUD: debugger/tracer detected")
    # Python 3.12+ sys.monitoring tracers are invisible to gettrace().
    # getattr guard: sys.monitoring does not exist on older Pythons.
    monitoring = getattr(sys, "monitoring", None)
    if _SHROUD_ANTI_DEBUG and monitoring is not None:
        for tool_id in range(4):
            if monitoring.get_tool(tool_id) is not None:
                raise RuntimeError("SHROUD: debugger/tracer detected")
    if _SHROUD_INTEGRITY_MANIFEST:
        try:
            manifest = json.loads(_SHROUD_INTEGRITY_MANIFEST)
        except Exception as exc:
            raise RuntimeError("SHROUD: corrupt integrity manifest") from exc
        base = os.path.dirname(os.path.abspath(__file__))
        for rel_path, expected in manifest.items():
            path = os.path.join(base, rel_path)
            if not os.path.isfile(path):
                raise RuntimeError(
                    "SHROUD: integrity check failed (missing file): %s" % rel_path
                )
            with open(path, "rb") as fh:
                actual = hashlib.sha256(fh.read()).hexdigest()
            if actual != expected:
                raise RuntimeError(
                    "SHROUD: integrity check failed: %s" % rel_path
                )
    if _SHROUD_LICENSE_HASH:
        provided = os.environ.get("SHROUD_LICENSE_KEY", "")
        if not provided:
            raise RuntimeError("SHROUD: license key required (SHROUD_LICENSE_KEY)")
        actual = hashlib.sha256(provided.encode("utf-8")).hexdigest()
        if actual != _SHROUD_LICENSE_HASH:
            raise RuntimeError("SHROUD: invalid license key")
'''
