"""SHROUD Python engine — orchestration.

Honest limit: protection raises the cost of reversal; it does not make
reversal impossible. The decryption key lives in the delivered runtime
(``shroud_runtime.py``); a determined attacker with full access to the
delivered files can eventually extract it.

Interface (the CLI depends on this exactly):
  protect_py(source, options) -> str
  protect_py_file(src_path, dst_path, options) -> None
  protect_py_dir(src_dir, dst_dir, options) -> list[str]
  write_runtime(out_dir, options) -> str

Key coordination: when ``seed`` is given, the decryption key is derived
deterministically from it, so ``protect_py`` and ``write_runtime`` called
separately with the same seed agree on the key. When ``seed`` is None, a
fresh key is generated once and stored back into the options dict under
the private key ``"_shroud_key_b64"`` so later calls with the same dict
reuse it (the CLI calls protect-then-write_runtime with one dict per
file, so this keeps them in sync). Never hardcode a key in source.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import random
import secrets
from pathlib import Path

try:
    from shroud.errors import ProtectionError
except ImportError:  # pragma: no cover - standalone fallback
    class ProtectionError(Exception):  # type: ignore[no-redef]
        """Raised when protecting a file or directory fails."""


from shroud.py.runtime_template import RUNTIME_TEMPLATE
from shroud.py.transforms import (
    FlattenTransformer,
    LiteralEncodeTransformer,
    RenameTransformer,
    StringEncryptTransformer,
    add_dead_code,
)

__all__ = ["protect_py", "protect_py_dir", "protect_py_file", "write_runtime"]

_DEFAULTS = {
    "rename": True,
    "string_encryption": True,
    "flatten": True,
    "literal_encoding": True,
    "dead_code": True,
    "anti_debug": True,
    "integrity": True,
    "license_key": "",
    "seed": None,
}

_KEY_OPTION = "_shroud_key_b64"


def _options(options):
    opts = dict(_DEFAULTS)
    if options:
        opts.update(options)
    return opts


def _key_bytes(opts) -> bytes:
    """Return the per-build key, consistent across calls (see module doc)."""
    seed = opts.get("seed")
    if seed is not None:
        rng = random.Random(seed)
        try:
            return rng.randbytes(16)
        except AttributeError:  # pragma: no cover - very old Python
            return bytes(rng.getrandbits(8) for _ in range(16))
    stored = opts.get(_KEY_OPTION)
    if stored:
        return base64.b64decode(stored.encode("ascii"))
    key = secrets.token_bytes(16)
    opts[_KEY_OPTION] = base64.b64encode(key).decode("ascii")
    return key


def _ensure_key(caller_options):
    """Make sure the caller's options dict carries the per-build key.

    ``_options()`` copies the dict, so a key generated inside a copy
    would be lost to the next call. This stores the generated key in
    the dict object the caller actually passed, so protect-then-write
    with one dict agree even when ``seed`` is None. With a seed the
    key is derived deterministically and nothing needs storing.
    Returns the key bytes, or None if there is no dict to store in.
    """
    if caller_options is None or not isinstance(caller_options, dict):
        return None
    seed = caller_options.get("seed")
    if seed is not None:
        return _key_bytes({"seed": seed})
    if caller_options.get(_KEY_OPTION):
        return base64.b64decode(caller_options[_KEY_OPTION].encode("ascii"))
    key = secrets.token_bytes(16)
    caller_options[_KEY_OPTION] = base64.b64encode(key).decode("ascii")
    return key


def _license_hash(opts) -> str:
    license_key = opts.get("license_key") or ""
    if not license_key:
        return ""
    return hashlib.sha256(license_key.encode("utf-8")).hexdigest()


def protect_py(source: str, options: dict) -> str:
    """Return protected Python source.

    The output contains ``import shroud_runtime`` and a
    ``shroud_runtime.check()`` call, inserted after any leading
    ``from __future__ import ...`` statements and after the module
    docstring (if present), so future imports stay legal and
    ``__doc__`` survives. Encrypted strings call
    ``shroud_runtime.dec(...)``. Raises :class:`ProtectionError` if the
    source does not parse or the protected output does not compile.
    """
    opts = _options(options)
    _ensure_key(options)
    opts = _options(options)
    seed = opts.get("seed")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ProtectionError("invalid Python source: %s" % exc) from exc

    key = _key_bytes(opts)

    # The module docstring — the string Expr that is either the very
    # first statement or the first statement after any leading future
    # imports — is lifted out before the transforms run: the string
    # encryptor only recognises a docstring at body[0], so with a
    # future import first it would encrypt the docstring into a dec()
    # call and __doc__ would be lost. It is restored below, before
    # the runtime header is inserted after it.
    doc_node = None
    doc_index = 0
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            doc_index += 1
        else:
            break
    if doc_index < len(tree.body):
        first = tree.body[doc_index]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            doc_node = tree.body.pop(doc_index)

    if opts.get("rename"):
        tree = RenameTransformer(seed=seed).visit(tree)
        ast.fix_missing_locations(tree)
    if opts.get("literal_encoding"):
        tree = LiteralEncodeTransformer(seed=seed).visit(tree)
        ast.fix_missing_locations(tree)
    if opts.get("string_encryption"):
        tree = StringEncryptTransformer(key).visit(tree)
        ast.fix_missing_locations(tree)
    if opts.get("flatten"):
        tree = FlattenTransformer().visit(tree)
        ast.fix_missing_locations(tree)
    if opts.get("dead_code"):
        tree = add_dead_code(tree, seed=seed)
        ast.fix_missing_locations(tree)

    # Restore the lifted module docstring (see above) at its original
    # position, then insert the runtime header after the leading
    # prefix — the module docstring (only the very first statement
    # counts as one; it must stay first for __doc__ to survive) and
    # any leading `from __future__` imports (which must stay near the
    # top). A stray string literal after the future imports is skipped
    # too, so the header never lands before it.
    header = [
        ast.parse("import shroud_runtime").body[0],
        ast.parse("shroud_runtime.check()").body[0],
    ]
    if doc_node is not None:
        tree.body[doc_index:doc_index] = [doc_node]
    insert_at = 0
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            insert_at += 1
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            insert_at += 1
        else:
            break
    tree.body[insert_at:insert_at] = header
    ast.fix_missing_locations(tree)

    try:
        output = ast.unparse(tree)
    except Exception as exc:  # pragma: no cover - unparse failure
        raise ProtectionError("failed to render protected source: %s" % exc) from exc
    if output:
        output += "\n"

    # The protected output must be valid Python.
    try:
        ast.parse(output)
        compile(output, "<shroud>", "exec")
    except SyntaxError as exc:
        raise ProtectionError(
            "protected output is not valid Python: %s" % exc
        ) from exc
    return output


def protect_py_file(src_path, dst_path, options) -> None:
    """Protect one file, writing the result to ``dst_path``."""
    src = Path(src_path)
    dst = Path(dst_path)
    try:
        source = src.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ProtectionError("cannot read %s: %s" % (src, exc)) from exc
    protected = protect_py(source, options)
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(protected, encoding="utf-8")
    except OSError as exc:
        raise ProtectionError("cannot write %s: %s" % (dst, exc)) from exc


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_for_dir(out_dir: Path) -> dict:
    """{relative_posix_path: sha256} for .py files under ``out_dir``,
    excluding the runtime itself."""
    manifest = {}
    for path in sorted(out_dir.rglob("*.py")):
        if path.name == "shroud_runtime.py":
            continue
        rel = path.relative_to(out_dir).as_posix()
        manifest[rel] = _hash_file(path)
    return manifest


def write_runtime(out_dir, options) -> str:
    """Write ``shroud_runtime.py`` + ``.shroud_manifest.json`` into
    ``out_dir``; return the runtime path as a string.

    The manifest hashes the protected files, computed AFTER protection
    (call this after protecting files into ``out_dir``); it is ``{}``
    when integrity is off. The same JSON is embedded in the runtime.
    """
    opts = _options(options)
    _ensure_key(options)
    opts = _options(options)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    key = _key_bytes(opts)
    key_b64 = base64.b64encode(key).decode("ascii")
    license_hash = _license_hash(opts)
    anti_debug = bool(opts.get("anti_debug"))
    if opts.get("integrity"):
        try:
            manifest = _manifest_for_dir(out)
        except OSError as exc:
            raise ProtectionError(
                "cannot compute integrity manifest for %s: %s" % (out, exc)
            ) from exc
        manifest_json = json.dumps(manifest, sort_keys=True)
    else:
        manifest = {}
        manifest_json = ""

    runtime_source = (
        RUNTIME_TEMPLATE.replace("__SHROUD_KEY__", key_b64)
        .replace("__SHROUD_LICENSE_HASH__", license_hash)
        # repr() so the JSON is a valid Python string literal no matter
        # what characters the filenames contain (quotes, backslashes,
        # unicode); repr("") is "''", falsy, so the check stays skipped
        # when integrity is off.
        .replace("__SHROUD_INTEGRITY_MANIFEST__", repr(manifest_json))
        .replace("__SHROUD_ANTI_DEBUG__", "True" if anti_debug else "False")
    )
    # The template must not leave any placeholder behind.
    for placeholder in (
        "__SHROUD_KEY__",
        "__SHROUD_LICENSE_HASH__",
        "__SHROUD_INTEGRITY_MANIFEST__",
        "__SHROUD_ANTI_DEBUG__",
    ):
        if placeholder in runtime_source:
            raise ProtectionError(
                "runtime template placeholder not substituted: %s" % placeholder
            )
    try:
        ast.parse(runtime_source)
        compile(runtime_source, "shroud_runtime.py", "exec")
    except SyntaxError as exc:  # pragma: no cover - template bug
        raise ProtectionError("runtime template is invalid Python: %s" % exc) from exc

    runtime_path = out / "shroud_runtime.py"
    manifest_path = out / ".shroud_manifest.json"
    try:
        runtime_path.write_text(runtime_source, encoding="utf-8")
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ProtectionError("cannot write runtime in %s: %s" % (out, exc)) from exc
    return str(runtime_path)


def protect_py_dir(src_dir, dst_dir, options) -> list:
    """Protect every .py file under ``src_dir`` (recursively), mirroring
    the layout into ``dst_dir``; write ``shroud_runtime.py`` once at
    the ``dst_dir`` root; return the list of protected file paths
    written (as strings)."""
    opts = _options(options)
    src = Path(src_dir)
    dst = Path(dst_dir)
    if not src.is_dir():
        raise ProtectionError("source directory not found: %s" % src)
    dst.mkdir(parents=True, exist_ok=True)

    written = []
    for path in sorted(src.rglob("*.py")):
        rel = path.relative_to(src)
        out_path = dst / rel
        protect_py_file(str(path), str(out_path), opts)
        written.append(str(out_path))

    write_runtime(str(dst), opts)
    return written
