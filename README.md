# SHROUD

SHROUD is a command-line code protector for JavaScript and Python. It
rewrites source code so that it is harder to read and harder to reverse
engineer, while keeping its behaviour identical: the protected program
prints the same output, exits with the same code, and reads the same
input as the original.

```text
original.js  ──►  shroud protect  ──►  protected.js   (same behaviour)
original.py  ──►  shroud protect  ──►  protected.py   (same behaviour)
```

## What SHROUD is — and what it is not

SHROUD raises the cost of reversing your code. It does not make
reversal impossible, and no tool can: **no protection is literally
un-reverse-engineerable**. Anyone who receives the protected files can
study them for as long as they like, and a determined attacker with
full access can eventually undo every transform below.

Be clear about the threat model before relying on SHROUD:

- **The decryption key lives in the delivered runtime.** Protected
  Python code ships with `shroud_runtime.py`, and protected JavaScript
  ships with its decoder inline. The key that unscrambles the strings
  is in the same delivery as the scrambled strings. SHROUD hides the
  key among the transforms; it does not — and cannot — keep it from
  someone who owns the files.
- **Domain lock and integrity checks are speed bumps, not security
  boundaries.** They stop casual copying and casual tampering. They do
  not stop an attacker who edits the check out of the delivered code,
  which is always possible because the check itself is delivered.
- **Anti-debug checks detect common debuggers; they do not defeat a
  skilled analyst.** They raise the effort required, nothing more.
- **SHROUD protects code, not data.** Configuration files, assets,
  embedded credentials, and API keys shipped next to the code are not
  protected by SHROUD. Do not ship secrets and expect SHROUD to hide
  them.

Use SHROUD to deter casual copying, to slow down competitors, and to
make casual tampering fail loudly. Do not use it as the only line of
defence for anything whose secrecy must hold against a motivated
attacker. For that, keep the sensitive logic on a server you control.

## Install

Requirements: Python 3.9 or newer (developed and tested on Python
3.12.3), PyYAML, and Node.js for the JavaScript engine (developed and
tested on Node v24.22.1).

```bash
git clone https://github.com/Thegreatprabh/SHROUD.git
cd SHROUD
python3 -m venv .venv
.venv/bin/pip install -e .
```

This installs the `shroud` command into the virtual environment
(activate it with `source .venv/bin/activate`, or call
`.venv/bin/shroud` directly). On systems where plain `pip` refuses to
install into the system Python (PEP 668, "externally managed
environment"), the virtual environment above is the way to install it.

Without installing, the CLI also runs from the repository root as
`python3 -m shroud`.

### Node dependencies (JavaScript engine only)

The JavaScript engine parses code with `esprima` and re-emits it with
`escodegen`. If the JS engine reports missing Node dependencies,
install them from the repository root:

```bash
cd shroud/js/node && npm install
```

`shroud protect` and `shroud demo` check for these dependencies
automatically before protecting JavaScript; the manual install above
is only needed if that check fails.

## Quickstart

Run from the repository root. The commands below protect the bundled
demos, run them, and verify the protected copies behave identically to
the originals. Protected output goes to a scratch directory,
`/tmp/shroud-demo`.

```bash
# Protect both bundled demos and compare original vs protected output.
python3 -m shroud demo

# JavaScript: protect the demo, run the protected copy, verify it.
python3 -m shroud protect shroud/demo/demo.js --engine js --out /tmp/shroud-demo/protected-js
node /tmp/shroud-demo/protected-js/demo.js
python3 -m shroud verify shroud/demo/demo.js /tmp/shroud-demo/protected-js/demo.js

# Python: protect the demo, run the protected copy, verify it.
python3 -m shroud protect shroud/demo/demo.py --engine py --out /tmp/shroud-demo/protected-py
python3 /tmp/shroud-demo/protected-py/demo.py
python3 -m shroud verify shroud/demo/demo.py /tmp/shroud-demo/protected-py/demo.py

# Inspect what protections a protected file contains.
python3 -m shroud inspect /tmp/shroud-demo/protected-js/demo.js
```

Expected results: `shroud demo` prints both outputs for each demo and
`JavaScript demo: MATCH` / `Python demo: MATCH`; each `shroud verify`
prints `PASS`; `shroud inspect` lists the detected protections, for
example:

```text
file: /tmp/shroud-demo/protected-js/demo.js
engine guess: js
string decoder: present
flattened dispatch: present
domain lock: absent
integrity check: present
anti-debug: present
```

(The exact markers present depend on the options in force; the example
above is from the default configuration, with no domain lock set.)

## Usage

```text
shroud protect <input> --engine js|py|auto --out <dir> [--config FILE] [--seed N]
shroud inspect <file>
shroud verify <original> <protected>
shroud demo [--engine js|py|all]
```

### `shroud protect`

Protects a single `.js` or `.py` file, or every `.js`/`.py` file in a
directory (scanned recursively; other files are ignored).

- `--engine js|py|auto` (default `auto`): `auto` picks the engine from
  the file extension — `.js` goes to the JavaScript engine, `.py` to
  the Python engine.
- `--out <dir>` (required): output directory, created if needed.
  Protected files keep their original file names.
- `--config FILE`: YAML configuration file (see below). Without it,
  the built-in defaults are used.
- `--seed N`: seed for deterministic protection. The same seed and the
  same input produce the same protected output.

For Python output, the runtime module `shroud_runtime.py` is written
once into the output directory; protected Python files import it, so
ship the whole output directory together. For a directory input, the
Python runtime is likewise written once per output directory.

On success the command prints a short summary, for example
`Protected 2 file(s) with the JavaScript + Python engine(s) into out`.
On failure it prints `Error: <message>` to stderr and exits with
code 1.

### `shroud inspect`

Reports which protections are present in a file, by looking for the
markers the engines emit: a string decoder, a flattened dispatch, a
domain lock, an integrity check, and an anti-debug check. It also
guesses the engine (`js` or `py`) from the markers. Exit code is 0
even when nothing is detected — an unprotected file simply reports
`absent` for every check.

### `shroud verify`

Runs the original and the protected file (Node for `.js`, `python3`
for `.py`) and compares stdout, stderr, and exit code. Prints `PASS`
and exits 0 when all three are identical; otherwise prints `FAIL`
with the first differing lines and exits 1. Use it after every
`protect` run: identical behaviour is the whole point, and `verify`
is how you prove it.

### `shroud demo`

Protects the bundled demo program(s) into a temporary directory, runs
the original and the protected copy of each, prints both outputs, and
reports `MATCH` or `MISMATCH` per engine. `--engine js|py|all`
(default `all`) selects which demo to run. Exits 0 only if every demo
matches.

## Configuration

Configuration is a YAML file. Every key is optional; anything left out
keeps the default. See `examples/config.example.yaml` for a commented
copy of the full file.

```yaml
seed: 1337

js:
  rename: true
  string_encryption: true
  flatten: true
  literal_encoding: true
  dead_code: true
  anti_debug: true
  integrity: true
  domain_lock: []          # e.g. ["app.example.com"]

py:
  rename: true
  string_encryption: true
  flatten: true
  literal_encoding: true
  dead_code: true
  anti_debug: true
  integrity: true
  license_key: ""          # checked against SHROUD_LICENSE_KEY at runtime
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `seed` | integer | `1337` | Seed for deterministic protection |
| `js.rename` / `py.rename` | boolean | `true` | Rename local identifiers |
| `js.string_encryption` / `py.string_encryption` | boolean | `true` | Encrypt string literals |
| `js.flatten` / `py.flatten` | boolean | `true` | Flatten control flow |
| `js.literal_encoding` / `py.literal_encoding` | boolean | `true` | Encode numeric literals |
| `js.dead_code` / `py.dead_code` | boolean | `true` | Inject dead code |
| `js.anti_debug` / `py.anti_debug` | boolean | `true` | Detect debuggers at runtime |
| `js.integrity` / `py.integrity` | boolean | `true` | Check file integrity at runtime |
| `js.domain_lock` | list of hostnames | `[]` | Allowed hostnames (JS only; empty = no lock) |
| `py.license_key` | string | `""` | License key hash (Python only; empty = no check) |

Validation rules (`shroud/config.py`):

- A missing file, invalid YAML, or a non-mapping document raises
  `ConfigError`.
- Wrong types raise `ConfigError`: flags must be booleans (note that
  `1` is not accepted as `true`, and `true` is not accepted as the
  integer `seed`), `domain_lock` must be a list of hostnames, and
  `license_key` must be a string.
- Unknown keys **inside** an engine section (`js` / `py`) fail closed
  with `ConfigError`. A misspelled flag such as `strnig_encryption`
  must fail loudly instead of silently leaving a protection off.
- Unknown **top-level** keys only produce a warning and are ignored,
  so a config file may carry forward-compatible metadata without
  breaking older versions of SHROUD.
- A CLI `--seed` overrides the config file's `seed`; any other CLI
  flag overrides the matching config value. `load_config(None)`
  returns the defaults.

## How each protection works

### JavaScript engine

- **Rename.** Local identifiers are replaced with short generated
  names, so the code no longer reads as the author's vocabulary.
- **String encryption.** String literals are replaced with encoded
  blobs decoded at runtime by an inline `_shroud_dec` decoder.
- **Control-flow flattening.** Straight-line code is rewritten into a
  `switch`-based state dispatch, so the original order of operations
  is no longer visible in the file layout.
- **Literal encoding.** Numeric literals are rewritten as arithmetic
  expressions (for example `42` becomes `21 + 21`).
- **Dead code.** Side-effect-free junk statements and never-called
  functions are added as noise.
- **Anti-debug.** A `debugger` check is emitted so the code reacts
  when run under a debugger.
- **Integrity.** A SHA-256 hash of the encrypted-string table is
  embedded and checked at runtime so tampering with the table fails
  loudly.
- **Domain lock.** When `domain_lock` lists hostnames, the code checks
  `location.hostname` at runtime and refuses to run elsewhere.

### Python engine

- **Rename.** Scope-aware renaming of local variables and function
  parameters to `_sXXXX` names. Module-level names, class names,
  attribute names, imported names, dunder names, `self`/`cls`,
  `global`/`nonlocal` names, and names read by a nested scope
  (closures) are never renamed, so behaviour is preserved.
- **String encryption.** Plain string constants are replaced with
  `shroud_runtime.dec("<base64>")` calls. The runtime XOR-decodes
  them with the key embedded in the delivered `shroud_runtime.py`.
- **Control-flow flattening.** A function body is rewritten into a
  `while True:` loop with an `__state` dispatch; each top-level
  statement becomes one state. Top-level `return` becomes an
  assignment to `__ret` followed by an exit state.
- **Literal encoding.** Integer constants (except `0`, `1`, `True`,
  `False`, and `None`) are rewritten as additions, for example
  `42` becomes `21 + 21`.
- **Dead code.** `if False:` blocks and one never-called junk function
  are added per file; all of it is side-effect-free.
- **Anti-debug.** The runtime raises if a tracer or debugger is
  attached (`sys.gettrace()` is not `None`).
- **Integrity.** The runtime re-hashes the protected files against an
  embedded SHA-256 manifest and raises on any mismatch or missing
  file (fail closed).
- **License key.** When `py.license_key` is set, the runtime requires
  the environment variable `SHROUD_LICENSE_KEY` and compares its
  SHA-256 hash against the embedded hash.

## Limitations

Verified against the Python engine implementation
(`shroud/py/transforms.py`, `shroud/py/runtime_template.py`):

- **Python string encryption skips** docstrings, f-strings (the whole
  f-string is left alone, so its formatting behaviour cannot change),
  strings used as dict keys, and strings in annotations.
- **Python literal encoding skips** `True`/`False`/`None`, dict keys,
  annotation integers, and the values `0` and `1`.
- **Python flattening skips** generator functions (any `yield`), async
  functions, and functions that use `global` or `nonlocal`. Returns
  nested inside a flattened chunk stay as plain `return` statements.
- **Python renaming is deliberately conservative** (see the never-
  rename list above). Code that relies on dynamic name lookup
  (`globals()`, `getattr` by string, `eval`) keeps working because the
  names it looks up are not renamed — but those same names stay
  readable in the protected output.
- **The Python runtime is delivered with the code.** `shroud_runtime.py`
  contains the decryption key in base64, the integrity manifest, and
  the license hash. Anyone with the output directory can read it.

For the JavaScript engine, the same honest limits apply in general
form: constructs the engine cannot rewrite safely are left as-is
rather than risking broken code, so dynamically computed names,
`eval`, and template literals with embedded expressions stay more
readable than plain code; and the decoder and its key ship inside the
protected file itself. Domain lock and integrity checks only run in
the environment the code executes in, and can be removed by editing
the delivered file.

Common to both engines: SHROUD does not protect data files, does not
hide secrets embedded in the source, and does not defend against an
attacker inspecting the running process's memory. Protected code must
still be tested with `shroud verify` — identical behaviour is the
contract, and verification is part of using the tool.

## Inventory

| File | What it does |
| --- | --- |
| `shroud/__init__.py` | Package marker; `__version__ = "0.1.0"` |
| `shroud/__main__.py` | `python -m shroud` entry point |
| `shroud/cli.py` | The CLI: `protect`, `inspect`, `verify`, `demo`; exit codes and `Error:` reporting |
| `shroud/config.py` | YAML config loading, validation, defaults, `merge_options` |
| `shroud/errors.py` | `ShroudError`, `ConfigError`, `ProtectionError` |
| `shroud/demo/demo.js` | Bundled JavaScript demo (strings, arithmetic, control flow, functions, arrays) |
| `shroud/demo/demo.py` | Bundled Python demo (strings, arithmetic, control flow, functions, dicts/lists, a class) |
| `shroud/js/engine.py` | JavaScript engine wrapper: `protect_js`, `protect_js_file`, `ensure_node_deps` |
| `shroud/js/__init__.py` | Package marker for the JavaScript engine |
| `shroud/js/node/package.json` | Node dependencies for the JS engine (`esprima`, `escodegen`) |
| `shroud/js/node/package-lock.json` | Pinned Node dependency versions |
| `shroud/js/node/protect.js` | JavaScript transforms on the esprima AST (rename, string encryption, flattening, literal encoding, dead code) and runtime assembly |
| `shroud/js/runtime.js` | Runtime template prepended to protected JavaScript (string decoder, integrity, anti-debug, domain lock) |
| `shroud/py/engine.py` | Python engine wrapper: `protect_py`, `protect_py_file`, `protect_py_dir`, `write_runtime` |
| `shroud/py/__init__.py` | Package marker; re-exports the Python engine functions |
| `shroud/py/transforms.py` | Python AST transforms (rename, string encryption, literal encoding, flattening, dead code) |
| `shroud/py/runtime_template.py` | Source template for the delivered `shroud_runtime.py` |
| `examples/config.example.yaml` | Commented example configuration file |
| `pyproject.toml` | Project metadata, `pyyaml` dependency, `shroud` console script |
| `LICENSE` | MIT License, Copyright (c) 2026 Prabhjot Singh |
| `.gitignore` | Ignores `.venv/`, `__pycache__/`, `*.pyc`, `node_modules/`, `*.egg-info/`, `dist/`, `build/` |
| `tests/test_cli.py` | CLI tests: `protect`, `inspect`, `verify`, `demo`, in-process and via `python -m shroud` |
| `tests/test_config.py` | Config tests: defaults, example file, invalid YAML, wrong types, unknown keys, merging |
| `tests/test_e2e.py` | End-to-end tests for both engines, plus the README quickstart commands run verbatim |
| `tests/test_js.py` | JavaScript engine tests: one class per transform, plus behaviour equivalence via Node |
| `tests/test_py.py` | Python engine tests: one class per transform, plus runtime checks (integrity, anti-debug, license) |

## Tests

Tests are `unittest` only (run from the repository root):

```bash
python3 -m unittest discover -s tests -v
```

`tests/test_config.py` covers configuration without any engine.
`tests/test_cli.py` covers each CLI command in-process (via `main()`)
and via subprocess (`python -m shroud`), using temporary directories
— tests never write into the repository tree. `tests/test_e2e.py`
protects both bundled demos, runs the originals against the protected
copies, and runs every README quickstart command verbatim.

## License

MIT — see `LICENSE`.
