"""Configuration loading and merging for SHROUD.

Design choice, documented as requested: unknown *top-level* keys only
produce a warning and are otherwise ignored, because a config file may
carry forward-compatible metadata (for example ``notes``) that an older
SHROUD should not choke on. Unknown keys *inside* an engine section
(``js`` / ``py``) fail closed with :class:`ConfigError`, because a
misspelled protection flag (for example ``strnig_encryption``) would
otherwise silently leave a protection off while the user believed it
was on — a silent failure in a protection tool is worse than a loud one.
"""

import copy
import warnings

import yaml

from shroud.errors import ConfigError

__all__ = ["ConfigError", "DEFAULTS", "load_config", "merge_options"]

# The built-in defaults. ``load_config(None)`` returns a deep copy of this.
DEFAULTS = {
    "seed": 1337,
    "js": {
        "rename": True,
        "string_encryption": True,
        "flatten": True,
        "literal_encoding": True,
        "dead_code": True,
        "anti_debug": True,
        "integrity": True,
        "domain_lock": [],
    },
    "py": {
        "rename": True,
        "string_encryption": True,
        "flatten": True,
        "literal_encoding": True,
        "dead_code": True,
        "anti_debug": True,
        "integrity": True,
        "license_key": "",
    },
}

# Expected type of every known key, per section. ``bool`` is checked with
# ``type(value) is bool`` (not ``isinstance``) because in Python
# ``bool`` is a subclass of ``int`` and ``True`` must not pass as a seed.
_JS_TYPES = {
    "rename": bool,
    "string_encryption": bool,
    "flatten": bool,
    "literal_encoding": bool,
    "dead_code": bool,
    "anti_debug": bool,
    "integrity": bool,
    "domain_lock": list,
}
_PY_TYPES = {
    "rename": bool,
    "string_encryption": bool,
    "flatten": bool,
    "literal_encoding": bool,
    "dead_code": bool,
    "anti_debug": bool,
    "integrity": bool,
    "license_key": str,
}
_SECTION_TYPES = {"js": _JS_TYPES, "py": _PY_TYPES}


def _check_bool(value, key, section):
    if type(value) is not bool:
        raise ConfigError(
            "config key %s.%s must be a boolean, got %s"
            % (section, key, type(value).__name__)
        )


def _validate_section(section, data):
    """Validate one engine section dict; fail closed on unknown keys."""
    if not isinstance(data, dict):
        raise ConfigError("config section %r must be a mapping" % section)
    expected = _SECTION_TYPES[section]
    for key, value in data.items():
        if key not in expected:
            raise ConfigError(
                "unknown key %r in config section %r" % (key, section)
            )
        if expected[key] is bool:
            _check_bool(value, key, section)
        elif key == "domain_lock":
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                raise ConfigError(
                    "config key js.domain_lock must be a list of hostnames"
                )
        elif key == "license_key":
            if not isinstance(value, str):
                raise ConfigError(
                    "config key py.license_key must be a string, got %s"
                    % type(value).__name__
                )


def _validate(data):
    """Validate a parsed config mapping in place (raises ConfigError)."""
    if not isinstance(data, dict):
        raise ConfigError("config file must contain a YAML mapping")
    for key in data:
        if key not in DEFAULTS:
            warnings.warn("unknown config key %r ignored" % key, UserWarning)
    if "seed" in data:
        if type(data["seed"]) is not int:
            raise ConfigError(
                "config key seed must be an integer, got %s"
                % type(data["seed"]).__name__
            )
    for section in ("js", "py"):
        if section in data:
            _validate_section(section, data[section])


def load_config(path=None):
    """Load a YAML config file and merge it over the defaults.

    ``path`` may be ``None`` (or omitted), in which case only the
    defaults are returned. Raises :class:`ConfigError` when the file
    does not exist, is not valid YAML, is not a mapping, or has a
    wrongly typed or unknown engine key.
    """
    config = copy.deepcopy(DEFAULTS)
    if path is None:
        return config
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except FileNotFoundError:
        raise ConfigError("config file not found: %s" % path)
    except OSError as exc:
        raise ConfigError("cannot read config file %s: %s" % (path, exc))
    except yaml.YAMLError as exc:
        raise ConfigError("invalid YAML in config file %s: %s" % (path, exc))
    if data is None:
        return config
    _validate(data)
    for key, value in data.items():
        if key in ("js", "py"):
            config[key].update(value)
        elif key in config:
            config[key] = value
        # Unknown top-level keys were warned about in _validate; ignore them.
    return config


def merge_options(config, engine, overrides=None):
    """Return the effective options dict for one engine.

    Starts from the defaults for ``engine``, overlays the matching
    section of ``config``, then overlays ``overrides`` (for example
    CLI flags such as ``seed``). ``None`` override values are ignored
    so an unset CLI flag never wipes a configured value. The returned
    dict is the one the engines accept: the engine's flags plus
    ``seed``. Raises :class:`ConfigError` for an unknown engine.
    """
    if engine not in ("js", "py"):
        raise ConfigError("unknown engine %r (expected 'js' or 'py')" % engine)
    overrides = overrides or {}
    effective = copy.deepcopy(DEFAULTS[engine])
    section = (config or {}).get(engine) or {}
    if not isinstance(section, dict):
        raise ConfigError("config section %r must be a mapping" % engine)
    effective.update(section)
    seed = (config or {}).get("seed", DEFAULTS["seed"])
    if overrides.get("seed") is not None:
        seed = overrides["seed"]
    effective["seed"] = seed
    for key, value in overrides.items():
        if key == "seed" or value is None:
            continue
        if key in effective:
            effective[key] = value
    return effective
