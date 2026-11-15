"""Tests for shroud.config: defaults, file loading, validation, merging."""

import unittest
import warnings
from pathlib import Path

from shroud.config import DEFAULTS, ConfigError, load_config, merge_options

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "examples" / "config.example.yaml"


class TestDefaults(unittest.TestCase):
    def test_none_returns_defaults(self):
        config = load_config(None)
        self.assertEqual(config, DEFAULTS)
        self.assertEqual(config["seed"], 1337)

    def test_defaults_have_all_js_flags(self):
        js = load_config()["js"]
        for key in (
            "rename",
            "string_encryption",
            "flatten",
            "literal_encoding",
            "dead_code",
            "anti_debug",
            "integrity",
        ):
            self.assertIs(js[key], True, key)
        self.assertEqual(js["domain_lock"], [])

    def test_defaults_have_all_py_flags(self):
        py = load_config()["py"]
        for key in (
            "rename",
            "string_encryption",
            "flatten",
            "literal_encoding",
            "dead_code",
            "anti_debug",
            "integrity",
        ):
            self.assertIs(py[key], True, key)
        self.assertEqual(py["license_key"], "")

    def test_returned_config_is_a_copy(self):
        first = load_config()
        first["js"]["rename"] = False
        first["seed"] = 1
        self.assertEqual(load_config(), DEFAULTS)


class TestLoadFile(unittest.TestCase):
    def test_example_file_loads(self):
        config = load_config(str(EXAMPLE))
        self.assertEqual(config["seed"], 1337)
        self.assertIs(config["js"]["rename"], True)
        self.assertIs(config["py"]["integrity"], True)
        self.assertEqual(config["js"]["domain_lock"], [])
        self.assertEqual(config["py"]["license_key"], "")

    def test_example_file_matches_defaults(self):
        self.assertEqual(load_config(str(EXAMPLE)), DEFAULTS)

    def test_missing_file_raises(self):
        with self.assertRaises(ConfigError):
            load_config("/tmp/shroud-does-not-exist.yaml")

    def test_invalid_yaml_raises(self):
        bad = Path(self._tmp_file("key: [unclosed\n"))
        with self.assertRaises(ConfigError):
            load_config(str(bad))

    def test_non_mapping_yaml_raises(self):
        bad = Path(self._tmp_file("- one\n- two\n"))
        with self.assertRaises(ConfigError):
            load_config(str(bad))

    def test_empty_file_is_defaults(self):
        empty = Path(self._tmp_file(""))
        self.assertEqual(load_config(str(empty)), DEFAULTS)

    def _tmp_file(self, text):
        import tempfile

        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False, encoding="utf-8"
        )
        handle.write(text)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return handle.name


class TestValidation(unittest.TestCase):
    def _write(self, text):
        import tempfile

        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False, encoding="utf-8"
        )
        handle.write(text)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return handle.name

    def test_js_rename_not_bool_raises(self):
        path = self._write("js:\n  rename: 'yes'\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_js_flag_as_int_raises(self):
        path = self._write("js:\n  rename: 1\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_seed_not_int_raises(self):
        path = self._write("seed: '1337'\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_seed_bool_raises(self):
        path = self._write("seed: true\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_domain_lock_not_list_raises(self):
        path = self._write("js:\n  domain_lock: example.com\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_domain_lock_non_string_item_raises(self):
        path = self._write("js:\n  domain_lock: [123]\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_domain_lock_list_of_hosts_ok(self):
        path = self._write("js:\n  domain_lock: ['app.example.com']\n")
        config = load_config(path)
        self.assertEqual(config["js"]["domain_lock"], ["app.example.com"])

    def test_license_key_not_string_raises(self):
        path = self._write("py:\n  license_key: 42\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_engine_section_not_mapping_raises(self):
        path = self._write("js: [1, 2]\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_unknown_engine_key_fails_closed(self):
        path = self._write("js:\n  strnig_encryption: true\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_unknown_py_key_fails_closed(self):
        path = self._write("py:\n  licens_key: abc\n")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_unknown_top_level_key_warns_but_loads(self):
        path = self._write("notes: hello\nseed: 7\n")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            config = load_config(path)
        self.assertEqual(config["seed"], 7)
        self.assertTrue(
            any("notes" in str(w.message) for w in caught),
            "expected a warning naming the unknown key",
        )

    def test_partial_config_merges_over_defaults(self):
        path = self._write("seed: 42\njs:\n  rename: false\n")
        config = load_config(path)
        self.assertEqual(config["seed"], 42)
        self.assertIs(config["js"]["rename"], False)
        self.assertIs(config["js"]["flatten"], True)
        self.assertIs(config["py"]["rename"], True)


class TestMergeOptions(unittest.TestCase):
    def test_defaults_for_each_engine(self):
        for engine in ("js", "py"):
            options = merge_options(load_config(), engine, {})
            self.assertEqual(options["seed"], 1337)
            self.assertIs(options["rename"], True)

    def test_cli_seed_overrides_config_seed(self):
        config = load_config()
        config["seed"] = 42
        options = merge_options(config, "js", {"seed": 99})
        self.assertEqual(options["seed"], 99)

    def test_config_seed_used_when_no_override(self):
        config = load_config()
        config["seed"] = 42
        options = merge_options(config, "py", {})
        self.assertEqual(options["seed"], 42)

    def test_none_override_value_ignored(self):
        config = load_config()
        config["seed"] = 42
        options = merge_options(config, "js", {"seed": None})
        self.assertEqual(options["seed"], 42)

    def test_config_section_values_respected(self):
        config = load_config()
        config["js"]["domain_lock"] = ["app.example.com"]
        options = merge_options(config, "js", {})
        self.assertEqual(options["domain_lock"], ["app.example.com"])

    def test_engine_specific_overrides_applied(self):
        options = merge_options(load_config(), "js", {"flatten": False})
        self.assertIs(options["flatten"], False)

    def test_unknown_engine_raises(self):
        with self.assertRaises(ConfigError):
            merge_options(load_config(), "ruby", {})

    def test_merging_does_not_mutate_config(self):
        config = load_config()
        merge_options(config, "js", {"seed": 5, "rename": False})
        self.assertEqual(config, DEFAULTS)


if __name__ == "__main__":
    unittest.main()
