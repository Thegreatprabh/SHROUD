"""SHROUD error types."""


class ShroudError(Exception):
    """Base error for all SHROUD failures."""


class ConfigError(ShroudError):
    """Raised when a configuration file is missing, invalid, or mistyped."""


class ProtectionError(ShroudError):
    """Raised when protecting a file or directory fails."""
