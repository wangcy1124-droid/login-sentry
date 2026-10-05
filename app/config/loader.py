"""Validated rule settings; other TOML sections remain reserved."""

from dataclasses import dataclass
from pathlib import Path
from typing import Union

try:
    import tomllib
except ImportError:
    import tomli as tomllib


class ConfigurationError(ValueError):
    """Missing or invalid detection rule configuration."""


def validate_rule(enabled: bool, window_seconds: int, threshold: int) -> None:
    if type(enabled) is not bool:
        raise ConfigurationError("enabled must be a boolean")
    for name, value in (("window_seconds", window_seconds), ("threshold", threshold)):
        if type(value) is not int or value <= 0:
            raise ConfigurationError(name + " must be a positive integer")


@dataclass(frozen=True)
class FailureBurstConfig:
    enabled: bool
    window_seconds: int
    threshold: int
    cooldown_seconds: int = 300

    def __post_init__(self) -> None:
        if type(self.cooldown_seconds) is not int or self.cooldown_seconds <= 0:
            raise ConfigurationError("cooldown_seconds must be a positive integer")
        validate_rule(self.enabled, self.window_seconds, self.threshold)


@dataclass(frozen=True)
class MultiAccountConfig:
    enabled: bool
    window_seconds: int
    distinct_username_threshold: int
    cooldown_seconds: int = 600

    def __post_init__(self) -> None:
        if type(self.cooldown_seconds) is not int or self.cooldown_seconds <= 0:
            raise ConfigurationError("cooldown_seconds must be a positive integer")
        validate_rule(self.enabled, self.window_seconds, self.distinct_username_threshold)


@dataclass(frozen=True)
class DetectionConfig:
    failure_burst: FailureBurstConfig
    multi_account: MultiAccountConfig


def load_config(path: Union[str, Path]) -> DetectionConfig:
    try:
        with Path(path).open("rb") as stream:
            document = tomllib.load(stream)
    except tomllib.TOMLDecodeError:
        raise ConfigurationError("invalid TOML configuration") from None
    rules = document.get("rules")
    if not isinstance(rules, dict):
        raise ConfigurationError("missing or invalid rules table")
    configs = []
    for name, model, threshold in (
        ("failure_burst", FailureBurstConfig, "threshold"),
        ("multi_account", MultiAccountConfig, "distinct_username_threshold"),
    ):
        values = rules.get(name)
        if not isinstance(values, dict):
            raise ConfigurationError("missing or invalid rules." + name)
        required = {"enabled", "window_seconds", threshold, "cooldown_seconds"}
        if set(values) != required:
            raise ConfigurationError("rules." + name + " requires exactly: " + ", ".join(sorted(required)))
        configs.append(model(**values))
    return DetectionConfig(configs[0], configs[1])
