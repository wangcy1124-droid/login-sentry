from dataclasses import replace
from pathlib import Path

import pytest

from app.config.loader import ConfigurationError, FailureBurstConfig, MultiAccountConfig, load_config
from app.services.detection import detect

DEFAULT = Path(__file__).resolve().parents[2] / "config/default.toml"


def test_defaults(rules):
    assert rules.failure_burst == FailureBurstConfig(True, 60, 5)
    assert rules.multi_account == MultiAccountConfig(True, 300, 4)


@pytest.mark.parametrize("field,value", [("enabled", 1), ("enabled", "true"), ("window_seconds", 0),
    ("window_seconds", -1), ("window_seconds", True), ("window_seconds", 1.5), ("threshold", -1),
    ("threshold", 0), ("threshold", True), ("threshold", "5")])
def test_invalid_config_types_and_values(field, value):
    values = dict(enabled=True, window_seconds=60, threshold=5)
    values[field] = value
    with pytest.raises(ConfigurationError):
        FailureBurstConfig(**values)
    values["distinct_username_threshold"] = values.pop("threshold")
    with pytest.raises(ConfigurationError):
        MultiAccountConfig(**values)


@pytest.mark.parametrize("old,new", [('threshold = 5', ''), ('threshold = 5', 'threshold = "5"'),
    ('enabled = true', 'enabled = 1'), ('[rules.multi_account]', '[rules.other]'),
    ('threshold = 5', 'threshold = 5\nextra = 1')])
def test_invalid_toml_fields(tmp_path, old, new):
    path = tmp_path / 'rules.toml'
    path.write_text(DEFAULT.read_text().replace(old, new))
    with pytest.raises(ConfigurationError):
        load_config(path)


def test_missing_file_and_malformed_toml(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / 'missing.toml')
    path = tmp_path / 'bad.toml'
    path.write_text('rules = [')
    with pytest.raises(ConfigurationError, match='invalid TOML'):
        load_config(path)
    path.write_text('rules = 4')
    with pytest.raises(ConfigurationError, match='rules table'):
        load_config(path)


@pytest.mark.parametrize("disabled,expected", [('failure_burst', 'multi_account'), ('multi_account', 'failure_burst')])
def test_disabled_rules_independently(detection_db, rules, persist_event, disabled, expected):
    for user in ('alice', 'bob', 'charlie', 'david', 'alice'):
        persist_event(username=user)
    rules = replace(rules, **{disabled: replace(getattr(rules, disabled), enabled=False)})
    matches = detect(detection_db, rules).matches
    assert [match.rule_type.value for match in matches] == [expected]


def test_both_disabled_do_not_query(detection_db, rules):
    rules = replace(rules, failure_burst=replace(rules.failure_burst, enabled=False), multi_account=replace(rules.multi_account, enabled=False))
    queries = []
    detection_db.set_trace_callback(queries.append)
    assert detect(detection_db, rules).matches == ()
    assert queries == []


@pytest.mark.parametrize("old,new,users,rule", [
    ('threshold = 5', 'threshold = 4', ['alice'] * 4, 'failure_burst'),
    ('distinct_username_threshold = 4', 'distinct_username_threshold = 3', ['alice', 'bob', 'charlie'], 'multi_account'),
])
def test_dynamic_threshold_from_file(tmp_path, detection_db, persist_event, old, new, users, rule):
    for user in users:
        persist_event(username=user)
    assert detect(detection_db, load_config(DEFAULT)).matches == ()
    path = tmp_path / 'custom.toml'
    path.write_text(DEFAULT.read_text().replace(old, new))
    assert [match.rule_type.value for match in detect(detection_db, load_config(path)).matches] == [rule]


def test_default_cooldowns(rules):
    assert rules.failure_burst.cooldown_seconds == 300
    assert rules.multi_account.cooldown_seconds == 600


@pytest.mark.parametrize('old,new', [('cooldown_seconds = 300', ''),
    ('cooldown_seconds = 300', 'cooldown_seconds = 0'),
    ('cooldown_seconds = 600', 'cooldown_seconds = -1'),
    ('cooldown_seconds = 300', 'cooldown_seconds = true'),
    ('cooldown_seconds = 600', 'cooldown_seconds = "600"'),
    ('cooldown_seconds = 300', 'cooldown_seconds = 300\nunknown = 1')])
def test_strict_cooldown_toml(tmp_path, old, new):
    path = tmp_path / 'config.toml'
    path.write_text(DEFAULT.read_text().replace(old, new))
    with pytest.raises(ConfigurationError):
        load_config(path)
