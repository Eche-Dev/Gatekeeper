import pytest

from gatekeeper import Config

YAML = """
rate_limit: 5
rate_window: 30
monitor_only: true
inspect_cross_carrier: true
max_body_size: 2048
allow_paths: ["/docs", "/health"]
blocked_ips: ["10.0.0.1"]
disabled_rules: [xss]
custom_rules:
  - name: wp-probe
    pattern: 'wp-login\\.php'
"""


def test_from_yaml_loads_all_fields(tmp_path):
    f = tmp_path / "gk.yaml"
    f.write_text(YAML, encoding="utf-8")
    cfg = Config.from_yaml(f)
    assert cfg.rate_limit == 5 and cfg.rate_window == 30
    assert cfg.monitor_only is True
    assert cfg.inspect_cross_carrier is True
    assert cfg.max_body_size == 2048
    assert cfg.allow_paths == ["/docs", "/health"]
    assert cfg.blocked_ips == {"10.0.0.1"}
    assert cfg.disabled_rules == {"xss"}
    assert "wp-probe" in cfg.compiled_custom


def test_empty_yaml_gives_defaults(tmp_path):
    f = tmp_path / "gk.yaml"
    f.write_text("", encoding="utf-8")
    assert Config.from_yaml(f) == Config()


def test_custom_rules_accept_dict():
    cfg = Config(custom_rules={"probe": r"\.env"})
    assert "probe" in cfg.compiled_custom


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"custom_rules": {"bad": "("}}, "inválido"),
        ({"custom_rules": {"empty": ""}}, "vacío"),
        ({"custom_rules": {"sqli": "x"}}, "choca"),
        ({"custom_rules": [{"name": "x"}]}, "name"),
        ({"disabled_rules": {"nope"}}, "inexistentes"),
        ({"rate_window": 0}, "rate_window"),
        ({"rate_limit": -1}, "rate_limit"),
        ({"max_body_size": 0}, "max_body_size"),
        ({"rate_backend": "memroy"}, "rate_backend"),
        ({"rate_backend": "redis", "redis_url": ""}, "redis_url"),
    ],
)
def test_invalid_config_fails_loudly(kwargs, match):
    with pytest.raises(ValueError, match=match):
        Config(**kwargs)


def test_unknown_key_in_dict_is_rejected():
    with pytest.raises(ValueError, match="desconocidas"):
        Config.from_dict({"rate_limt": 5})  # typo


def test_non_mapping_is_rejected():
    with pytest.raises(TypeError):
        Config.from_dict(["a"])


def test_custom_rules_wrong_type_is_rejected():
    with pytest.raises(TypeError, match="diccionario"):
        Config(custom_rules=5)


def test_disabling_a_custom_rule_is_allowed():
    cfg = Config(custom_rules={"probe": r"\.env"}, disabled_rules={"probe"})
    assert cfg.disabled_rules == {"probe"}
