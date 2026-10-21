import pytest

from gatekeeper.rules import normalize, scan


@pytest.mark.parametrize(
    "payload,rule",
    [
        ("/x?id=1 UNION SELECT password FROM users", "sqli"),
        ("/x?id=1 OR 1=1", "sqli"),
        ("/x?q=admin'--", "sqli"),
        ("/x?q=1; DROP TABLE users", "sqli"),
        ("/x?q=<script>alert(1)</script>", "xss"),
        ("/x?q=<img src=x onerror=alert(1)>", "xss"),
        ("/x?f=../../etc/passwd", "path_traversal"),
        ("/x?f=%2e%2e%2f%2e%2e%2fsecret", "path_traversal"),
        ("/x?q=%253Cscript%253E", "xss"),  # doble codificación
    ],
)
def test_detects_attacks(payload, rule):
    assert scan(payload) == rule


@pytest.mark.parametrize(
    "payload",
    [
        "/search?q=hello world",
        "/users?online=1&order=asc",
        "/search?q=union station select seats",
        "/items?price=10&limit=5",
    ],
)
def test_benign_requests_pass(payload):
    assert scan(payload) is None


def test_disabled_rule_is_skipped():
    assert scan("/x?id=1 OR 1=1", disabled={"sqli"}) is None


def test_normalize_handles_double_encoding():
    assert normalize("%253Cscript") == "<script"
