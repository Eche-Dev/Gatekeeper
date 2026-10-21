import pytest

from gatekeeper.paths import is_path_allowed

PATTERNS = ["/docs", "/docs/*", "/health"]


@pytest.mark.parametrize("path", ["/docs", "/docs/", "/docs/oauth2-redirect", "/health"])
def test_allowed(path):
    assert is_path_allowed(path, PATTERNS)


@pytest.mark.parametrize(
    "path",
    [
        "/docs/../admin",          # traversal
        "/docs/%2e%2e/admin",      # traversal codificado
        "/docs/..%2fadmin",
        "/docs\\..\\admin",        # backslash
        "/other",
        "/DOCS",                   # sensible a mayúsculas
        "/healthz",
    ],
)
def test_not_allowed(path):
    assert not is_path_allowed(path, PATTERNS)


def test_empty_patterns_allow_nothing():
    assert not is_path_allowed("/docs", [])
