import logging

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware


def make_client(**cfg):
    async def home(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", home)])
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))
    return TestClient(app)


def test_clean_request_gets_security_headers():
    r = make_client().get("/?q=hello")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_sqli_is_blocked():
    r = make_client().get("/", params={"q": "1 UNION SELECT password FROM users"})
    assert r.status_code == 403


def test_monitor_only_logs_but_allows(caplog):
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        r = make_client(monitor_only=True).get("/", params={"q": "<script>x</script>"})
    assert r.status_code == 200
    assert "attack_detected" in caplog.text


def test_rate_limit_returns_429_with_retry_after():
    c = make_client(rate_limit=2, rate_window=60)
    assert c.get("/").status_code == 200
    assert c.get("/").status_code == 200
    r = c.get("/")
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) >= 1


def test_blocked_ip():
    r = make_client(blocked_ips={"testclient"}).get("/")
    assert r.status_code == 403


def test_app_headers_are_not_overwritten():
    async def home(request):
        return PlainTextResponse("ok", headers={"X-Frame-Options": "SAMEORIGIN"})

    app = Starlette(routes=[Route("/", home)])
    app.add_middleware(GatekeeperMiddleware)
    assert TestClient(app).get("/").headers["x-frame-options"] == "SAMEORIGIN"
