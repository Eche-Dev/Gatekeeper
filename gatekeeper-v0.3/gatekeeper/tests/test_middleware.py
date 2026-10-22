import logging

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware


def make_client(**cfg):
    async def home(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", home, methods=["GET", "POST"])])
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


def test_custom_rule_blocks_and_is_audited(caplog):
    c = make_client(custom_rules={"wp-probe": r"wp-login\.php"}, rate_limit=0)
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        r = c.get("/wp-login.php")
    assert r.status_code == 403
    assert "wp-probe" in caplog.text


def test_query_body_cross_detection_is_opt_in():
    body = "select password from users"
    headers = {"content-type": "text/plain"}
    assert make_client().post("/?q=union", content=body, headers=headers).status_code == 200
    assert (
        make_client(inspect_cross_carrier=True)
        .post("/?q=union", content=body, headers=headers)
        .status_code
        == 403
    )


def test_query_body_cross_detection_respects_excluded_fields():
    response = make_client(
        inspect_cross_carrier=True,
        exclude_fields=["q"],
    ).post(
        "/?q=union",
        content="select password from users",
        headers={"content-type": "text/plain"},
    )
    assert response.status_code == 200


def test_query_body_cross_detection_handles_json_values():
    response = make_client(inspect_cross_carrier=True).post(
        "/?q=union",
        json={"statement": "select password from users"},
    )
    assert response.status_code == 403


def test_query_body_cross_detection_respects_excluded_body_fields():
    response = make_client(
        inspect_cross_carrier=True,
        exclude_fields=["statement"],
    ).post(
        "/?q=union",
        json={"statement": "select password from users"},
    )
    assert response.status_code == 200


def test_query_body_cross_detection_monitor_mode_does_not_log_payload(caplog):
    body = "select private_column from users"
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        response = make_client(
            inspect_cross_carrier=True,
            monitor_only=True,
        ).post(
            "/?q=union",
            content=body,
            headers={"content-type": "text/plain"},
        )
    assert response.status_code == 200
    assert '"source": "query_body"' in caplog.text
    assert "private_column" not in caplog.text
