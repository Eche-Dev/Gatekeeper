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


# --- Bloque 5: cabeceras duplicadas ASGI, métodos con body y gzip ------------


def test_cabeceras_duplicadas_cookie_y_xff_se_combinan():
    """AG-6: múltiples tuplas cookie o x-forwarded-for en ASGI no deben evadir el WAF."""
    import asyncio

    async def ejecutar() -> tuple[int, int]:
        async def inner_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = GatekeeperMiddleware(
            inner_app,
            config=Config(
                rate_limit=0,
                trust_proxy=True,
                trusted_proxies=1,
                blocked_ips=["198.51.100.99"],
            ),
        )

        async def recv():
            return {"type": "http.request", "body": b"", "more_body": False}

        resp_cookie = []
        async def send_cookie(msg):
            resp_cookie.append(msg)

        await mw(
            {
                "type": "http",
                "method": "GET",
                "path": "/",
                "raw_path": b"/",
                "query_string": b"",
                "client": ("127.0.0.1", 12345),
                "headers": [
                    (b"cookie", b"session=inocuo"),
                    (b"cookie", b"evil=1 UNION SELECT password FROM users"),
                ],
            },
            recv,
            send_cookie,
        )

        resp_xff = []
        async def send_xff(msg):
            resp_xff.append(msg)

        await mw(
            {
                "type": "http",
                "method": "GET",
                "path": "/",
                "raw_path": b"/",
                "query_string": b"",
                "client": ("127.0.0.1", 12345),
                "headers": [
                    (b"x-forwarded-for", b"203.0.113.1"),
                    (b"x-forwarded-for", b"198.51.100.99"),
                ],
            },
            recv,
            send_xff,
        )
        return resp_cookie[0]["status"], resp_xff[0]["status"]

    st_cookie, st_xff = asyncio.run(ejecutar())
    assert st_cookie == 403
    assert st_xff == 403


def test_body_en_get_head_y_options_se_inspecciona():
    """IA-2: si una petición GET/HEAD/OPTIONS transporta body, se debe inspeccionar."""
    client = make_client()
    for metodo in ("GET", "HEAD", "OPTIONS"):
        r = client.request(
            metodo,
            "/",
            content=b'{"q": "1 UNION SELECT password FROM users"}',
            headers={"content-type": "application/json"},
        )
        assert r.status_code == 403


def test_body_comprimido_con_gzip_se_inspecciona_y_bomba_da_413():
    """IA-3: Content-Encoding: gzip se descomprime de forma acotada antes de inspeccionar."""
    import gzip

    client = make_client(max_body_size=1024)
    ataque_gz = gzip.compress(b'{"q": "1 UNION SELECT password FROM users"}')
    r_atk = client.post(
        "/",
        content=ataque_gz,
        headers={"content-type": "application/json", "content-encoding": "gzip"},
    )
    assert r_atk.status_code == 403

    bomba_gz = gzip.compress(b"A" * 5000)
    r_bomba = client.post(
        "/",
        content=bomba_gz,
        headers={"content-type": "text/plain", "content-encoding": "gzip"},
    )
    assert r_bomba.status_code == 413

