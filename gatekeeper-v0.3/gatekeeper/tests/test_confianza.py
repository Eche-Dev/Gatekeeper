"""Regresiones de confianza: los cuatro bypasses verificados en una revisión
externa sobre v0.3.0, cada uno con su arreglo y su test.

1. X-Forwarded-For se leía de izquierda a derecha: ips[0] lo escribe el cliente,
   con lo que rotándolo se saltaba rate limit y blocked_ips.
2. Solo se inspeccionaban JSON/form: un POST text/plain o sin content-type
   pasaba sin verlo aunque `await request.json()` lo parseara igual.
3. Las cabeceras no se inspeccionaban (scanners y Log4Shell viven ahí).
4. blocked_ips no admitía CIDR y el log no traía campo ni patrón que disparó.

Si alguien revierte cualquiera de los arreglos, estos tests fallan aquí y en CI.
"""

import json
import logging

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.middleware import _client_ip


def make_client(client: tuple[str, int] | None = None, **cfg):
    async def home(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", home, methods=["GET", "POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))
    kwargs = {"client": client} if client else {}
    return TestClient(app, **kwargs)


def _scope(headers=(), client=("10.0.0.5", 1234)):
    return {
        "type": "http",
        "client": client,
        "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers],
    }


# ── 1. X-Forwarded-For: de derecha a izquierda ────────────────────────────


def test_xff_rotating_left_value_cannot_bypass_blocked_ip():
    # El bug: ips[0] lo escribe el cliente, así que rotándolo esquivaba el bloqueo.
    cfg = dict(trust_proxy=True, trusted_proxies=1,
               blocked_ips={"198.51.100.7"}, rate_limit=0)
    for fake in ("9.9.9.1", "9.9.9.2", "9.9.9.3"):
        r = make_client(**cfg).get("/", headers={"x-forwarded-for": f"{fake}, 198.51.100.7"})
        assert r.status_code == 403, "rotar la primera entrada no debe cambiar la IP real"


def test_xff_rotating_left_value_cannot_bypass_rate_limit():
    # La reproducción exacta de la revisión: 8 peticiones rotando ips[0] con
    # rate_limit=2 pasaban todas; con ips[-N] la identidad es siempre la misma.
    c = make_client(trust_proxy=True, trusted_proxies=1, rate_limit=2, rate_window=60)
    codes = [
        c.get("/", headers={"x-forwarded-for": f"9.9.9.{i}, 10.0.0.9"}).status_code
        for i in range(5)
    ]
    assert codes == [200, 200, 429, 429, 429]


def test_xff_is_ignored_from_untrusted_peer():
    # Con trusted_proxy_cidrs, solo un peer que es tu proxy manda en el XFF:
    # si la app es alcanzable saltándose el proxy, el XFF del atacante no cuenta.
    cfg = dict(trust_proxy=True, trusted_proxies=1,
               trusted_proxy_cidrs={"10.0.0.0/8"}, blocked_ips={"198.51.100.7"},
               rate_limit=0)
    r = make_client(client=("203.0.113.9", 1234), **cfg).get(
        "/", headers={"x-forwarded-for": "198.51.100.7"}
    )
    assert r.status_code == 200  # peer que no es proxy: el XFF se ignora
    r = make_client(client=("10.0.0.5", 1234), **cfg).get(
        "/", headers={"x-forwarded-for": "9.9.9.9, 198.51.100.7"}
    )
    assert r.status_code == 403  # peer proxy tuyo: se lee de la derecha


def test_client_ip_counts_trusted_proxies_from_the_right():
    cfg = Config(trust_proxy=True, trusted_proxies=2)
    # La 3ª entrada la añadió tu P2, la 2ª tu P1: el cliente real es la 2ª.
    scope = _scope(headers=[("x-forwarded-for", "9.9.9.9, 1.2.3.4, 10.0.0.1")])
    assert _client_ip(scope, cfg) == "1.2.3.4"
    # Cadena más corta que los proxies declarados: cadena inconsistente -> peer.
    scope = _scope(headers=[("x-forwarded-for", "1.2.3.4")])
    assert _client_ip(scope, cfg) == "10.0.0.5"
    # Sin trust_proxy, manda el peer TCP.
    assert _client_ip(_scope(headers=[("x-forwarded-for", "9.9.9.9")]), Config()) == "10.0.0.5"


# ── 2. Content-type: todo lo textual ──────────────────────────────────────


def test_post_without_content_type_is_inspected():
    r = make_client(rate_limit=0).post(
        "/", content=b'{"q": "1 UNION SELECT password FROM users"}'
    )
    assert r.status_code == 403


def test_text_plain_post_is_inspected():
    r = make_client(rate_limit=0).post(
        "/", content="1 UNION SELECT password FROM users",
        headers={"content-type": "text/plain"},
    )
    assert r.status_code == 403


def test_binary_body_is_not_inspected():
    # Documentado: los binarios no son cadenas que inspeccionar (multipart, v0.4).
    r = make_client(rate_limit=0).post(
        "/", content=b"\x89PNG\r\n\x1a\n UNION SELECT password FROM users",
        headers={"content-type": "image/png"},
    )
    assert r.status_code == 200


# ── 3. Cabeceras ──────────────────────────────────────────────────────────


def test_header_payloads_are_blocked():
    c = make_client(rate_limit=0)
    assert c.get("/", headers={"user-agent": "<script>alert(1)</script>"}).status_code == 403
    assert c.get("/", headers={"referer": "/x?q=1 UNION SELECT pw FROM users"}).status_code == 403
    assert c.get("/", headers={"cookie": "sid=1; q=<script>x</script>"}).status_code == 403


def test_custom_header_is_inspected_only_if_configured():
    c = make_client(rate_limit=0)
    assert c.get("/", headers={"x-custom-probe": "<script>x</script>"}).status_code == 200
    c2 = make_client(rate_limit=0, inspect_headers={"x-custom-probe"})
    assert c2.get("/", headers={"x-custom-probe": "<script>x</script>"}).status_code == 403


# ── 4. CIDR, validación y auditoría con campo y patrón ────────────────────


def test_blocked_ip_cidr_and_ipv4_mapped_ipv6():
    blocked = dict(blocked_ips={"10.0.0.0/8"}, rate_limit=0)
    assert make_client(client=("10.4.5.6", 1), **blocked).get("/").status_code == 403
    assert make_client(client=("11.0.0.1", 1), **blocked).get("/").status_code == 200
    # Un peer IPv6 mapeado (dual stack) debe caer en el IPv4 equivalente.
    assert make_client(client=("::ffff:10.4.5.6", 1), **blocked).get("/").status_code == 403


def test_config_rejects_bad_network_entries():
    # Un typo en una máscara no puede quedarse silencioso en producción.
    for kwargs in (
        {"blocked_ips": {"10.0.0.999"}},
        {"trusted_proxy_cidrs": {"testclient"}},
        {"trust_proxy": True, "trusted_proxies": 0},
    ):
        with pytest.raises(ValueError):
            Config(**kwargs)


def test_audit_log_carries_field_rule_and_pattern(caplog):
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        make_client(rate_limit=0).post(
            "/", json={"comment": "1 UNION SELECT password FROM users"}
        )
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    attack = next(e for e in events if e["event"] == "attack_detected")
    assert attack["source"] == "body"
    assert attack["field"] == "/comment"  # JSON pointer del campo culpable
    assert attack["rule"] == "sqli"
    assert "union" in attack["pattern"]  # el patrón que disparó: el "motivo"
    assert "password FROM users" not in json.dumps(attack)  # nunca el payload


def test_query_audit_names_the_parameter(caplog):
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        make_client(rate_limit=0).get("/", params={"q": "<script>x</script>"})
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    attack = next(e for e in events if e["event"] == "attack_detected")
    assert attack["source"] == "query"
    assert attack["field"] == "q"
    assert attack["rule"] == "xss"
    assert "pattern" in attack


def test_header_audit_names_the_header(caplog):
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        make_client(rate_limit=0).get("/", headers={"user-agent": "<script>x</script>"})
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    attack = next(e for e in events if e["event"] == "attack_detected")
    assert attack["source"] == "header"
    assert attack["field"] == "user-agent"
    assert "pattern" in attack
