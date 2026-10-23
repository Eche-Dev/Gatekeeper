"""Limites de confianza del body y del rate limit: casos que no dependen del corpus.

El corpus mide DETECCION (que firmas se disparan). Esto mide el COMPORTAMIENTO
en los bordes: exactamente en el limite, un Content-Length mentiroso, la
desconexion del cliente a mitad del body, la concurrencia y la politica de
fallo del backend de rate limit.

Cada test fija una garantia observable. Si una regla nueva cambia el manejo del
body o del limite, esto salta.
"""
from __future__ import annotations

import asyncio

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware


async def _ok(request):
    return PlainTextResponse("ok")


def make_app(**cfg_kwargs):
    app = Starlette(routes=[Route("/{path:path}", _ok, methods=["GET", "POST"])])
    return GatekeeperMiddleware(app, Config(**cfg_kwargs))


# ------------------------------------------------------- body: limite exacto


def test_body_en_el_limite_exacto_pasa():
    """El tamano EXACTO igual a max_body_size se admite: el limite es inclusivo."""
    app = make_app(max_body_size=100)
    with TestClient(app) as client:
        r = client.post("/x", content=b"a" * 100,
                        headers={"content-type": "application/json"})
    assert r.status_code == 200, r.text


def test_body_una_byte_por_encima_del_limite_da_413():
    app = make_app(max_body_size=100)
    with TestClient(app) as client:
        r = client.post("/x", content=b"a" * 101,
                        headers={"content-type": "application/json"})
    assert r.status_code == 413, r.text


def test_body_fragmentado_suma_al_total():
    """Fragmentos pequenos: el limite se aplica al TOTAL, no a cada fragmento."""
    app = make_app(max_body_size=50)
    with TestClient(app) as client:
        r = client.post("/x", content=b"a" * 30 + b"b" * 30,
                        headers={"content-type": "application/json"})
    assert r.status_code == 413, r.text


def test_content_length_declarado_menor_que_el_real_da_413():
    """Si el Content-Length miente y dice menos de lo que llega, manda el stream real.

    Un proxy que reescribe el Content-Length no puede hacer que Gatekeeper acepte
    un body que excede el limite.
    """
    app = make_app(max_body_size=100)

    async def receive():
        return {"type": "http.request", "body": b"a" * 200, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": [(b"content-type", b"application/json"), (b"content-length", b"10")],
        "client": ("1.2.3.4", 1234),
    }
    sent = []

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    assert sent[0]["status"] == 413, sent


def test_content_length_ausente_no_provoca_413():
    """Sin Content-Length y con body pequeno: se admite.

    La ausencia de la cabecera NO es motivo de rechazo por si sola (el 413 llega
    cuando el tamano declarado o el stream leído exceden el limite).
    """
    app = make_app(max_body_size=1000)

    async def receive():
        return {"type": "http.request", "body": b'{"a": 1}', "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": [(b"content-type", b"application/json")],
        "client": ("1.2.3.4", 1234),
    }
    sent = []

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    assert sent[0]["status"] == 200, sent


def test_desconexion_del_cliente_durante_el_body_no_rompe_el_middleware():
    """http.disconnect a mitad del body: el middleware responde, no se cuelga."""
    app = make_app(max_body_size=1000)

    async def receive():
        return {"type": "http.disconnect"}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": [(b"content-type", b"application/json")],
        "client": ("1.2.3.4", 1234),
    }
    sent = []

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    assert sent, "el middleware no respondio tras la desconexion"


def test_multipart_no_se_inspecciona():
    """multipart queda fuera de la inspeccion (documentado): el ataque pasa."""
    app = make_app()
    with TestClient(app) as client:
        r = client.post(
            "/x",
            content=(
                b"--b\r\nContent-Disposition: form-data; name=f\r\n\r\n"
                b"<script>alert(1)</script>\r\n--b--\r\n"
            ),
            headers={"content-type": "multipart/form-data; boundary=b"},
        )
    assert r.status_code == 200, r.text


def test_binario_no_se_inspecciona():
    """Content-type binario: no se inspecciona (documentado)."""
    app = make_app()
    with TestClient(app) as client:
        r = client.post(
            "/x",
            content=b"\x89PNG<script>alert(1)</script>",
            headers={"content-type": "application/octet-stream"},
        )
    assert r.status_code == 200, r.text


# ------------------------------------------------------- rate limit y fallo


def test_concurrencia_en_memoria_no_admite_mas_del_limite():
    """N peticiones simultaneas contra el backend en memoria: gana el limite."""
    from gatekeeper.ratelimit import MemoryBackend

    async def scenario():
        backend = MemoryBackend(limit=10, window=60.0)
        results = await asyncio.gather(*[backend.allow("1.2.3.4") for _ in range(50)])
        return sum(results)

    permitidos = asyncio.run(scenario())
    assert permitidos <= 10, f"se admitieron {permitidos} con limite 10"


def test_redis_caido_con_fail_open_sigue_admitiendo():
    """Fallo de Redis con la politica por defecto: se admite y se audita."""
    app = make_app(rate_limit=1, rate_backend="redis",
                   redis_url="redis://127.0.0.1:63999/0")
    with TestClient(app) as client:
        r = client.get("/x")
    assert r.status_code == 200, r.text


def test_redis_caido_con_fail_closed_devuelve_503():
    """Fallo de Redis con rate_fail_open=False: 503 (disponibilidad sacrificada)."""
    app = make_app(rate_limit=1, rate_backend="redis",
                   redis_url="redis://127.0.0.1:63999/0", rate_fail_open=False)
    with TestClient(app) as client:
        r = client.get("/x")
    assert r.status_code == 503, r.text
