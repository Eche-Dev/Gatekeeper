"""REGRESION: las cabeceras de seguridad tienen que ir TAMBIEN en los rechazos.

Encontrado al medir la matriz de compatibilidad (2026-10-25): las cabeceras
de seguridad se anadian solo en el camino de EXITO. Las respuestas de rechazo
(403, 413, 429, 503) se envian directamente, sin pasar por el envoltorio que
las anade.

Por que importa: un 403 sin `X-Frame-Options` ni HSTS es una respuesta MAS
DEBIL que la de 200, y el rechazo es justamente la respuesta que ve el
atacante.
"""
from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware

# Cabeceras que el middleware debe poner en TODAS sus respuestas.
ESPERADAS = {
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
}


async def ok(request):
    return PlainTextResponse("ok")


def _app(**cfg):
    app = Starlette(routes=[Route("/{path:path}", ok, methods=["GET", "POST"])])
    return GatekeeperMiddleware(app, Config(**cfg))


def _cabeceras(respuesta) -> set[str]:
    return {k.lower() for k in respuesta.headers}


@pytest.mark.parametrize(
    "nombre,cfg,preparar,esperado",
    [
        (
            "200",
            {},
            lambda c: c.get("/ok"),
            200,
        ),
        (
            "403 por ataque",
            {},
            lambda c: c.get("/x?q=1%20UNION%20SELECT%20password%20FROM%20users"),
            403,
        ),
        (
            "413 por body grande",
            {"max_body_size": 100},
            lambda c: c.post(
                "/x", content=b"a" * 500,
                headers={"content-type": "application/json"},
            ),
            413,
        ),
    ],
)
def test_las_cabeceras_de_seguridad_llegan_en_cada_respuesta(
    nombre, cfg, preparar, esperado
):
    """Todas las respuestas del middleware llevan las cabeceras de seguridad."""
    with TestClient(_app(**cfg)) as client:
        r = preparar(client)
        assert r.status_code == esperado, r.text
        assert ESPERADAS <= _cabeceras(r), (
            f"faltan cabeceras en el {nombre}: {ESPERADAS - _cabeceras(r)}"
        )


def test_el_429_tambien_lleva_cabeceras():
    """El 429 del rate limit tambien las lleva."""
    app = _app(rate_limit=1)
    with TestClient(app) as client:
        assert client.get("/ok").status_code == 200
        r = client.get("/ok")
        assert r.status_code == 429, r.text
        assert ESPERADAS <= _cabeceras(r), (
            f"faltan cabeceras en el 429: {ESPERADAS - _cabeceras(r)}"
        )
        # Y el Retry-After sigue ahí: no se pierde al añadir las cabeceras.
        assert "retry-after" in _cabeceras(r)


def test_el_403_por_ip_bloqueada_lleva_cabeceras():
    """El rechazo por IP bloqueada también."""
    app = _app(blocked_ips={"192.0.2.66"})
    with TestClient(app, client=("192.0.2.66", 1234)) as client:
        r = client.get("/ok")
        assert r.status_code == 403, r.text
        assert ESPERADAS <= _cabeceras(r), (
            f"faltan cabeceras: {ESPERADAS - _cabeceras(r)}"
        )


def test_el_503_por_redis_caido_lleva_cabeceras():
    """El 503 (backend de rate limit caído, fail-closed) también."""
    from gatekeeper.ratelimit import RedisBackend

    class Roto:
        async def eval(self, *args, **kwargs):
            raise ConnectionError("redis caido")

    app = _app(rate_limit=5, rate_fail_open=False)
    app.limiter = RedisBackend(Roto(), 5, 60)
    with TestClient(app) as client:
        r = client.get("/ok")
        assert r.status_code == 503, r.text
        assert ESPERADAS <= _cabeceras(r), (
            f"faltan cabeceras en el 503: {ESPERADAS - _cabeceras(r)}"
        )


def test_las_cabeceras_personalizadas_tambien_llegan_en_los_rechazos():
    """Si el usuario personaliza las cabeceras, también valen para los rechazos."""
    app = _app(security_headers={"X-Mia-Cabecera": "si"})
    with TestClient(app) as client:
        r = client.get("/x?q=1%20UNION%20SELECT%20password%20FROM%20users")
        assert r.status_code == 403, r.text
        assert r.headers.get("x-mia-cabecera") == "si", dict(r.headers)


def test_la_app_no_puede_quitar_las_cabeceras_del_middleware():
    """La app no puede sobrescribir una cabecera de seguridad del middleware.

    Es lo que hace `if key not in h` en el camino de exito: el middleware no
    pisa las cabeceras de la app, y la app no pisa las del middleware.
    """
    async def con_cabecera(request):
        return PlainTextResponse("ok", headers={"X-Content-Type-Options": "lo-que-yo-quiera"})

    app = Starlette(routes=[Route("/{path:path}", con_cabecera)])
    mw = GatekeeperMiddleware(app, Config(rate_limit=100))
    with TestClient(mw) as client:
        r = client.get("/ok")
        # La de la app gana (no se pisa lo que ya venia).
        assert r.headers["x-content-type-options"] == "lo-que-yo-quiera"
