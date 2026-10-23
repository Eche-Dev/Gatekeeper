"""La guia de inicio rapido promete cosas concretas: hay que comprobarlas.

`docs/inicio-rapido.md` dice que una peticion normal responde 200 y un ataque
responde 403. Si eso deja de ser cierto, la guia esta mintiendo y el usuario
descubre el problema cuando ya esta en produccion.

Este test EJECUTA las peticiones de la guia contra la app que la guia define, y
comprueba que da lo que la guia promete. Si cambia el comportamiento del
middleware, esto salta.
"""
from __future__ import annotations

from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware


def _build_app():
    """La misma app que define la guia de inicio rapido."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def saludo(request):
        return JSONResponse({"mensaje": "hola"})

    app = Starlette(routes=[Route("/saludo", saludo, methods=["GET", "POST"])])
    return GatekeeperMiddleware(app, Config(rate_limit=100, rate_window=60))


def test_peticion_normal_responde_200():
    """La guia dice: una peticion permitida debe responder 200."""
    with TestClient(_build_app()) as client:
        r = client.get("/saludo")
    assert r.status_code == 200, r.text


def test_ataque_en_query_responde_403():
    """La guia dice: el ataque con UNION SELECT debe recibir 403."""
    with TestClient(_build_app()) as client:
        r = client.get("/saludo?q=1%20UNION%20SELECT%20password%20FROM%20users")
    assert r.status_code == 403, r.text


def test_ataque_en_body_responde_403():
    """La guia dice: el mismo ataque en el body JSON tambien recibe 403."""
    with TestClient(_build_app()) as client:
        r = client.post("/saludo", json={"nombre": "' OR '1'='1"})
    assert r.status_code == 403, r.text


def test_la_guia_no_promete_mas_de_lo_que_cumple():
    """La guia dice que el ataque en query responde 403 (no 500 ni 200).

    Este test fija el codigo exacto para que un cambio en el middleware que
    cambie el status rompa la guia, no al reves.
    """
    with TestClient(_build_app()) as client:
        r = client.get("/saludo?q=1%20UNION%20SELECT%20password%20FROM%20users")
    assert r.status_code == 403
    # Y la respuesta es un JSON con detalle, no una pagina de error de ASGI.
    assert r.headers["content-type"].startswith("application/json")
    assert "detail" in r.json()


def test_modo_monitor_no_bloquea_pero_sigue_registrando(caplog):
    """La guia dice que monitor_only registra sin bloquear: se comprueba."""
    import logging

    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    with caplog.at_level(logging.WARNING, logger="gatekeeper"):

        async def saludo(request):
            return JSONResponse({"mensaje": "hola"})

        inner = Starlette(routes=[Route("/saludo", saludo)])
        app = GatekeeperMiddleware(inner, Config(rate_limit=100, rate_window=60,
                                                 monitor_only=True))
        with TestClient(app) as client:
            r = client.get("/saludo?q=1%20UNION%20SELECT%20password%20FROM%20users")

    assert r.status_code == 200, r.text  # monitor_only deja pasar
    eventos = [rec.getMessage() for rec in caplog.records if rec.name == "gatekeeper"]
    assert any("attack_detected" in e for e in eventos), eventos
    # El payload no debe aparecer en el log.
    assert not any("password" in e for e in eventos), eventos
