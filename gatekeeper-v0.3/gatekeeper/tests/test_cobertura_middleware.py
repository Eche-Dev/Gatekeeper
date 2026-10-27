"""Cobertura de los caminos de error del middleware.

`middleware.py` decide que hacer cuando algo no va bien: Redis caido, el
presupuesto de inspeccion agotado, una cabecera exenta, un `Content-Length`
que no es un numero. Esos caminos son los que decides NO dejar pasar: un
`fail-open` en cualquiera de ellos es un bypass, no una degradacion.

Aqui se comprueban uno a uno. No cambia ningun comportamiento: solo se
comprueba el que ya hay.
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper import middleware as mw
from gatekeeper.body import InspectionTimeout
from gatekeeper.ratelimit import BackendUnavailable

SQLI = "union select password from users"


def _app(**cfg):
    async def home(request):
        return PlainTextResponse("ok")

    async def ws(websocket):
        await websocket.accept()
        await websocket.send_text("hola")
        await websocket.close()

    app = Starlette(routes=[
        Route("/", home, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]),
        WebSocketRoute("/ws", ws),
    ])
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))
    return app


def _scope_websocket(query: str = "", headers=None) -> dict:
    return {
        "type": "websocket",
        "path": "/ws",
        "query_string": query.encode("latin-1"),
        "headers": headers or [],
        "client": ("9.9.9.9", 1234),
    }


class _LimiterCaido:
    """Backend de rate limiting que no responde, como un Redis apagado."""

    def __init__(self) -> None:
        self.claves: list[str] = []

    async def allow(self, key: str) -> bool:
        self.claves.append(key)
        raise BackendUnavailable("redis no responde")


# ------------------------------------------------------- IP del cliente
def test_sin_xff_la_ip_del_cliente_es_el_peer():
    """Con `trust_proxy` pero sin cabecera XFF, manda el peer."""
    cfg = Config(trust_proxy=True)
    scope = {"type": "http", "client": ("9.9.9.9", 1234), "headers": []}
    assert mw._client_ip(scope, cfg) == "9.9.9.9"


def test_sin_cliente_la_ip_del_cliente_es_desconocida():
    """Una peticion sin peer (no deberia pasar) no rompe nada."""
    cfg = Config()
    scope = {"type": "http", "headers": []}
    assert mw._client_ip(scope, cfg) == "unknown"


# ------------------------------------------------------- Content-Length
def test_un_content_length_no_numerico_se_ignora():
    """Un `Content-Length` invalido no es un error: se ignora.

    El cuerpo se acota de todas formas al leerlo; un header raro no puede
    tumbar el middleware.
    """
    scope = {"headers": [(b"content-length", b"no-es-un-numero")]}
    assert mw._content_length(scope) is None


def test_un_content_length_normal_se_lee():
    scope = {"headers": [(b"content-length", b"42")]}
    assert mw._content_length(scope) == 42


def test_sin_content_length_no_hay_tamano_declarado():
    scope = {"headers": []}
    assert mw._content_length(scope) is None


# ------------------------------------------------------- atribucion
def test_el_campo_atribuido_es_el_parametro_que_casa():
    """El campo del log es el parametro culpable, no el primero de la lista."""
    cfg = Config()
    campo = mw._query_field("/buscar", "q=1&union%20select=1", cfg)
    assert campo == "union select"


def test_sin_payload_no_hay_campo_atribuido():
    cfg = Config()
    assert mw._query_field("/buscar", "q=1&otro=2", cfg) is None


# ------------------------------------- WebSocket: Redis caido
def test_el_handshake_websocket_se_corta_si_redis_cae_y_no_se_abre(caplog):
    """Con `rate_fail_open=False`, un Redis caido cierra el handshake.

    El codigo 1013 dice "reintentad mas tarde": el cliente sabe que es un
    problema del servidor, no un rechazo suyo.
    """
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        cfg = Config(rate_limit=10, rate_fail_open=False)
        middleware = GatekeeperMiddleware(_noop_app, config=cfg)
        middleware.limiter = _LimiterCaido()
        enviados: list[dict] = []

        asyncio.run(
            middleware._handle_websocket(
                _scope_websocket(), _receive_websocket(), _send_websocket(enviados)
            )
        )

    assert enviados == [{"type": "websocket.close", "code": 1013}]
    assert any("rate_backend_error" in r.getMessage() for r in caplog.records)


def test_el_handshake_websocket_pasa_si_redis_cae_y_se_abre_en_modo_fail_open():
    """Con `rate_fail_open=True` (el defecto) el handshake sigue.

    Es una decision consciente: cortar todo el trafico porque Redis no
    responde seria una denegacion de servicio causada por el propio WAF.
    """
    cfg = Config(rate_limit=10, rate_fail_open=True)
    middleware = GatekeeperMiddleware(_noop_app, config=cfg)
    middleware.limiter = _LimiterCaido()
    enviados: list[dict] = []

    asyncio.run(
        middleware._handle_websocket(
            _scope_websocket(), _receive_websocket(), _send_websocket(enviados)
        )
    )

    assert enviados == [], "el handshake no deberia cerrarse con fail_open"


# ------------------------------- WebSocket: presupuesto agotado
def test_el_handshake_websocket_corta_si_agota_el_presupuesto(caplog):
    """Una query enorme agota el presupuesto: el handshake no entra.

    Agotar el presupuesto NO es un modo fail-open: si el handshake pasara,
    el ataque se quedaria sin inspeccionar.
    """
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        with TestClient(_app(max_fields=1)) as client:
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect("/ws?a=1&b=2"):
                    pass
    assert any("too_many_fields" in r.getMessage() for r in caplog.records)


# ------------------------------- WebSocket: cabecera exenta
def test_una_cabecera_exenta_no_se_inspecciona_en_el_handshake():
    """Una cabecera marcada como exenta se salta: ni se lee ni se escanea."""
    with TestClient(_app(exclude_fields=["user-agent"])) as client:
        with client.websocket_connect("/ws", headers={"user-agent": SQLI}) as websocket:
            assert websocket.receive_text() == "hola"


def test_sin_exencion_el_handshake_con_payload_en_cabecera_se_rechaza():
    """El mismo payload, sin exencion, no entra."""
    with TestClient(_app()) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws", headers={"user-agent": SQLI}):
                pass


# ------------------------------- HTTP: reloj de inspeccion agotado
class _PresupuestoFalso:
    """Presupuesto que agota el reloj en la comprobacion numero `fallo_en`.

    El reloj real (`time.perf_counter`) no se puede agotar de forma fiable en
    un test: dependeria de lo que tarde la maquina. Aqui se sustituye el
    presupuesto entero, asi que el test dice exactamente que se quiere:
    "cuando el reloj se agota en ESTE punto, se corta".

    El limite que se lleva la excepcion es el numero de la comprobacion
    (1000, 2000, ...): el evento de auditoria lo escribe, asi que el test
    puede COMPROBAR en que comprobacion se corto, y no suponerlo.
    """

    def __init__(self, *args, fallo_en: int = 1, **kwargs) -> None:
        self.campos = 0
        self.fallo_en = fallo_en
        self.comprobaciones = 0

    def cuenta(self, n: int = 1) -> None:
        self.campos += n

    def reinicia_reloj(self) -> None:
        pass

    def comprueba_tiempo(self) -> None:
        self.comprobaciones += 1
        if self.comprobaciones == self.fallo_en:
            raise InspectionTimeout(1000 * self.comprobaciones, self.campos)


def _eventos(caplog) -> list[dict]:
    """Los eventos del log de Gatekeeper, ya parseados."""
    import json

    return [
        json.loads(rec.getMessage())
        for rec in caplog.records
        if rec.name == "gatekeeper"
    ]


def test_el_body_que_agota_el_reloj_se_corta_con_413(monkeypatch, caplog):
    """Si el reloj se agota inspecting el body, la peticion se corta.

    Agotar el reloj da 413, NO un 200: si la peticion pasara, el payload se
    quedaria sin inspeccionar.
    """
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        monkeypatch.setattr(
            mw, "InspectionBudget", partial(_PresupuestoFalso, fallo_en=1)
        )
        with TestClient(_app()) as client:
            r = client.post("/", json={"q": "hola"})
    assert r.status_code == 413, r.text
    # El limite es el numero de comprobacion: se corto en la primera.
    tiempos = [e for e in _eventos(caplog) if e["event"] == "inspection_timeout"]
    assert tiempos and tiempos[0]["limite"] == 1000, tiempos


def test_el_cruce_query_body_que_agota_el_reloj_se_corta_con_413(monkeypatch, caplog):
    """Lo mismo, en el cruce query+body: el corte es el mismo.

    El cuerpo es un JSON que es UNA sola cadena, para que el bucle de campos
    consuma exactamente una comprobacion: asi la siguiente es, sin ambiguedad,
    la del cruce.
    """
    from gatekeeper.body import extract_strings_and_values

    campos, _ = extract_strings_and_values("application/json", b'"hola"')
    assert len(campos) == 1, campos

    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        monkeypatch.setattr(
            mw, "InspectionBudget", partial(_PresupuestoFalso, fallo_en=2)
        )
        with TestClient(_app(inspect_cross_carrier=True)) as client:
            r = client.post("/?q=1", content=b'"hola"',
                            headers={"content-type": "application/json"})
    assert r.status_code == 413, r.text
    # Limite 2000 = segunda comprobacion = la del cruce.
    tiempos = [e for e in _eventos(caplog) if e["event"] == "inspection_timeout"]
    assert tiempos and tiempos[0]["limite"] == 2000, tiempos


def test_un_reloj_que_no_se_agota_no_corta_nada(monkeypatch):
    """El presupuesto de mentira solo agota en la comprobacion que se le dice."""
    monkeypatch.setattr(mw, "InspectionBudget", partial(_PresupuestoFalso, fallo_en=99))
    with TestClient(_app()) as client:
        r = client.post("/", json={"q": "hola"})
    assert r.status_code == 200, r.text


# ------------------------------------------------------- utilidades
async def _noop_app(scope, receive, send) -> None:
    """App vacia: si el middleware deja pasar la peticion, no dice nada."""


def _receive_websocket() -> dict:
    """Recepcion que no se usa: el middleware no lee frames del handshake."""
    return {"type": "websocket.connect"}


def _send_websocket(enviados: list[dict]):
    async def send(message: dict) -> None:
        enviados.append(message)

    return send
