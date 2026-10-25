"""Las tres superficies que se cerraron: WebSocket, octet-stream y multipart.

Antes de este fichero, un atacante que quisiera saltarse Gatekeeper solo
tenia que hablar el protocolo o el content-type que el middleware no
miraba:

- el handshake de un WebSocket pasaba sin rate limit ni inspeccion;
- un JSON enviado como `application/octet-stream` no se escaneaba;
- un `multipart/form-data` no se inspeccionaba, y ahi viven los
  `filename=../../etc/passwd`.

Cada test que falla aqui es un bypass.
"""
from __future__ import annotations

import json

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from gatekeeper import Config, GatekeeperMiddleware

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
        Route("/subida", home, methods=["POST"]),
        WebSocketRoute("/ws", ws),
    ])
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))
    return app


# --------------------------------------------------------------- WebSocket
def test_websocket_legitimo_pasa():
    with TestClient(_app()) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "hola"


def test_websocket_con_sqli_en_el_handshake_se_rechaza():
    """El handshake se inspecciona: un payload en la query no entra."""
    with TestClient(_app()) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/ws?q={SQLI.replace(' ', '%20')}"):
                pass


def test_websocket_con_sqli_en_los_headers_se_rechaza():
    """El handshake tambien se inspecciona en las cabeceras."""
    with TestClient(_app()) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "/ws", headers={"user-agent": SQLI}
            ):
                pass


def test_websocket_tiene_rate_limit():
    """Con rate_limit=1, el segundo handshake se rechaza."""
    app = _app(rate_limit=1, rate_window=60)
    with TestClient(app) as client:
        with client.websocket_connect("/ws"):
            pass
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws"):
                pass


def test_websocket_con_sqli_en_modo_monitor_se_registra_pero_no_corta(caplog):
    import logging

    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        with TestClient(_app(monitor_only=True)) as client:
            with client.websocket_connect(f"/ws?q={SQLI.replace(' ', '%20')}") as websocket:
                assert websocket.receive_text() == "hola"
    eventos = [rec.getMessage() for rec in caplog.records if rec.name == "gatekeeper"]
    assert any("attack_detected" in e for e in eventos), eventos


def test_websocket_se_puede_desactivar():
    """`inspect_websockets=False` deja los WebSockets como estaban."""
    with TestClient(_app(inspect_websockets=False)) as client:
        with client.websocket_connect(f"/ws?q={SQLI.replace(' ', '%20')}") as websocket:
            assert websocket.receive_text() == "hola"


def test_websocket_ip_bloqueada_tampoco_entra():
    with TestClient(_app(blocked_ips={"testclient"})) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws"):
                pass


# ------------------------------------------------------------ octet-stream
def test_json_como_octet_stream_se_inspecciona():
    """El content-type generic no decide: decide el CONTENIDO."""
    cuerpo = json.dumps({"q": SQLI}).encode()
    with TestClient(_app()) as client:
        r = client.post("/", content=cuerpo,
                        headers={"content-type": "application/octet-stream"})
    assert r.status_code == 403, r.text


def test_json_como_octet_stream_con_espacios_al_ppio_tambien():
    cuerpo = b"   \n\t" + json.dumps({"q": SQLI}).encode()
    with TestClient(_app()) as client:
        r = client.post("/", content=cuerpo,
                        headers={"content-type": "application/octet-stream"})
    assert r.status_code == 403, r.text


def test_binario_de_verdad_como_octet_stream_pasa():
    """Un binario que no es JSON no se inspecciona (no es texto)."""
    with TestClient(_app()) as client:
        r = client.post("/", content=b"\x89PNG\r\n\x1a\n" + b"\x00" * 64,
                        headers={"content-type": "application/octet-stream"})
    assert r.status_code == 200, r.text


def test_imagen_no_se_lee():
    """Un image/png no se lee: es binario de verdad, no un JSON disfrazado."""
    with TestClient(_app()) as client:
        r = client.post("/", content=b"\x89PNG" + SQLI.encode(),
                        headers={"content-type": "image/png"})
    assert r.status_code == 200, r.text


# --------------------------------------------------------------- multipart
def test_multipart_con_traversal_en_el_filename_se_rechaza():
    with TestClient(_app()) as client:
        r = client.post(
            "/subida",
            files={"f": ("../../etc/passwd", b"contenido", "text/plain")},
            data={"campo": "valor"},
        )
    assert r.status_code == 403, r.text


def test_multipart_con_payload_en_un_campo_de_texto_se_rechaza():
    with TestClient(_app()) as client:
        r = client.post(
            "/subida",
            data={"campo": SQLI},
            files={"f": ("informe.pdf", b"%PDF-1.4", "application/pdf")},
        )
    assert r.status_code == 403, r.text


def test_multipart_legitimo_pasa():
    with TestClient(_app()) as client:
        r = client.post(
            "/subida",
            data={"campo": "hola", "otro": "mundo"},
            files={"f": ("informe.pdf", b"%PDF-1.4", "application/pdf")},
        )
    assert r.status_code == 200, r.text


def test_multipart_se_puede_desactivar():
    """`inspect_multipart=False` devuelve el comportamiento anterior."""
    with TestClient(_app(inspect_multipart=False)) as client:
        r = client.post(
            "/subida",
            files={"f": ("../../etc/passwd", b"contenido", "text/plain")},
        )
    assert r.status_code == 200, r.text


def test_multipart_respeta_el_limite_de_body():
    """Un multipart enorme se corta con 413 como cualquier otro body."""
    with TestClient(_app(max_body_size=1024)) as client:
        r = client.post(
            "/subida",
            files={"f": ("informe.pdf", b"x" * 4096, "application/pdf")},
        )
    assert r.status_code == 413, r.text
