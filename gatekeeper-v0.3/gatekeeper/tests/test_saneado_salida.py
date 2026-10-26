"""Saneado de la salida y promesa del log (Fase 2.4).

Dos cosas que se comprueban aqui:

1. **El escape de terminal.** Lo que el CLI imprime lo eligio el atacante (el
   nombre de un campo, la ruta). Un `\x1b[2J` en la URL puede borrar la
   pantalla del operador o reescribir el titulo de su ventana. Se sanea al
   escribir el log Y al imprimir el informe, porque el log puede venir de
   otra herramienta (con el ESC ya decodificado).

2. **La promesa del log.** La documentacion decia "nunca se registra el
   contenido del payload". Es FALSA: el nombre de un campo lo elige el
   atacante, asi que puede ser el payload entero. Lo que se garantiza es que
   los VALORES no se registran, y que el texto que si se registra va
   saneado y acotado.
"""
from __future__ import annotations

import json
import logging

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.cli import construir_informe, main
from gatekeeper.sanitize import MAX_LONGITUD_LOG, sanear, sanear_y_acotar

ESC = "\x1b"


async def _ok(request):
    return PlainTextResponse("ok")


def _app(**cfg):
    app = Starlette(routes=[Route("/{path:path}", _ok, methods=["GET", "POST"])])
    return GatekeeperMiddleware(app, Config(rate_limit=0, **cfg))


# ------------------------------------------------------------ el saneado


def test_el_esc_se_quita():
    assert sanear(f"antes{ESC}[2Jdespues") == "antes\\e[2Jdespues"


def test_los_controles_se_quitan():
    assert sanear("a\x00b\x07c") == "abc"
    assert sanear("a\x7fb") == "ab"


def test_los_blancos_de_control_se_vuelven_espacio():
    """Un salto de linea en un nombre de campo romperia la tabla del informe."""
    assert sanear("a\nb\rc\td") == "a b c d"


def test_el_texto_normal_no_se_toca():
    texto = "SELECT * FROM users WHERE id = 1 — acentos, ñ, emojis 🛡"
    assert sanear(texto) == texto


def test_el_saneado_acota():
    largo = "x" * 1000
    corto = sanear_y_acotar(largo)
    assert len(corto) == MAX_LONGITUD_LOG
    assert corto.endswith("…")


def test_el_acotado_marca_el_recorte():
    """Que se note que el texto estaba incompleto."""
    assert sanear_y_acotar("x" * 1000).endswith("…")
    assert not sanear_y_acotar("x" * 10).endswith("…")


# ------------------------------------------------- el log del middleware


def test_el_log_no_lleva_escapes(caplog):
    """Un ESC en la ruta no llega al log."""
    app = _app()
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        with TestClient(app) as client:
            client.get("/x", headers={"user-agent": f"curl{ESC}[2J"})
    for registro in caplog.records:
        assert ESC not in registro.getMessage(), registro.getMessage()


def test_el_log_acota_el_nombre_del_campo(caplog):
    """Un nombre de campo enorme no produce una linea de log enorme."""
    app = _app()
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        with TestClient(app) as client:
            client.post(
                "/x",
                content=("q" * 5000).encode(),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
    for registro in caplog.records:
        assert len(registro.getMessage()) < 2000, len(registro.getMessage())


def test_el_log_sigue_siendo_json_valido(caplog):
    app = _app()
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        with TestClient(app) as client:
            client.get("/x")
    for registro in caplog.records:
        json.loads(registro.getMessage())  # no revienta


# ------------------------------------------------------ la salida del CLI


def _log_con_escapes(tmp_path):
    ruta = tmp_path / "tráfico.log"
    evento = {
        "event": "attack_detected",
        "rule": "sqli",
        "source": "body",
        "field": f"{ESC}]0;titulo manipulado\x07/campo",
        "path": f"/x{ESC}[2J",
    }
    ruta.write_text(json.dumps(evento) + "\n", encoding="utf-8")
    return ruta


def test_el_informe_no_lleva_escapes(tmp_path):
    """El ESC del log no puede llegar a la terminal del operador."""
    ruta = _log_con_escapes(tmp_path)
    informe = construir_informe(ruta)
    assert ESC not in informe, repr(informe)


def test_el_json_del_cli_no_lleva_escapes(tmp_path, capsys):
    """Tambien en el formato JSON: ahi el ESC ya venia decodificado."""
    ruta = _log_con_escapes(tmp_path)
    main(["report", str(ruta), "--json"])
    salida = capsys.readouterr().out
    assert ESC not in salida, repr(salida)
    # Y sigue siendo JSON valido.
    json.loads(salida)


def test_el_log_de_acceso_generico_tambien_se_sanea(tmp_path):
    """El segundo formato del CLI (acceso generico) lleva los bytes sueltos."""
    ruta = tmp_path / "acceso.log"
    ruta.write_text(
        f"GET /x?a=1{ESC}[2J 200\n"
        f"GET /y?q=union{ESC}[2Jselect 1 200\n",
        encoding="utf-8",
    )
    informe = construir_informe(ruta)
    assert ESC not in informe, repr(informe)


def test_el_esc_queda_marcado_como_visible(tmp_path):
    """No se borra en silencio: se marca, para que se vea que habia algo."""
    ruta = _log_con_escapes(tmp_path)
    informe = construir_informe(ruta)
    assert "\\e" in informe, repr(informe)
