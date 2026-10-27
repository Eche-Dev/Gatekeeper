"""Cobertura de la CLI: los formatos que solo se dan con logs raros.

La CLI lee ficheros de log que puede haber escrito otra herramienta. Por eso
tiene que aguantar lineas vacias, comentarios, JSON roto y rutas que no
empiezan por barra: cada uno de esos casos era un `continue` que nadie
ejercitaba.

No cambia ningun comportamiento: solo se comprueba lo que ya hace el codigo.
"""

from __future__ import annotations

import json

import pytest

from gatekeeper import cli


# ------------------------------------------------- la lectura de las lineas
def test_las_lineas_vacias_y_los_comentarios_se_ignoran():
    """Un log con huecos y comentarios no produce ningun evento."""
    lineas = ["", "   ", "# esto es un comentario", "#"]
    assert list(cli._iter_events(lineas)) == []


def test_un_json_roto_no_revienta_el_informe():
    """Una linea que empieza por `{` pero no es JSON se salta.

    Sin esto, un log a medio escribir (un `tail -f` que corta la linea) haria
    que la CLI fallara al entero.
    """
    lineas = ['{"event": "attack_detected", "rule": "sqli"', "no es json"]
    assert list(cli._iter_events(lineas)) == []


def test_una_ruta_que_no_empieza_por_barra_no_es_una_peticion():
    """El formato de acceso generico solo cuenta si el objetivo es una ruta."""
    lineas = ["GET http://ejemplo.com/x 200", "POST ftp://x 200"]
    assert list(cli._iter_events(lineas)) == []


def test_el_nombre_del_campo_es_el_primero_que_empieza_por_letra():
    """Un parámetro cuyo nombre no empieza por letra no cuenta como campo.

    La heuristica del nombre del campo es a proposito simple: el nombre lo
    elige el atacante y no tiene por que ser una letra.
    """
    assert cli._field_de_query("q=valor") == "q"
    assert cli._field_de_query("1abc=valor&campo=otro") == "campo"
    assert cli._field_de_query("123=valor") is None
    assert cli._field_de_query("") is None


# ----------------------------------------------------------- las tablas
def test_la_tabla_avisa_cuando_hay_mas_filas_que_el_limite():
    """Si hay más elementos que filas permitidas, se dice cuántos faltan.

    Sin ese aviso, un informe con 200 reglas distintas y un limite de 15
    parecería completo.
    """
    from collections import Counter

    contador = Counter({f"regla-{i}": i for i in range(20)})
    lineas = cli._fmt_tabla("Reglas", contador, limite=15)
    assert any("y 5 más" in linea for linea in lineas)


# ------------------------------------------------------------ el informe
def test_el_informe_de_un_log_de_acceso_detecta_el_ataque(tmp_path, capsys):
    """El formato de acceso generico tambien produce informe.

    Un log de acceso ("GET /ruta 200") no viene de Gatekeeper, pero el informe
    tiene que saber reconocer un ataque en el.
    """
    log = tmp_path / "acceso.log"
    log.write_text(
        "GET /buscar?q=1%27%20OR%20%271%27%3D%271 200\n",
        encoding="utf-8",
    )
    informe = cli.construir_informe(log)
    assert "sqli" in informe
    assert "peticiones bloqueadas" in informe


def test_el_informe_sin_ataques_dice_que_no_hay_que_ajustar(tmp_path):
    """Un log limpio no inventa ajustes: lo dice."""
    log = tmp_path / "limpio.log"
    log.write_text("GET /salud 200\n", encoding="utf-8")
    informe = cli.construir_informe(log)
    assert "No hay falsos positivos que ajustar" in informe


# ------------------------------------------------------------- el main
def test_el_comando_report_devuelve_el_informe(tmp_path, capsys):
    """`gatekeeper report <log>` escribe el informe y sale con 0."""
    log = tmp_path / "acceso.log"
    log.write_text("GET /buscar?q=1%27%20OR%20%271%27%3D%271 200\n", encoding="utf-8")
    codigo = cli.main(["report", str(log)])
    assert codigo == 0
    assert "Informe de tráfico" in capsys.readouterr().out


def test_el_comando_report_en_json_devuelve_el_resumen(tmp_path, capsys):
    """`--json` devuelve una salida legible por maquina."""
    log = tmp_path / "eventos.log"
    log.write_text(
        json.dumps(
            {"event": "attack_detected", "rule": "sqli", "path": "/x", "field": "q"}
        )
        + "\n",
        encoding="utf-8",
    )
    codigo = cli.main(["report", str(log), "--json"])
    assert codigo == 0
    datos = json.loads(capsys.readouterr().out)
    assert datos["total"] == 1
    assert datos["rules"] == {"sqli": 1}


def test_un_log_que_no_existe_dice_que_no_existe(tmp_path, capsys):
    """Un log inexistente es un error claro, no una excepcion."""
    codigo = cli.main(["report", str(tmp_path / "no-existe.log")])
    assert codigo == 2
    assert "no existe el log" in capsys.readouterr().err


def test_un_comando_desconocido_es_un_error_de_uso():
    """Un subcomando que no existe se rechaza con el codigo de argparse."""
    with pytest.raises(SystemExit) as excepcion:
        cli.main(["inventado"])
    assert excepcion.value.code == 2
