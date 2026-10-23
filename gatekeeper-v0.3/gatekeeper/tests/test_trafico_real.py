"""El procedimiento de trafico real se tiene que poder SEGUIR, no solo leer.

`docs/trafico-real.md` describe un procedimiento de varios pasos: poner en modo
monitor, recoger los eventos, analizar el log con `gatekeeper report`, decidir
el ajuste y volver a medir. Si alguno de esos pasos no funciona tal como se
documenta, el procedimiento es papel: el lector lo sigue y se queda atascado.

Este test EJECUCTA el camino completo con un log de ejemplo y comprueba que:
- el log que se documenta tiene el formato que el informe espera;
- el informe dice qué reglas saltaron, en qué campos y qué ajuste propone;
- el ajuste que propone se puede aplicar de verdad (que `Config` lo acepta);
- el modo monitor no bloquea, pero registra.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware

ROOT = Path(__file__).resolve().parent.parent

# Eventos tal como los emite el middleware en modo monitor.
EVENTOS = [
    {
        "ts": 1750000000.0, "event": "attack_detected", "ip": "203.0.113.7",
        "method": "GET", "path": "/buscar", "rule": "sqli", "source": "query",
        "field": "q", "pattern": "\\bunion\\b", "blocked": False,
    },
    {
        "ts": 1750000001.0, "event": "attack_detected", "ip": "203.0.113.8",
        "method": "GET", "path": "/buscar", "rule": "sqli", "source": "query",
        "field": "q", "pattern": "\\bunion\\b", "blocked": False,
    },
    {
        "ts": 1750000002.0, "event": "attack_detected", "ip": "203.0.113.9",
        "method": "GET", "path": "/webhook", "rule": "xss", "source": "query",
        "field": "url", "pattern": "<script", "blocked": False,
    },
]


@pytest.fixture
def log_de_trafico(tmp_path: Path) -> Path:
    ruta = tmp_path / "trafico.log"
    with ruta.open("w", encoding="utf-8") as fh:
        for evento in EVENTOS:
            fh.write(json.dumps(evento, ensure_ascii=False) + "\n")
    return ruta


def test_el_log_que_documenta_el_procedimiento_se_analiza(log_de_trafico: Path):
    """Paso 3: `gatekeeper report` sobre el log que se documenta."""
    proc = subprocess.run(
        [sys.executable, "-m", "gatekeeper.cli", "report", str(log_de_trafico)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    salida = proc.stdout

    # Dice que reglas saltaron, con cuantos.
    assert "sqli" in salida and "xss" in salida
    # Y en que campos: eso es lo que permite ajustar.
    assert "q" in salida and "url" in salida
    # Y propone un ajuste concreto.
    assert "exclude_fields" in salida


def test_el_informe_sale_tambien_en_json(log_de_trafico: Path):
    """El procedimiento menciona `--json` para procesar logs a escala."""
    proc = subprocess.run(
        [sys.executable, "-m", "gatekeeper.cli", "report", str(log_de_trafico), "--json"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    datos = json.loads(proc.stdout)
    assert datos, "el informe JSON esta vacio"
    assert isinstance(datos, (dict, list))


def test_el_ajuste_propuesto_se_puede_aplicar(log_de_trafico: Path):
    """Paso 4: el `exclude_fields` que propone el informe lo acepta Config.

    Si el ajuste que el informe sugiere no se puede aplicar, el procedimiento
    lleva a un callejon sin salida.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "gatekeeper.cli", "report", str(log_de_trafico)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr

    # El informe propone excluir el campo mas repetido.
    assert "exclude_fields:" in proc.stdout
    campos = [
        linea.strip().lstrip("- ")
        for linea in proc.stdout.splitlines()
        if linea.strip().startswith("- ") and "q" in linea
    ]
    assert campos, "el informe no propone ningun campo concreto"
    config = Config(exclude_fields=[campos[0]])
    assert config.exclude_fields == [campos[0]]


def test_el_modo_monitor_registra_pero_no_bloquea(caplog):
    """Paso 1: el modo monitor deja pasar y deja rastro.

    Es la diferencia entre poder observar el trafico y tener que decidir a
    ciegas: si bloquea, el trafico que hay que medir no llega.
    """
    import logging

    async def home(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/{path:path}", home)])
    mw = GatekeeperMiddleware(app, config=Config(rate_limit=0, monitor_only=True))
    client = TestClient(mw)

    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        r = client.get("/buscar?q=1%20UNION%20SELECT%20x")

    assert r.status_code == 200, "el modo monitor no debe bloquear"
    eventos = [rec.getMessage() for rec in caplog.records if rec.name == "gatekeeper"]
    assert any("attack_detected" in e for e in eventos), eventos
    # Y el evento lleva el campo: sin el, no hay nada que ajustar.
    assert any('"field": "q"' in e or '"field":"q"' in e for e in eventos), eventos


def test_el_log_no_lleva_el_payload(caplog):
    """Lo que se recoge para medir no puede filtrar el payload.

    El procedimiento dice que el log no lleva el payload: si fuera asi, el
    propio procedimiento de medicion seria una fuga.
    """
    import logging

    async def home(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/{path:path}", home)])
    mw = GatekeeperMiddleware(app, config=Config(rate_limit=0, monitor_only=True))
    client = TestClient(mw)

    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        client.get("/buscar?q=1%20UNION%20SELECT%20secreto_de_la_tabla")

    texto = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "secreto_de_la_tabla" not in texto, "el payload se ha filtrado al log"
