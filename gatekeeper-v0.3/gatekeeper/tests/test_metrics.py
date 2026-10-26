"""`tools/metrics.py` convierte el log de auditoria en metricas Prometheus.

Dos cosas que hay que fijar con un test:

1. Los **contadores** cuentan lo que dicen contar (y los del catalogo de
   `corpus/events.json` tienen los mismos nombres).
2. Las metricas **no filtran datos personales**: ni IPs, ni rutas, ni
   payloads. Los conteos van al Prometheus; los datos se quedan en el log.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "metrics.py"
CATALOGO = ROOT / "corpus" / "events.json"


def _carga():
    spec = importlib.util.spec_from_file_location("metrics_tool", SCRIPT)
    assert spec and spec.loader
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def _evento(evento: str, **extra: object) -> str:
    datos = {
        "ts": 1.0,
        "event": evento,
        "ip": "203.0.113.9",
        "method": "GET",
        "path": "/privado",
    }
    datos.update(extra)
    return json.dumps(datos)


def test_agrega_los_ataques_por_regla_y_origen():
    modulo = _carga()
    lineas = [
        _evento("attack_detected", rule="sqli", source="query", field="q"),
        _evento("attack_detected", rule="sqli", source="query", field="q"),
        _evento("attack_detected", rule="xss", source="body", field="html"),
    ]
    datos = modulo.agregar(lineas)
    ataques = {(a["rule"], a["source"]): a["count"] for a in datos["attacks"]}
    assert ataques[("sqli", "query")] == 2
    assert ataques[("xss", "body")] == 1
    assert datos["eventos_total"] == 3


def test_agrega_el_resto_de_los_contadores():
    modulo = _carga()
    lineas = [
        _evento("rate_limited"),
        _evento("blocked_ip"),
        _evento("body_too_large"),
        _evento("too_many_fields"),
        _evento("inspection_timeout"),
        _evento("rate_backend_error", fail_open="true"),
    ]
    datos = modulo.agregar(lineas)
    assert datos["rate_limited"] == 1
    assert datos["blocked_ips"] == 1
    assert datos["body_too_large"] == 1
    assert datos["too_many_fields"] == 1
    assert datos["inspection_timeout"] == 1
    assert datos["rate_backend_errors"] == {"true": 1}


def test_la_salida_prometheus_expone_los_contadores():
    modulo = _carga()
    lineas = [_evento("attack_detected", rule="sqli", source="query", field="q")]
    texto = modulo.a_prometheus(modulo.agregar(lineas))
    assert "gatekeeper_attacks_total" in texto
    assert 'rule="sqli"' in texto
    assert "gatekeeper_rate_limited_total" in texto


def test_las_metricas_no_filtran_datos_personales():
    """Ni IP, ni ruta, ni payload: eso se queda en el log."""
    modulo = _carga()
    lineas = [
        _evento(
            "attack_detected",
            rule="sqli",
            source="query",
            field="token_secreto",
            pattern="\\bunion\\b",
        )
    ]
    texto = modulo.a_prometheus(modulo.agregar(lineas))
    assert "203.0.113.9" not in texto      # la IP
    assert "/privado" not in texto          # la ruta
    assert "token_secreto" not in texto     # el nombre del campo
    assert "union" not in texto             # el patron


def test_las_lineas_que_no_son_json_no_rompen():
    modulo = _carga()
    lineas = ["no es json", "", _evento("rate_limited"), "{roto"]
    datos = modulo.agregar(lineas)
    assert datos["rate_limited"] == 1
    assert datos["eventos_total"] == 1


def test_los_nombres_de_los_contadores_cuadran_con_el_catalogo():
    """El catalogo de eventos y las metricas no pueden separarse."""
    modulo = _carga()
    catalogo = json.loads(CATALOGO.read_text(encoding="utf-8"))
    declarados = {
        evento["metrics"]["counter"]
        for evento in catalogo["events"].values()
        if "metrics" in evento
    }
    texto = modulo.a_prometheus(modulo.agregar([]))
    faltan = {nombre for nombre in declarados if nombre not in texto}
    assert not faltan, faltan
