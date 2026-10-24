"""El catalogo de eventos y las metricas tienen que estar al dia con el codigo.

El plan pide "definir metricas/observabilidad de bloqueos, limites, errores de
Redis, respuestas 413 y modo monitor, sin exponer datos sensibles". Eso son dos
cosas que se pueden desincronizar sin que nadie se entere:

- que el middleware emita un evento que no esta en el catalogo (o al reves);
- que las metricas amazementcarry datos personales.

Este test comprueba las dos cosas, y que el exportador de Prometheus produce
una exposicion valida.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = json.loads((ROOT / "corpus" / "events.json").read_text(encoding="utf-8"))
MIDDLEWARE = (ROOT / "src" / "gatekeeper" / "middleware.py").read_text(encoding="utf-8")


def _eventos_del_codigo() -> set[str]:
    """Los `event` que el middleware emite de verdad."""
    encontrados = set(re.findall(r'_audit\(\s*\n?\s*"([a-z_]+)"', MIDDLEWARE))
    assert encontrados, "no se ha encontrado ningun evento en el middleware"
    return encontrados


def test_el_catalogo_cubre_todos_los_eventos_del_codigo():
    """Si el middleware emite un evento que no esta en el catalogo, este falla."""
    codigo = _eventos_del_codigo()
    documentados = set(CATALOG["events"])
    faltan = codigo - documentados
    assert not faltan, (
        f"eventos que el middleware emite y el catalogo no documenta: {sorted(faltan)}"
    )


def test_el_catalogo_no_documenta_eventos_que_no_existen():
    """Si el catalogo documenta un evento que ya no se emite, este falla."""
    codigo = _eventos_del_codigo()
    documentados = set(CATALOG["events"])
    sobran = documentados - codigo
    assert not sobran, (
        f"eventos documentados que el middleware ya no emite: {sorted(sobran)}"
    )


def test_cada_evento_tiene_lo_que_hace_falta_para_operarlo():
    """Un evento sinmeaning, sin 'when' y sin contador no se puede operar."""
    for nombre, evento in CATALOG["events"].items():
        assert evento.get("meaning"), f"{nombre}: falta 'meaning'"
        assert evento.get("when"), f"{nombre}: falta 'when'"
        assert evento.get("metrics", {}).get("counter"), f"{nombre}: falta el contador"
        assert "extra_fields" in evento, f"{nombre}: falta 'extra_fields'"


def test_los_codigos_de_respuesta_estan_documentados():
    """Los codigos que emite el middleware tienen que estar en el catalogo."""
    for codigo in ("403", "413", "429", "503"):
        assert codigo in CATALOG["response_codes"], f"falta el codigo {codigo}"


def test_el_catalogo_dice_que_no_se_registra_el_payload():
    """La garantia de que no hay payloads en el log tiene que estar escrita."""
    texto = json.dumps(CATALOG, ensure_ascii=False).lower()
    assert "payload" in texto
    assert CATALOG["what_is_never_logged"], "falta la lista de lo que nunca se registra"


def test_el_modo_monitor_esta_documentado():
    """El modo monitor cambia el comportamiento de los eventos: va documentado."""
    assert "monitor_only" in CATALOG
    monitor = CATALOG["monitor_only"]
    assert monitor.get("meaning"), "falta explicar el modo monitor"
    assert monitor.get("use"), "falta para que se usa"
    # El evento `attack_detected` lleva el campo `blocked`, que es lo que
    # distingue "registrado" de "bloqueado".
    assert "blocked" in CATALOG["events"]["attack_detected"]["extra_fields"]


def test_la_ayuda_de_prometheus_cubre_los_cinco_contadores():
    """El exportador tiene que exponer los cinco contadores del catalogo."""
    sys.path.insert(0, str(ROOT / "tools"))
    import metrics  # noqa: PLC0415

    assert len(metrics.CONTADORES) == 5
    for nombre, ayuda in metrics.CONTADORES:
        assert nombre.startswith("gatekeeper_"), nombre
        assert ayuda and ayuda.strip(), nombre


def test_el_exportador_no_saca_datos_personales(tmp_path: Path):
    """Las metricas son conteos: ni IPs, ni rutas, ni patrones."""
    sys.path.insert(0, str(ROOT / "tools"))
    import metrics  # noqa: PLC0415

    eventos = [
        {"ts": 1.0, "event": "attack_detected", "ip": "203.0.113.7", "method": "GET",
         "path": "/buscar", "rule": "sqli", "source": "query", "field": "q",
         "pattern": "\\bunion\\b\\sselect", "blocked": True},
        {"ts": 2.0, "event": "rate_limited", "ip": "198.51.100.3", "method": "GET",
         "path": "/api/privado", "blocked": True},
        {"ts": 3.0, "event": "blocked_ip", "ip": "192.0.2.66", "method": "GET",
         "path": "/x", "entry": "192.0.2.0/24", "blocked": True},
        {"ts": 4.0, "event": "body_too_large", "ip": "198.51.100.4", "method": "POST",
         "path": "/upload", "size": 5000000, "blocked": True},
        {"ts": 5.0, "event": "rate_backend_error", "ip": "198.51.100.5", "method": "GET",
         "path": "/api", "fail_open": True, "error": "connection refused"},
    ]
    log = tmp_path / "trafico.log"
    with log.open("w", encoding="utf-8") as fh:
        for e in eventos:
            fh.write(json.dumps(e) + "\n")

    salida = metrics.a_prometheus(metrics.agregar(log.read_text(encoding="utf-8").splitlines()))

    for dato in ("203.0.113", "198.51.100", "192.0.2", "/buscar", "/api", "/upload",
                 "union", "pattern", "ip="):
        assert dato not in salida, f"las metricas filtran {dato!r}"
    # Pero los conteos si estan.
    assert 'gatekeeper_attacks_total{rule="sqli",source="query"} 1' in salida
    assert "gatekeeper_rate_limited_total 1" in salida
    assert "gatekeeper_blocked_ips_total 1" in salida
    assert "gatekeeper_body_too_large_total 1" in salida
    assert 'gatekeeper_rate_backend_errors_total{fail_open="true"} 1' in salida


def test_la_exposicion_prometheus_tiene_el_formato_esperado(tmp_path: Path):
    """Cada linea de metrica tiene que ser `nombre{etiquetas} valor`."""
    sys.path.insert(0, str(ROOT / "tools"))
    import metrics  # noqa: PLC0415

    log = tmp_path / "trafico.log"
    with log.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"event": "rate_limited", "ip": "1.2.3.4", "method": "GET",
                             "path": "/x", "blocked": True}) + "\n")
    salida = metrics.a_prometheus(metrics.agregar(log.read_text(encoding="utf-8").splitlines()))

    for linea in salida.splitlines():
        if linea.startswith("#"):
            continue
        assert re.match(r"^gatekeeper_\w+(\{[^}]*\})? \d+$", linea), linea


def test_el_exportador_ignora_lineas_que_no_son_eventos(tmp_path: Path):
    """Un log de produccion tiene mas cosas que eventos de Gatekeeper."""
    sys.path.insert(0, str(ROOT / "tools"))
    import metrics  # noqa: PLC0415

    log = tmp_path / "trafico.log"
    with log.open("w", encoding="utf-8") as fh:
        fh.write("2026-10-24 10:00:00 INFO otra cosa\n")
        fh.write("no es json\n")
        fh.write(json.dumps({"event": "rate_limited", "ip": "1.2.3.4"}) + "\n")
        fh.write("{json roto\n")
    datos = metrics.agregar(log.read_text(encoding="utf-8").splitlines())
    assert datos["eventos_total"] == 1, datos
    assert datos["rate_limited"] == 1, datos


def test_la_herramienta_funciona_desde_la_linea_de_comandos(tmp_path: Path):
    """`python tools/metrics.py log` tiene que funcionar de verdad."""
    log = tmp_path / "trafico.log"
    with log.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"event": "attack_detected", "ip": "1.2.3.4", "method": "GET",
                             "path": "/x", "rule": "sqli", "source": "query",
                             "field": "q", "pattern": "p", "blocked": True}) + "\n")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "metrics.py"), str(log)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "gatekeeper_attacks_total" in proc.stdout
