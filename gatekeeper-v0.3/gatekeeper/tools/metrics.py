#!/usr/bin/env python3
"""Convierte un log de auditoria de Gatekeeper en metricas Prometheus.

Gatekeeper emite eventos JSON en el logger `gatekeeper`. Este script los
agrega y escribe la exposicion en formato Prometheus, para que se pueda
rascar sin pegar nada a mano.

El catalogo de eventos esta en `corpus/events.json`: ahi se ve que campo lleva
cada evento y que contador corresponde a cada uno.

Uso:
    gatekeeper report trafico.log --json > informe.json
    python tools/metrics.py trafico.log                 # texto Prometheus
    python tools/metrics.py trafico.log --json          # salida JSON
    python tools/metrics.py trafico.log --port 9090     # exposicion HTTP

Qué se agrega:
- `gatekeeper_attacks_total{rule,source}`: ataques por familia y por
  transportador.
- `gatekeeper_rate_limited_total`: peticiones que superaron el limite.
- `gatekeeper_blocked_ips_total`: IPs bloqueadas.
- `gatekeeper_body_too_large_total`: bodies mayores que `max_body_size`.
- `gatekeeper_rate_backend_errors_total{fail_open}`: fallos del backend.

Qué NO se expone: IPs, rutas, payloads ni patrones. Las metricas son
conteos; los datos personales se quedan en el log, que es donde deben estar.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG_FILE = ROOT / "corpus" / "events.json"

# Contadores, en el orden en que se exponen.
CONTADORES = [
    ("gatekeeper_attacks_total", "Ataques detectados por familia y transportador."),
    ("gatekeeper_rate_limited_total", "Peticiones que superaron el limite de rate limit."),
    ("gatekeeper_blocked_ips_total", "Peticiones rechazadas por IP bloqueada."),
    ("gatekeeper_body_too_large_total", "Peticiones rechazadas por body demasiado grande."),
    ("gatekeeper_rate_backend_errors_total", "Fallos del backend de rate limit."),
]


def _iter_eventos(lineas: list[str]):
    """Eventos JSON de las lineas que los contienen."""
    for linea in lineas:
        linea = linea.strip()
        if not linea.startswith("{"):
            continue
        try:
            dato = json.loads(linea)
        except json.JSONDecodeError:
            continue
        if isinstance(dato, dict) and "event" in dato:
            yield dato


def agregar(lineas: list[str]) -> dict:
    """Agrega los eventos del log en contadores."""
    ataques: Counter[tuple[str, str]] = Counter()
    rate_limited = 0
    blocked_ips = 0
    body_too_large = 0
    backend_errors: Counter[str] = Counter()
    eventos_total = 0

    for evento in _iter_eventos(lineas):
        eventos_total += 1
        tipo = evento.get("event")
        if tipo == "attack_detected":
            ataques[(str(evento.get("rule", "?")), str(evento.get("source", "?")))] += 1
        elif tipo == "rate_limited":
            rate_limited += 1
        elif tipo == "blocked_ip":
            blocked_ips += 1
        elif tipo == "body_too_large":
            body_too_large += 1
        elif tipo == "rate_backend_error":
            backend_errors["true" if evento.get("fail_open") else "false"] += 1

    return {
        "eventos_total": eventos_total,
        "attacks": [{"rule": r, "source": s, "count": c} for (r, s), c in sorted(ataques.items())],
        "rate_limited": rate_limited,
        "blocked_ips": blocked_ips,
        "body_too_large": body_too_large,
        "rate_backend_errors": dict(sorted(backend_errors.items())),
    }


def a_prometheus(datos: dict) -> str:
    """Muestra en formato de exposicion de Prometheus."""
    lineas: list[str] = []
    for nombre, ayuda in CONTADORES:
        lineas.append(f"# HELP {nombre} {ayuda}")
        lineas.append(f"# TYPE {nombre} counter")

    for item in datos["attacks"]:
        rule = item["rule"].replace('"', "")
        source = item["source"].replace('"', "")
        lineas.append(
            f'gatekeeper_attacks_total{{rule="{rule}",source="{source}"}} {item["count"]}'
        )
    if not datos["attacks"]:
        lineas.append("gatekeeper_attacks_total 0")

    lineas.append(f"gatekeeper_rate_limited_total {datos['rate_limited']}")
    lineas.append(f"gatekeeper_blocked_ips_total {datos['blocked_ips']}")
    lineas.append(f"gatekeeper_body_too_large_total {datos['body_too_large']}")
    if datos["rate_backend_errors"]:
        for fail_open, count in datos["rate_backend_errors"].items():
            lineas.append(
                f'gatekeeper_rate_backend_errors_total{{fail_open="{fail_open}"}} {count}'
            )
    else:
        lineas.append("gatekeeper_rate_backend_errors_total 0")

    return "\n".join(lineas) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", type=Path, help="fichero de log de Gatekeeper")
    parser.add_argument("--json", action="store_true", help="salida JSON")
    parser.add_argument("--port", type=int, help="sirve la exposicion por HTTP")
    args = parser.parse_args(argv)

    if not args.log.exists():
        print(f"No existe: {args.log}", file=sys.stderr)
        return 1

    with args.log.open(encoding="utf-8", errors="replace") as fh:
        lineas = fh.readlines()

    datos = agregar(lineas)

    if args.port:
        from http.server import BaseHTTPRequestHandler, HTTPServer

        cuerpo = a_prometheus(datos).encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 (nombre de la clase base)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)

            def log_message(self, *args):  # silencia el log de acceso
                pass

        print(f"Serviendo metricas en http://127.0.0.1:{args.port}/metrics",
              file=sys.stderr)
        HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
        return 0

    if args.json:
        print(json.dumps(datos, ensure_ascii=False, indent=2))
    else:
        print(a_prometheus(datos), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
