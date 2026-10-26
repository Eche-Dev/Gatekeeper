"""`gatekeeper report`: mide el tráfico real y propone ajustes.

La idea: en producción no sabes qué falsos positives te va a dar tu app hasta
que la pones delante con `monitor_only=True`. Este comando lee ese tráfico y
responde las tres preguntas que te importan:

1. **¿Qué se bloquea?** — ranking de reglas, rutas y campos culpable.
2. **¿Es ruido?** — agrupa por (regla, campo) para ver si son ataques reales o
   el mismo falso positivo repetido.
3. **¿Qué ajusto?** — propone `exclude_fields` y `disabled_rules` a partir de
   los campos que más falsos positivos acumulan, listo para copiar a tu config.

Formatos de entrada:

- **JSON de Gatekeeper** (una línea por evento, el que emite el logger):
  `{"event": "attack_detected", "rule": "sqli", "source": "query",
    "field": "q", "path": "/search", ...}`
- **Acceso genérico**: una request por línea (`GET /search?q=... 200`), útil
  cuando el log del middleware no está y solo tienes el del servidor web.

Sin payloads: los eventos de Gatekeeper ya no incluyen el contenido, y aquí no
se reconstruye nada que no venga ya en el log.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

from .rules import scan_detailed
from .sanitize import sanear_y_acotar

# Eventos que son "el middleware bloqueó/registró algo sobre una petición".
_ATTACK_EVENTS = {"attack_detected"}


def _iter_events(lines: Iterable[str]) -> Iterable[dict[str, object]]:
    """Normaliza cada línea a un evento con `rule`/`path`/`field`, o None si no
    es un evento de ataque reconocible."""
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("event") in _ATTACK_EVENTS:
                yield event
            continue
        # Formato acceso genérico: "GET /ruta?query 200" (o solo la ruta).
        partes = line.split()
        objetivo = partes[1] if len(partes) > 1 else partes[0]
        metodo = partes[0].upper() if partes else "?"
        if not objetivo.startswith("/"):
            continue
        ruta, _, query = objetivo.partition("?")
        hit = scan_detailed(objetivo)
        if hit:
            yield {
                "event": "attack_detected",
                "rule": hit[0],
                "source": "log",
                "method": metodo,
                "path": ruta,
                "field": _field_de_query(query),
            }


def _field_de_query(query: str) -> str | None:
    """Primer parámetro de la query cuyo nombre empieza por una letra (heurística)."""
    for par in query.split("&"):
        nombre = par.split("=", 1)[0]
        if nombre and nombre[0].isalpha():
            return nombre
    return None


def _fmt_tabla(titulo: str, counter: Counter[str], limite: int) -> list[str]:
    lineas = [f"\n{titulo}"]
    if not counter:
        return lineas + ["  (ninguno)"]
    for nombre, cuenta in counter.most_common(limite):
        lineas.append(f"  {cuenta:>6}  {nombre}")
    if len(counter) > limite:
        lineas.append(f"  … y {len(counter) - limite} más")
    return lineas


def _sanea_eventos(eventos: list[dict[str, object]]) -> list[dict[str, object]]:
    """Sanea los valores de texto antes de imprimirlos.

    Lo que hay aqui lo eligio el atacante: el nombre de un campo, la ruta, la
    propia regla. Sin sanear, un `\x1b[2J` en la URL puede borrar la pantalla
    del operador o reescribir el titulo de su ventana.

    En el formato JSON de Gatekeeper, `json.loads` ya devuelve el ESC como un
    caracter real (el `\u001b` del archivo lo decodifica), asi que sanear en
    este punto es lo unico que hay.
    """
    limpios: list[dict[str, object]] = []
    for evento in eventos:
        limpio: dict[str, object] = {}
        for clave, valor in evento.items():
            limpio[clave] = sanear_y_acotar(valor) if isinstance(valor, str) else valor
        limpios.append(limpio)
    return limpios


def construir_informe(ruta_log: Path, limite: int = 15) -> str:
    with open(ruta_log, encoding="utf-8", errors="replace") as fh:
        eventos = _sanea_eventos(list(_iter_events(fh)))

    reglas = Counter(str(e.get("rule", "?")) for e in eventos)
    rutas = Counter(str(e.get("path", "?")) for e in eventos)
    campos = Counter(str(e.get("field")) for e in eventos if e.get("field"))
    reglas_campo = Counter(
        f"{e.get('rule')} en {e.get('field')}" for e in eventos if e.get("field")
    )

    out: list[str] = [
        f"# Informe de tráfico — {ruta_log.name}",
        f"{len(eventos)} peticiones bloqueadas o registradas en modo monitor.",
        "",
    ]
    out += _fmt_tabla("Reglas que saltaron", reglas, limite)
    out += _fmt_tabla("Rutas afectadas", rutas, limite)
    out += _fmt_tabla("Campos (JSON pointer o parámetro)", campos, limite)
    out += _fmt_tabla("Combinaciones regla + campo (las que repitiendo son ruido)", reglas_campo, limite)

    out += ["\n## Ajuste sugerido"]
    if not reglas_campo:
        out.append("No hay falsos positivos que ajustar (o el log no lleva campo).")
        return "\n".join(out)

    top = reglas_campo.most_common(1)[0]
    # "sqli en q" -> familia = antes del separador, campo = después. No se
    # parte por caracteres: el nombre de la familia puede ser largo.
    top_regla, _, top_campo = top[0].partition(" en ")
    out.append(
        f"El par más repetido es **{top[0]}** ({top[1]} veces). Si es tráfico "
        f"legítimo, lo más limpio es excluir ese campo:\n"
    )
    out.append("```yaml")
    out.append("exclude_fields:")
    out.append(f"  - {top_campo}")
    out.append("```")
    out.append(
        "\nSi además el campo es solo tuyo (p. ej. una URL de webhook), "
        "desactiva la familia entera:\n"
    )
    out.append("```yaml")
    out.append(f"disabled_rules: [{top_regla}]")
    out.append("```")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gatekeeper", description="Utilidades de Gatekeeper."
    )
    sub = parser.add_subparsers(dest="comando", required=True)
    report = sub.add_parser(
        "report", help="Analiza un log de tráfico y sugiere ajustes."
    )
    report.add_argument("log", type=Path, help="Fichero de log (JSON de Gatekeeper o acceso).")
    report.add_argument("--top", type=int, default=15, help="Cuántas filas por tabla (15).")
    report.add_argument("--json", action="store_true", help="Salida en JSON legible por máquina.")

    args = parser.parse_args(argv)
    if args.comando == "report":
        if not args.log.exists():
            print(f"no existe el log: {args.log}", file=sys.stderr)
            return 2
        if args.json:
            with open(args.log, encoding="utf-8", errors="replace") as fh:
                eventos = _sanea_eventos(list(_iter_events(fh)))
            reglas = Counter(str(e.get("rule", "?")) for e in eventos)
            campos = Counter(str(e.get("field")) for e in eventos if e.get("field"))
            print(json.dumps(
                {"total": len(eventos), "rules": dict(reglas), "fields": dict(campos)},
                indent=2,
                ensure_ascii=False,
            ))
            return 0
        print(construir_informe(args.log, args.top))
        return 0
    parser.error("comando desconocido")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
