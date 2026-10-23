#!/usr/bin/env python3
"""Evalúa Gatekeeper contra el corpus RETENIDO (corpus/heldout_*.json).

Por qué existe un corpus retenido:
el corpus de desarrollo (attacks.json/benign.json) se puede usar para AJUSTAR
las reglas. Cada vez que se añade una firma, se comprueba que detecta el caso
que motivó la firma. Eso hace que el 100% del corpus de desarrollo mida poco:
mide memoria, no generalización.

El corpus retenido se escribe UNA vez, sin mirar las firmas de las reglas, y se
usa para MEDIR. Por eso el evaluador corre en modo individual: es la misma
configuración por defecto que el resto de la documentación.

Uso:
    python tools/evaluate_heldout.py               # resumen por consola
    python tools/evaluate_heldout.py --json        # salida legible por máquina
    python tools/evaluate_heldout.py --check       # sale con 1 si falla un umbral
    python tools/evaluate_heldout.py --write-report # genera corpus/HELDOUT_REPORT.md

Los falsos positivos y falsos negativos *documentados* (campos `known_fp` y
`documented_miss`) se cuentan aparte: son límites conocidos y aceptados, no
sorpresas. Los umbrales de CI se aplican a los NO documentados.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gatekeeper.rules import scan  # noqa: E402

CORPUS_DIR = ROOT / "corpus"
ATTACKS_FILE = CORPUS_DIR / "heldout_attacks.json"
BENIGN_FILE = CORPUS_DIR / "heldout_benign.json"
REPORT_FILE = CORPUS_DIR / "HELDOUT_REPORT.md"

# Umbrales del corpus retenido. Son guardas de regresión, no promesas:
# si una regla nueva hace bajar la deteccion o sube los FP, CI se pone rojo.
#
# El umbral de deteccion (85%) esta por debajo del 100% del corpus de
# desarrollo A PROPOSITO: el retenido es mas dificil a proposito, porque
# incluye tecnicas que las reglas no cubren. Si se pusiera al 100%, cualquier
# payload nuevo que alguien anada al retenido haria fallar CI sin que las
# reglas hayan empeorado.
DEFAULT_MIN_DETECTION = 0.85
# Cero falsos positivos NO documentados: es el mismo criterio que el corpus
# propio. Un FP nuevo en trafico legitimo retenido es un bug.
DEFAULT_MAX_FP = 0.0


@dataclass
class Report:
    attacks_total: int = 0
    attacks_detected: int = 0
    attacks_missed: list[dict] = field(default_factory=list)
    attacks_documented_miss: int = 0
    per_rule: dict[str, tuple[int, int]] = field(default_factory=dict)
    benign_total: int = 0
    benign_flagged: int = 0
    benign_documented_fp: int = 0
    fps: list[dict] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        return self.attacks_detected / self.attacks_total if self.attacks_total else 0.0

    @property
    def fp_rate(self) -> float:
        """Falsos positivos que NO estaban documentados."""
        undocumented = self.benign_flagged - self.benign_documented_fp
        return undocumented / self.benign_total if self.benign_total else 0.0


def evaluate() -> Report:
    report = Report()
    per_rule: dict[str, list[int]] = {}

    attacks = json.loads(ATTACKS_FILE.read_text(encoding="utf-8"))["payloads"]
    for item in attacks:
        payload, expected = item["payload"], item["rule"]
        rule = scan(payload)
        documented = bool(item.get("documented_miss"))
        report.attacks_total += 1
        if rule:
            report.attacks_detected += 1
        elif not documented:
            report.attacks_missed.append(item)
        if documented and not rule:
            report.attacks_documented_miss += 1
        total, detected = per_rule.setdefault(expected, [0, 0])
        per_rule[expected] = [total + 1, detected + (1 if rule else 0)]

    report.per_rule = {k: (v[1], v[0]) for k, v in per_rule.items()}

    benign = json.loads(BENIGN_FILE.read_text(encoding="utf-8"))["payloads"]
    for item in benign:
        rule = scan(item["payload"])
        documented = bool(item.get("known_fp"))
        report.benign_total += 1
        if rule:
            report.benign_flagged += 1
            report.fps.append({**item, "rule": rule})
            if documented:
                report.benign_documented_fp += 1

    return report


def _code(text: str) -> str:
    return "`" + text.replace("|", "\\|").replace("`", "'") + "`"


def to_markdown(r: Report, min_detection: float, max_fp: float) -> str:
    undocumented_fp = r.benign_flagged - r.benign_documented_fp
    lines = [
        "# Informe del corpus retenido",
        "",
        "> Generado con `python tools/evaluate_heldout.py --write-report`.",
        "> No lo edites a mano.",
        "",
        "Este corpus se usa para **medir**, no para ajustar: se escribio una vez,",
        "sin mirar las firmas de las reglas, y a partir de ahi no se ha tocado para",
        "hacer que las reglas passen. Por eso su cifra es mas baja que la del",
        "corpus de desarrollo, y esa diferencia es informacion, no un defecto.",
        "",
        "| Metrica | Valor |",
        "|---|---|",
        f"| Payloads de ataque | {r.attacks_total} |",
        f"| Detectados | {r.attacks_detected} ({r.detection_rate:.1%}) |",
        f"| Falsos negativos no documentados | {len(r.attacks_missed)} |",
        f"| Falsos negativos documentados (limites conocidos) | {r.attacks_documented_miss} |",
        f"| Requests benignos | {r.benign_total} |",
        f"| Falsos positivos no documentados | {undocumented_fp} ({r.fp_rate:.1%}) |",
        f"| Falsos positivos documentados | {r.benign_documented_fp} |",
        "",
        "## Deteccion por regla",
        "",
        "| Regla | Detectados / total |",
        "|---|---|",
    ]
    for name in sorted(r.per_rule):
        detected, total = r.per_rule[name]
        lines.append(f"| {name} | {detected} / {total} |")

    if r.attacks_missed:
        lines += ["", "## Falsos negativos no documentados", "",
                  "| id | regla esperada | payload |", "|---|---|---|"]
        for item in r.attacks_missed:
            lines.append(
                f"| {item['id']} | {item['rule']} | {_code(item['payload'])} |"
            )

    documented = [
        i for i in json.loads(ATTACKS_FILE.read_text(encoding="utf-8"))["payloads"]
        if i.get("documented_miss")
    ]
    if documented:
        lines += ["", "## Falsos negativos documentados (limites conocidos)", "",
                  "| id | por que se escapa | payload |", "|---|---|---|"]
        for item in documented:
            lines.append(
                f"| {item['id']} | {item['note']} | {_code(item['payload'])} |"
            )

    if r.fps:
        lines += ["", "## Falsos positivos", "",
                  "| id | regla | motivo | payload |", "|---|---|---|---|"]
        for item in r.fps:
            reason = item.get("known_fp") or "**no documentado**"
            lines.append(
                f"| {item['id']} | {item['rule']} | {reason} | {_code(item['payload'])} |"
            )

    lines += ["", "## Umbrales de CI", "",
              f"- deteccion >= {min_detection:.0%}: "
              f"{'OK' if r.detection_rate >= min_detection else 'FALLO'} ({r.detection_rate:.1%})",
              f"- falsos positivos no documentados <= {max_fp:.0%}: "
              f"{'OK' if r.fp_rate <= max_fp else 'FALLO'} ({r.fp_rate:.1%})",
              ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--min-detection", type=float, default=DEFAULT_MIN_DETECTION)
    parser.add_argument("--max-fp", type=float, default=DEFAULT_MAX_FP)
    args = parser.parse_args(argv)

    report = evaluate()
    undocumented_fp = report.benign_flagged - report.benign_documented_fp

    if args.json:
        print(json.dumps({
            "attacks_total": report.attacks_total,
            "attacks_detected": report.attacks_detected,
            "detection_rate": round(report.detection_rate, 4),
            "attacks_missed": [i["id"] for i in report.attacks_missed],
            "attacks_documented_miss": report.attacks_documented_miss,
            "benign_total": report.benign_total,
            "benign_flagged": report.benign_flagged,
            "benign_documented_fp": report.benign_documented_fp,
            "fp_rate": round(report.fp_rate, 4),
            "per_rule": {k: list(v) for k, v in report.per_rule.items()},
        }, ensure_ascii=False, indent=2))
    else:
        print(to_markdown(report, args.min_detection, args.max_fp))

    if args.write_report:
        REPORT_FILE.write_text(
            to_markdown(report, args.min_detection, args.max_fp), encoding="utf-8"
        )
        print(f"informe escrito en {REPORT_FILE}", file=sys.stderr)

    if args.check:
        if report.detection_rate < args.min_detection:
            print(f"FALLO: deteccion {report.detection_rate:.1%} < {args.min_detection:.0%}",
                  file=sys.stderr)
            return 1
        if undocumented_fp:
            print(f"FALLO: {undocumented_fp} falsos positivos no documentados",
                  file=sys.stderr)
            return 1
        if report.fp_rate > args.max_fp:
            print(f"FALLO: FP {report.fp_rate:.1%} > {args.max_fp:.0%}", file=sys.stderr)
            return 1
        print("OK: umbrales del corpus retenido cumplidos", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
