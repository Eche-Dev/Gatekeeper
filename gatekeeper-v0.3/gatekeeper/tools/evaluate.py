#!/usr/bin/env python3
"""Evalúa las reglas de Gatekeeper contra el corpus de ataques y tráfico benigno.

Mide los dos números que el README publica con honestidad:

- **tasa de detección**: qué porcentaje de los payloads de ataque bloquea;
- **tasa de falsos positivos**: qué porcentaje del tráfico legítimo bloquea.

Uso:
    python tools/evaluate.py                 # resumen por consola
    python tools/evaluate.py --write-report  # genera corpus/REPORT.md
    python tools/evaluate.py --check         # sale con 1 si falla un umbral (para CI)
    python tools/evaluate.py --json          # salida legible por máquina

Los falsos positivos y falsos negativos *documentados* en el corpus (campos
`known_fp` y `documented_miss`) se cont aparte: son límites conocidos y
aceptados, no sorpresas. El umbral de CI se aplica a los no documentados.
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
DEFAULT_MIN_DETECTION = 0.90  # umbral de CI sobre la tasa de detección en crudo
DEFAULT_MAX_FP = 0.0  # umbral de CI sobre falsos positivos NO documentados


@dataclass
class Report:
    attacks_total: int = 0
    attacks_detected: int = 0
    attacks_expected_rule: int = 0
    attacks_missed: list[dict] = field(default_factory=list)
    attacks_documented_miss: int = 0
    per_rule: dict[str, tuple[int, int]] = field(default_factory=dict)
    benign_total: int = 0
    benign_flagged: int = 0
    benign_documented_fp: int = 0
    fp_by_rule: dict[str, int] = field(default_factory=dict)
    fps: list[dict] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        return self.attacks_detected / self.attacks_total if self.attacks_total else 0.0

    @property
    def fp_rate(self) -> float:
        """Falsos positivos que NO estaban documentados."""
        undocumented = self.benign_flagged - self.benign_documented_fp
        return undocumented / self.benign_total if self.benign_total else 0.0


def load(name: str) -> list[dict]:
    data = json.loads((CORPUS_DIR / name).read_text(encoding="utf-8"))
    return data["payloads"]


def evaluate() -> Report:
    report = Report()
    per_rule: dict[str, list[int]] = {}

    for item in load("attacks.json"):
        payload, expected = item["payload"], item["rule"]
        rule = scan(payload)
        documented = bool(item.get("documented_miss"))
        report.attacks_total += 1
        if rule:
            report.attacks_detected += 1
            if rule == expected:
                report.attacks_expected_rule += 1
        elif not documented:
            report.attacks_missed.append(item)
        if documented and not rule:
            report.attacks_documented_miss += 1
        total, detected = per_rule.setdefault(expected, [0, 0])
        per_rule[expected] = [total + 1, detected + (1 if rule else 0)]

    report.per_rule = {k: (v[1], v[0]) for k, v in per_rule.items()}

    for item in load("benign.json"):
        payload = item["payload"]
        rule = scan(payload)
        documented = bool(item.get("known_fp"))
        report.benign_total += 1
        if rule:
            report.benign_flagged += 1
            report.fp_by_rule[rule] = report.fp_by_rule.get(rule, 0) + 1
            report.fps.append({**item, "rule": rule})
            if documented:
                report.benign_documented_fp += 1

    return report


def _code(text: str) -> str:
    """Texto listo para una celda de tabla markdown."""
    return "`" + text.replace("|", "\\|").replace("`", "'") + "`"


def to_markdown(r: Report, min_detection: float, max_fp: float) -> str:
    undocumented_fp = r.benign_flagged - r.benign_documented_fp
    lines = [
        "# Informe de detección",
        "",
        "> Generado con `python tools/evaluate.py --write-report`. No lo edites a mano.",
        "",
        "| Métrica | Valor |",
        "|---|---|",
        f"| Payloads de ataque | {r.attacks_total} |",
        f"| Detectados | {r.attacks_detected} ({r.detection_rate:.1%}) |",
        f"| Detectados por la regla esperada | {r.attacks_expected_rule} "
        f"({r.attacks_expected_rule / r.attacks_total:.1%}) |",
        f"| Falsos negativos no documentados | {len(r.attacks_missed)} |",
        f"| Falsos negativos documentados | {r.attacks_documented_miss} |",
        f"| Requests benignos | {r.benign_total} |",
        f"| Falsos positivos no documentados | {undocumented_fp} ({r.fp_rate:.1%}) |",
        f"| Falsos positivos documentados | {r.benign_documented_fp} |",
        "",
        "## Detección por regla",
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
            lines.append(f"| {item['id']} | {item['rule']} | {_code(item['payload'])} |")

    documented = [i for i in load("attacks.json") if i.get("documented_miss")]
    if documented:
        lines += ["", "## Falsos negativos documentados (límites conocidos)", "",
                  "| id | por qué se escapa | payload |", "|---|---|---|"]
        for item in documented:
            lines.append(f"| {item['id']} | {item['note']} | {_code(item['payload'])} |")

    if r.fps:
        lines += ["", "## Falsos positivos", "",
                  "| id | regla | motivo | payload |", "|---|---|---|---|"]
        for item in r.fps:
            reason = item.get("known_fp") or "no documentado"
            lines.append(
                f"| {item['id']} | {item['rule']} | {reason} | {_code(item['payload'])} |"
            )

    lines += ["", "## Umbrales de CI", "",
              f"- detección ≥ {min_detection:.0%}: "
              f"{'✅' if r.detection_rate >= min_detection else '❌'} ({r.detection_rate:.1%})",
              f"- falsos positivos no documentados ≤ {max_fp:.0%}: "
              f"{'✅' if r.fp_rate <= max_fp else '❌'} ({r.fp_rate:.1%})", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    # Consolas de Windows en cp1252 no saben imprimir ≥/✓ ni payloads UTF-8.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write-report", action="store_true",
                        help="escribe corpus/REPORT.md")
    parser.add_argument("--check", action="store_true",
                        help="sale con 1 si no se cumplen los umbrales")
    parser.add_argument("--json", action="store_true", help="salida JSON")
    parser.add_argument("--min-detection", type=float, default=DEFAULT_MIN_DETECTION)
    parser.add_argument("--max-fp", type=float, default=DEFAULT_MAX_FP)
    args = parser.parse_args(argv)

    report = evaluate()

    if args.json:
        payload = {
            "attacks_total": report.attacks_total,
            "attacks_detected": report.attacks_detected,
            "detection_rate": round(report.detection_rate, 4),
            "attacks_missed": [i["id"] for i in report.attacks_missed],
            "benign_total": report.benign_total,
            "benign_flagged": report.benign_flagged,
            "benign_documented_fp": report.benign_documented_fp,
            "fp_rate": round(report.fp_rate, 4),
            "per_rule": {k: list(v) for k, v in report.per_rule.items()},
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(to_markdown(report, args.min_detection, args.max_fp))

    if args.write_report:
        (CORPUS_DIR / "REPORT.md").write_text(
            to_markdown(report, args.min_detection, args.max_fp), encoding="utf-8"
        )
        print(f"informe escrito en {CORPUS_DIR / 'REPORT.md'}", file=sys.stderr)

    if args.check:
        undocumented_fp = report.benign_flagged - report.benign_documented_fp
        if report.detection_rate < args.min_detection:
            print(f"❌ detección {report.detection_rate:.1%} < {args.min_detection:.0%}",
                  file=sys.stderr)
            return 1
        if undocumented_fp:
            print(f"❌ {undocumented_fp} falsos positivos no documentados", file=sys.stderr)
            return 1
        if report.fp_rate > args.max_fp:
            print(f"❌ FP {report.fp_rate:.1%} > {args.max_fp:.0%}", file=sys.stderr)
            return 1
        print("✅ umbrales de detección cumplidos", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
