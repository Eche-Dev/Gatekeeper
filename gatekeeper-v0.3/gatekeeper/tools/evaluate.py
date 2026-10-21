#!/usr/bin/env python3
"""Evalúa las reglas de Gatekeeper contra el corpus de ataques y tráfico benigno.

Mide los dos números que el README publica con honestidad:

- **tasa de detección**: qué porcentaje de los payloads de ataque bloquea;
- **tasa de falsos positivos**: qué porcentaje del tráfico legítimo bloquea.

Además puntúa el corpus EXTERNO de OWASP CRS (corpus/crs_payloads.json,
Apache-2.0, importado con tools/import_crs.py): un corpus escrito por gente
distinta, con sus propios negativos. Ahí los umbrales son una guarda de
regresión sobre la línea base medida, no una promesa de cobertura.

Uso:
    python tools/evaluate.py                 # resumen por consola
    python tools/evaluate.py --write-report  # genera corpus/REPORT.md
    python tools/evaluate.py --check         # sale con 1 si falla un umbral (para CI)
    python tools/evaluate.py --json          # salida legible por máquina

Los falsos positivos y falsos negativos *documentados* en el corpus (campos
`known_fp` y `documented_miss`) se cuentan aparte: son límites conocidos y
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

from gatekeeper.body import content_type_of, extract_strings, is_inspectable
from gatekeeper.rules import scan

CORPUS_DIR = ROOT / "corpus"
CRS_FILE = CORPUS_DIR / "crs_payloads.json"
DEFAULT_MIN_DETECTION = 0.90  # umbral de CI sobre la tasa de detección en crudo
DEFAULT_MAX_FP = 0.0  # umbral de CI sobre falsos positivos NO documentados
# Umbrales sobre el corpus externo de CRS: guardas de regresión sobre la línea
# base medida (185/982 = 18.8% de detección, 8/185 = 4.3% de FP), redondeada al
# entero por debajo (detección) y por encima (FP). Se recalculan al reimportar.
DEFAULT_MIN_CRS_DETECTION = 0.18
DEFAULT_MAX_CRS_FP = 0.05


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


@dataclass
class CrsReport:
    """Resultado sobre el corpus externo de OWASP CRS."""

    source: dict = field(default_factory=dict)
    attacks_total: int = 0  # en alcance (transportados por campos inspeccionados)
    attacks_detected: int = 0
    per_family: dict[str, tuple[int, int]] = field(default_factory=dict)
    misses: list[dict] = field(default_factory=list)
    benign_total: int = 0  # negativos de CRS en alcance
    benign_flagged: int = 0
    fps: list[dict] = field(default_factory=list)
    fp_by_rule: dict[str, int] = field(default_factory=dict)
    excluded: dict[str, int] = field(default_factory=dict)

    @property
    def detection_rate(self) -> float:
        return self.attacks_detected / self.attacks_total if self.attacks_total else 0.0

    @property
    def fp_rate(self) -> float:
        return self.benign_flagged / self.benign_total if self.benign_total else 0.0

    @property
    def missed(self) -> int:
        return self.attacks_total - self.attacks_detected


def _crs_carriers(item: dict) -> tuple[list[str], bool]:
    """Strings que el middleware inspeccionaría en esa petición CRS y si el body es inspeccionable.

    El middleware inspecciona ruta+query siempre; el body solo con content-type
    JSON/form (los tests de CRS sin content-type se asumen formularios).
    """
    uri = item.get("uri") or ""
    carriers = [uri] if uri else []
    data = item.get("data")
    raw = item.get("content_type")
    # sin content-type se asume formulario (el navegador lo hace por defecto);
    # con parámetros (`; charset=...`) se recorta igual que en el middleware
    content_type = content_type_of(raw) if raw else "application/x-www-form-urlencoded"
    inspectable = is_inspectable(content_type)
    if data and inspectable:
        carriers.extend(extract_strings(content_type, data.encode("utf-8", "replace")))
    return carriers, inspectable


def _crs_in_scope(item: dict, inspectable: bool) -> bool:
    """Fuera de alcance: payload en cabeceras o en body con content-type no inspeccionado.

    Son límites documentados de Gatekeeper (ver SECURITY.md), no fallos: se
    excluyen del denominador y se contabilizan en el informe.
    """
    if item.get("carrier") == "headers":
        return False
    if item.get("carrier") == "body" and not inspectable:
        return False
    return True


def evaluate_crs() -> CrsReport:
    """Puntúa corpus/crs_payloads.json (importado con tools/import_crs.py)."""
    data = json.loads(CRS_FILE.read_text(encoding="utf-8"))
    report = CrsReport(source=data.get("source", {}))
    per_family: dict[str, list[int]] = {}

    def _note_family(family: str, detected: bool) -> None:
        total, det = per_family.setdefault(family, [0, 0])
        per_family[family] = [total + 1, det + (1 if detected else 0)]

    for item in data["payloads"]:
        carriers, inspectable = _crs_carriers(item)
        fired = next((r for r in (scan(c) for c in carriers) if r), None)
        in_scope = _crs_in_scope(item, inspectable)
        family = item.get("family") or "?"
        if item["expect"] == "attack":
            if fired:
                report.attacks_total += 1
                report.attacks_detected += 1
                _note_family(family, True)
            elif in_scope:
                report.attacks_total += 1
                _note_family(family, False)
                if len(report.misses) < 12:
                    report.misses.append(item)
            else:
                reason = ("payload solo en cabeceras (no inspeccionadas)"
                          if item.get("carrier") == "headers"
                          else "payload en body con content-type no inspeccionado")
                report.excluded[reason] = report.excluded.get(reason, 0) + 1
        else:  # benign: negativos de CRS
            if not in_scope:
                reason = ("payload solo en cabeceras (no inspeccionadas)"
                          if item.get("carrier") == "headers"
                          else "payload en body con content-type no inspeccionado")
                report.excluded[reason] = report.excluded.get(reason, 0) + 1
                continue
            report.benign_total += 1
            if fired:
                report.benign_flagged += 1
                report.fp_by_rule[fired] = report.fp_by_rule.get(fired, 0) + 1
                report.fps.append({**item, "rule": fired})

    report.per_family = {k: (v[1], v[0]) for k, v in per_family.items()}
    return report


def _code(text: str) -> str:
    """Texto listo para una celda de tabla markdown."""
    return "`" + text.replace("|", "\\|").replace("`", "'") + "`"


def _crs_payload(item: dict) -> str:
    text = item.get("data") or item.get("uri") or ""
    return text[:90] + ("…" if len(text) > 90 else "")


def crs_section(
    c: CrsReport,
    min_detection: float = DEFAULT_MIN_CRS_DETECTION,
    max_fp: float = DEFAULT_MAX_CRS_FP,
) -> list[str]:
    """Sección markdown del corpus externo de OWASP CRS."""
    commit = (c.source.get("commit") or "sin commit")[:12]
    lines = [
        "",
        "## Corpus externo: OWASP Core Rule Set",
        "",
        f"> Fuente: [{c.source.get('project', 'OWASP CRS')}]({c.source.get('url')}), "
        f"commit `{commit}`, licencia {c.source.get('license')}. "
        "Extraído con `tools/import_crs.py`; alcance, exclusiones y límites en "
        "[README.md](README.md).",
        "",
        "| Familia (familias CRS 930/941/942) | Detectados / total |",
        "|---|---|",
    ]
    for family in sorted(c.per_family):
        detected, total = c.per_family[family]
        lines.append(f"| {family} | {detected} / {total} |")
    lines += [
        f"| **total en alcance** | **{c.attacks_detected} / {c.attacks_total} "
        f"({c.detection_rate:.1%})** |",
        "",
        "| Métrica externa | Valor |",
        "|---|---|",
        f"| Negativos de CRS en alcance | {c.benign_total} |",
        f"| Falsos positivos sobre esos negativos | {c.benign_flagged} ({c.fp_rate:.1%}) |",
    ]
    for reason in sorted(c.excluded):
        lines.append(f"| Excluidos: {reason} | {c.excluded[reason]} |")

    if c.fps:
        lines += ["", "### Falsos positivos sobre los negativos de CRS", "",
                  "| id | regla | payload |", "|---|---|---|"]
        for item in c.fps:
            lines.append(
                f"| {item['id']} | {item['rule']} | {_code(_crs_payload(item))} |"
            )

    if c.misses:
        lines += ["", f"### Muestra de falsos negativos ({len(c.misses)} de {c.missed})", "",
                  "| id | familia | payload |", "|---|---|---|"]
        for item in c.misses:
            lines.append(
                f"| {item['id']} | {item['family']} | {_code(_crs_payload(item))} |"
            )

    lines += [
        "",
        "### Umbrales del corpus externo (guarda de regresión sobre la línea base)",
        "",
        f"- detección CRS ≥ {min_detection:.0%}: "
        f"{'✅' if c.detection_rate >= min_detection else '❌'} ({c.detection_rate:.1%})",
        f"- FP CRS ≤ {max_fp:.1%}: "
        f"{'✅' if c.fp_rate <= max_fp else '❌'} ({c.fp_rate:.1%})",
        "",
    ]
    return lines


def to_markdown(
    r: Report,
    min_detection: float,
    max_fp: float,
    crs: CrsReport | None = None,
    min_crs_detection: float = DEFAULT_MIN_CRS_DETECTION,
    max_crs_fp: float = DEFAULT_MAX_CRS_FP,
) -> str:
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
              f"{'✅' if r.fp_rate <= max_fp else '❌'} ({r.fp_rate:.1%})"]
    if crs is not None:
        lines += crs_section(crs, min_crs_detection, max_crs_fp)
    lines += [""]
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
    parser.add_argument("--min-crs-detection", type=float, default=DEFAULT_MIN_CRS_DETECTION,
                        help="guarda de regresión sobre el corpus externo de CRS")
    parser.add_argument("--max-crs-fp", type=float, default=DEFAULT_MAX_CRS_FP,
                        help="FP máximos sobre los negativos de CRS")
    args = parser.parse_args(argv)

    report = evaluate()
    crs = evaluate_crs() if CRS_FILE.exists() else None

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
        if crs is not None:
            payload["crs"] = {
                "source": crs.source,
                "attacks_total": crs.attacks_total,
                "attacks_detected": crs.attacks_detected,
                "detection_rate": round(crs.detection_rate, 4),
                "per_family": {k: list(v) for k, v in crs.per_family.items()},
                "benign_total": crs.benign_total,
                "benign_flagged": crs.benign_flagged,
                "fp_rate": round(crs.fp_rate, 4),
                "excluded": crs.excluded,
            }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(to_markdown(report, args.min_detection, args.max_fp, crs,
                          args.min_crs_detection, args.max_crs_fp))

    if args.write_report:
        (CORPUS_DIR / "REPORT.md").write_text(
            to_markdown(report, args.min_detection, args.max_fp, crs,
                        args.min_crs_detection, args.max_crs_fp),
            encoding="utf-8",
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
        if crs is not None:
            if crs.detection_rate < args.min_crs_detection:
                print(f"❌ detección CRS {crs.detection_rate:.1%} < "
                      f"{args.min_crs_detection:.0%} (regresión sobre la línea base)",
                      file=sys.stderr)
                return 1
            if crs.fp_rate > args.max_crs_fp:
                print(f"❌ FP sobre CRS {crs.fp_rate:.1%} > {args.max_crs_fp:.1%}",
                      file=sys.stderr)
                return 1
        print("✅ umbrales de detección cumplidos", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
