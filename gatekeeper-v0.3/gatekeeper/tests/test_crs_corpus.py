"""Contrato sobre el corpus externo de OWASP CRS (Apache-2.0).

El corpus de CRS (`corpus/crs_payloads.json`) lo escribió otra gente para otro
WAF: sirve para que Gatekeeper no se autoevalúe solo con su propio examen.

Aquí se bloquea cualquier cosa que empeore frente a la línea base medida
(`tools/import_crs.py` con el commit que figura en el JSON): regresión de
detección, aumento de falsos positivos o exclusiones que se disparen.

Regenera con:  python tools/import_crs.py --crs-dir <checkout>
"""

import importlib.util
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_EVAL = _ROOT / "tools" / "evaluate.py"
_spec = importlib.util.spec_from_file_location("gk_evaluate_crs", _EVAL)
evaluate_mod = importlib.util.module_from_spec(_spec)
sys.modules["gk_evaluate_crs"] = evaluate_mod  # dataclasses lo exige
_spec.loader.exec_module(evaluate_mod)

CORPUS = _ROOT / "corpus"
CRS_JSON = CORPUS / "crs_payloads.json"


def _source() -> dict:
    return json.loads(CRS_JSON.read_text(encoding="utf-8"))["source"]


def test_source_records_provenance_and_license():
    source = _source()
    assert source["license"] == "Apache-2.0"
    assert (CORPUS / "LICENSE-APACHE-2.0.txt").is_file(), "falta la licencia de CRS"
    assert source["url"] == "https://github.com/coreruleset/coreruleset"
    assert source["commit"] and len(source["commit"]) == 40, "falta el commit de procedencia"
    assert source["imported_by"] == "tools/import_crs.py"
    assert source["retrieved"], "falta la fecha de importación"


def test_entries_are_well_formed_and_unique():
    payloads = json.loads(CRS_JSON.read_text(encoding="utf-8"))["payloads"]
    assert len(payloads) >= 1000, "corpus externo demasiado pequeño"
    ids = [p["id"] for p in payloads]
    assert len(ids) == len(set(ids)), "ids duplicados en el corpus de CRS"
    for item in payloads:
        assert item["expect"] in ("attack", "benign")
        assert item["carrier"] in ("body", "query", "path", "headers")
        assert item["family"] in ("sqli", "xss", "path_traversal")
        assert item["uri"] or item["data"], f"{item['id']} sin transportador"


def test_detection_does_not_regress_against_crs():
    report = evaluate_mod.evaluate_crs()
    assert report.attacks_total > 500, "denominador de CRS demasiado pequeño"
    assert report.detection_rate >= evaluate_mod.DEFAULT_MIN_CRS_DETECTION, (
        f"detección sobre CRS {report.detection_rate:.1%} por debajo de la línea base "
        f"{evaluate_mod.DEFAULT_MIN_CRS_DETECTION:.0%}"
    )


def test_crs_false_positives_within_baseline():
    report = evaluate_mod.evaluate_crs()
    assert report.benign_total > 100
    assert report.fp_rate <= evaluate_mod.DEFAULT_MAX_CRS_FP, (
        f"FP sobre CRS {report.fp_rate:.1%} por encima de la línea base "
        f"{evaluate_mod.DEFAULT_MAX_CRS_FP:.1%}"
    )


def test_family_breakdown_sums_to_the_total():
    report = evaluate_mod.evaluate_crs()
    assert sum(total for _, total in report.per_family.values()) == report.attacks_total
    for detected, total in report.per_family.values():
        assert 0 <= detected <= total


def test_exclusions_are_declared_and_bounded():
    # Las exclusiones (cabeceras y content-types no inspeccionados) son límites
    # documentados, no un agujero: nunca pueden esconder más de 1/4 del corpus.
    payloads = json.loads(CRS_JSON.read_text(encoding="utf-8"))["payloads"]
    report = evaluate_mod.evaluate_crs()
    excluded = sum(report.excluded.values())
    assert excluded < len(payloads) * 0.25, "demasiados tests excluidos del denominador"
    assert excluded > 0, "las exclusiones esperadas (cabeceras/xml) han desaparecido"
    for reason in report.excluded:
        assert "cabeceras" in reason or "content-type" in reason, reason


def test_report_renders_the_external_section():
    text = evaluate_mod.to_markdown(
        evaluate_mod.evaluate(),
        evaluate_mod.DEFAULT_MIN_DETECTION,
        evaluate_mod.DEFAULT_MAX_FP,
        evaluate_mod.evaluate_crs(),
    )
    assert "OWASP Core Rule Set" in text
    assert "guarda de regresión" in text
    assert "Excluidos" in text
