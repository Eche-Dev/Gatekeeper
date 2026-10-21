"""Contrato de detección: las tasas medidas contra el corpus no pueden empeorar.

Si alguien toca una regla y eso rompe detección o mete falsos positivos, falla
CI aquí (y `tools/evaluate.py --check` lo mismo en el workflow).
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from gatekeeper.rules import RULES

_EVAL = Path(__file__).resolve().parents[1] / "tools" / "evaluate.py"
_spec = importlib.util.spec_from_file_location("gk_evaluate", _EVAL)
evaluate_mod = importlib.util.module_from_spec(_spec)
sys.modules["gk_evaluate"] = evaluate_mod  # dataclasses lo exige al resolver anotaciones
_spec.loader.exec_module(evaluate_mod)

CORPUS = Path(__file__).resolve().parents[1] / "corpus"


def test_detection_rate_meets_the_gate():
    report = evaluate_mod.evaluate()
    assert report.detection_rate >= evaluate_mod.DEFAULT_MIN_DETECTION
    assert report.attacks_missed == []  # ningún falso negativo sin documentar


def test_no_undocumented_false_positives():
    report = evaluate_mod.evaluate()
    undocumented = report.benign_flagged - report.benign_documented_fp
    assert undocumented == 0, f"falsos positivos sin documentar: {undocumented}"
    assert report.fp_rate <= evaluate_mod.DEFAULT_MAX_FP


def test_every_attack_is_checked_against_a_real_rule():
    report = evaluate_mod.evaluate()
    assert set(report.per_rule) <= set(RULES)  # solo reglas que existen
    for detected, total in report.per_rule.values():
        assert 0 < total
        assert 0 <= detected <= total
    # el desglose por regla suma el total de payloads medidos
    assert sum(total for _, total in report.per_rule.values()) == report.attacks_total


def test_cli_check_passes(capsys):
    assert evaluate_mod.main(["--check"]) == 0
    assert "✅" in capsys.readouterr().err


def test_report_is_rendered_and_mentions_limits():
    text = evaluate_mod.to_markdown(
        evaluate_mod.evaluate(), evaluate_mod.DEFAULT_MIN_DETECTION,
        evaluate_mod.DEFAULT_MAX_FP,
    )
    assert "Falsos positivos documentados" in text
    assert "Umbrales de CI" in text


@pytest.mark.parametrize("name", ["attacks.json", "benign.json"])
def test_corpus_entries_are_well_formed(name):
    payloads = json.loads((CORPUS / name).read_text(encoding="utf-8"))["payloads"]
    ids = [item["id"] for item in payloads]
    assert len(ids) == len(set(ids)), "ids duplicados en el corpus"
    for item in payloads:
        assert item["payload"], f"{item['id']} sin payload"
        assert item.get("note"), f"{item['id']} sin nota"
        if name == "attacks.json":
            assert item["rule"] in RULES, f"{item['id']} usa una regla inexistente"
            assert isinstance(item.get("documented_miss", False), bool)
        if item.get("known_fp"):
            assert len(item["known_fp"]) > 10, f"{item['id']}: known_fp sin justificación"
