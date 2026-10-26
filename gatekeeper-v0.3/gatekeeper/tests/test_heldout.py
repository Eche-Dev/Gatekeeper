"""El corpus retenido es una MEDIDA, y esta fijar sus cifras.

`corpus/heldout_*.json` mide si las reglas generalizan. El riesgo de un
corpus retenido es que se degrade: que se ajuste para que pase, o que las
cifras que se publican dejen de ser las que da el corpus.

Estos tests fijan:
- las cifras medidas (para que un cambio las mueva a proposito, no por
  descuido);
- que los payloads documentados como limite siguen documentados (con su
  motivo);
- que NO se anaden payloads nuevos para "cubrir" un fallo: el corpus se
  congela.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"

ATTACKS = json.loads((CORPUS / "heldout_attacks.json").read_text(encoding="utf-8"))
BENIGN = json.loads((CORPUS / "heldout_benign.json").read_text(encoding="utf-8"))

# Cifras medidas. Si cambian, el CHANGELOG y el informe deben cambiar con ellas.
EXPECTED_DETECTED = 103
EXPECTED_ATTACKS = 109
EXPECTED_BENIGN = 140
EXPECTED_DOCUMENTED_MISS = 6
EXPECTED_DOCUMENTED_FP = 5


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "tools" / "evaluate_heldout.py"), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )


def test_el_corpus_retenido_tiene_el_tamano_esperado():
    """El corpus se congela: si cambia de tamaño, es a proposito y con motivo."""
    assert len(ATTACKS["payloads"]) == EXPECTED_ATTACKS
    assert len(BENIGN["payloads"]) == EXPECTED_BENIGN


def test_las_cifras_medidas_son_las_publicadas():
    """La deteccion medida tiene que ser la que dice el informe."""
    proc = _run("--json")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["attacks_total"] == EXPECTED_ATTACKS
    assert data["attacks_detected"] == EXPECTED_DETECTED
    assert data["attacks_documented_miss"] == EXPECTED_DOCUMENTED_MISS
    assert data["benign_total"] == EXPECTED_BENIGN
    assert data["benign_documented_fp"] == EXPECTED_DOCUMENTED_FP


def test_no_hay_falsos_positivos_no_documentados():
    """Cero FP sin documentar sobre trafico legitimo retenido.

    Es el mismo criterio que el corpus de desarrollo: un FP nuevo sobre
    trafico real es un bug de las reglas, no un limite.
    """
    proc = _run("--json")
    data = json.loads(proc.stdout)
    assert data["fp_rate"] == 0.0, data
    assert data["benign_flagged"] == data["benign_documented_fp"], data


def test_no_hay_falsos_negativos_no_documentados():
    """Todo lo que se escapa esta documentado con su motivo."""
    proc = _run("--json")
    data = json.loads(proc.stdout)
    assert data["attacks_missed"] == [], data


def test_todo_limite_documentado_explica_por_que():
    """Un `documented_miss` sin motivo no vale: o se arregla, o se explica."""
    for item in ATTACKS["payloads"]:
        if item.get("documented_miss"):
            assert item["documented_miss"].strip(), item["id"]
            assert item.get("note"), item["id"]


def test_todo_falso_positivo_documentado_explica_por_que():
    for item in BENIGN["payloads"]:
        if item.get("known_fp"):
            assert item["known_fp"].strip(), item["id"]


def test_los_identificadores_no_se_repiten():
    """Un id repetido hace que un payload se cuente dos veces."""
    ids = [i["id"] for i in ATTACKS["payloads"]] + [i["id"] for i in BENIGN["payloads"]]
    assert len(ids) == len(set(ids)), "hay identificadores repetidos en el retenido"


def test_el_corpus_retenido_no_se_solapa_con_el_de_desarrollo():
    """Los payloads del retenido no pueden ser los del corpus de desarrollo.

    Si se compartieran, el retenido mediria memoria y no generalizacion: que
    es justo lo que el corpus retenido existe para evitar.
    """
    dev = json.loads((CORPUS / "attacks.json").read_text(encoding="utf-8"))
    benignos_dev = json.loads((CORPUS / "benign.json").read_text(encoding="utf-8"))

    desarrollo = {i["payload"] for i in dev["payloads"]}
    desarrollo |= {i["payload"] for i in benignos_dev["payloads"]}
    retenido = {i["payload"] for i in ATTACKS["payloads"]}
    retenido |= {i["payload"] for i in BENIGN["payloads"]}

    solape = desarrollo & retenido
    assert not solape, f"payloads compartidos entre desarrollo y retenido: {solape}"


def test_el_umbral_de_ci_pasa():
    """El evaluador en modo --check tiene que salir con 0."""
    proc = _run("--check")
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]


def test_el_informe_generado_coincide_con_el_corpus():
    """El informe se regenera; si esta desactualizado, CI deberia fallar.

    Aqui se comprueba que el informe que hay en disco menciona las mismas
    cifras que el corpus, para que nadie publique un informe viejo.
    """
    report = (CORPUS / "HELDOUT_REPORT.md").read_text(encoding="utf-8")
    assert f"| Payloads de ataque | {EXPECTED_ATTACKS} |" in report
    assert f"| Detectados | {EXPECTED_DETECTED} " in report


@pytest.mark.parametrize("herramienta", ["evaluate.py", "evaluate_cross.py"])
def test_los_otros_evaluadores_siguen_pasando(herramienta: str):
    """Añadir el retenido no puede romper los evaluadores que ya existian."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / herramienta), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout[-1000:] + proc.stderr[-1000:]


def test_el_evaluador_del_cruzado_retenido_pasa():
    """El corpus retenido del modo cruzado tambien tiene su guarda."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "evaluate_cross.py"), "--heldout", "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stdout[-1000:] + proc.stderr[-1000:]


def test_el_cruzado_retenido_no_se_solapa_con_el_de_desarrollo():
    """Igual que con el corpus principal: si comparten payloads, no mide nada."""
    dev = json.loads((CORPUS / "cross.json").read_text(encoding="utf-8"))
    retenido = json.loads((CORPUS / "heldout_cross.json").read_text(encoding="utf-8"))

    def pares(data: dict) -> set[tuple[str, str]]:
        return (
            {(p["target"], p["body"]) for p in data["payloads"]}
            | {(p["target"], p["body"]) for p in data["benign_payloads"]}
        )

    solape = pares(dev) & pares(retenido)
    assert not solape, f"payloads compartidos en el corpus cruzado: {solape}"

    ids_dev = {p["id"] for p in dev["payloads"]} | {p["id"] for p in dev["benign_payloads"]}
    ids_retenido = {p["id"] for p in retenido["payloads"]} | {
        p["id"] for p in retenido["benign_payloads"]
    }
    assert not (ids_dev & ids_retenido), "hay ids repetidos entre los corpus cruzados"


def test_el_modo_cruzado_gana_ataques_al_retenido():
    """La combinacion tiene que aportar algo: si no, no vale la pena.

    Sin el modo cruzado, la mitad de las firmas partidas se escapan. Con el,
    se detectan todas y sin falsos positivos.
    """
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "evaluate_cross.py"), "--heldout", "--json"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr[-1000:]
    data = json.loads(proc.stdout)
    por_defecto = data["default"]
    cruzado = data["cross"]

    assert por_defecto["attacks_blocked"] < por_defecto["attacks_total"], (
        "si el modo por defecto ya lo detecta todo, el corpus no mide el cruce"
    )
    assert cruzado["attacks_blocked"] == cruzado["attacks_total"], data
    assert cruzado["benign_blocked"] == 0, data
    # Y el modo cruzado no puede perder ataques que el normal ya cogia.
    assert cruzado["attacks_blocked"] >= por_defecto["attacks_blocked"], data
