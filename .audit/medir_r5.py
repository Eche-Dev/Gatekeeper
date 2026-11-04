"""Medición reproducible de NUEVO-7 (Ronda 5 de Claude) contra los tres corpus reales."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "gatekeeper-v0.3" / "gatekeeper"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from gatekeeper import rules  # noqa: E402
import evaluate  # noqa: E402
import evaluate_heldout  # noqa: E402


def medir_tres_corpus() -> tuple[int, int, int, int, int, int]:
    propio = evaluate.evaluate()
    crs = evaluate.evaluate_crs()
    heldout = evaluate_heldout.evaluate()
    return (
        propio.attacks_detected,
        propio.benign_flagged - propio.benign_documented_fp,
        heldout.attacks_detected,
        heldout.benign_flagged - heldout.benign_documented_fp,
        crs.attacks_detected,
        crs.benign_flagged,
    )


def main() -> None:
    benignos = {
        "test unitario Python (self.assertEqual)": "def test_suma(self):\n    self.assertEqual(suma(2,2), 4)",
        "clase Python (self.nombre, self.id)": "class Usuario:\n    def __init__(self):\n        self.nombre = ''\n        self.id = None",
        "JS legítimo (window.addEventListener + parent)": "window.addEventListener('message', (e) => {\n  if (e.source === parent) handle(e);\n});",
        "JS legítimo (parent.postMessage)": "parent.postMessage({type: 'ready'}, 'https://example.com');",
        "JS legítimo (frames.length)": "if (frames.length > 0) { console.log('ok'); }",
    }

    print("=== 1. Estado ANTES del ajuste ===")
    for k, v in benignos.items():
        print(f"  {k}: {rules.scan_detailed(v) is not None}")
    antes_crs_misses = evaluate.evaluate_crs().misses
    antes_metricas = medir_tres_corpus()
    print(f"  Métricas (propio_det, propio_fp, heldout_det, heldout_fp, crs_det, crs_fp): {antes_metricas}")

    # Candidato: retirar `self`, `parent` y `frames` de la lista genérica de xss[6],
    # y excluir `window.addEventListener` (listener receptor de postMessage, no sink de ejecución).
    nuevo_xss_6 = re.compile(
        r"\b(?:setinterval|settimeout|eval)\s{0,16}(?:\?\s{0,4}\.\s{0,8})?[\(`]"
        r"|(?<!/)\bdocument\s{0,8}(?:\?\s{0,4}\.\s{0,4}\[|\?\s{0,4}\.|\.|\[)"
        r"|\bwindow\s{0,8}(?:\?\s{0,4}\.\s{0,4}\[|(?:\?\s{0,4}\.|\.)(?!\s{0,4}addeventlistener\b)|\[)"
        r"|\b(?:globalthis|top)\s{0,8}(?:\?\s{0,4}\.\s{0,4}\[|\?\s{0,4}\.|\.|\[)"
        r"|\b(?:self|parent|frames)\s{0,8}(?:(?:\?\s{0,4})?\.\s{0,4}(?:document|window|globalthis|top|location|eval|settimeout|setinterval|alert|prompt|confirm)\b|(?:\?\s{0,4}\.\s{0,4})?\[\s{0,8}['\"`])"
        r"|\blocation\s{0,8}(?:=|\?\s{0,4}\.\s{0,4}\[|\?\s{0,4}\.|\.\s{0,4}(?:href|replace|assign)\b|\[)"
    )

    old_xss_6 = rules.RULES["xss"][6]
    old_pref = rules.PREFILTER_LITERALS["xss"]

    import json
    crs_items = json.loads(evaluate.CRS_FILE.read_text(encoding="utf-8"))["payloads"]
    antes_hits = {}
    for item in crs_items:
        if item["expect"] != "attack":
            continue
        carriers, _ = evaluate._crs_carriers(item)
        fired = next((r for r in (rules.scan(c) for c in carriers) if r), None)
        if fired:
            antes_hits[item["id"]] = (fired, carriers)

    rules.RULES["xss"][6] = nuevo_xss_6
    rules._PREFILTER_LITERALS_FLAT, rules._PREFILTER_FAMILIA = rules._build_prefilter()

    print("\n=== 2. Estado DESPUÉS del ajuste ===")
    for k, v in benignos.items():
        print(f"  {k}: {rules.scan_detailed(v) is not None}")
    despues_metricas = medir_tres_corpus()
    print(f"  Métricas (propio_det, propio_fp, heldout_det, heldout_fp, crs_det, crs_fp): {despues_metricas}")

    print("\n=== 3. CRS payloads que dependían de self/parent/frames ===")
    for item in crs_items:
        if item["id"] not in antes_hits:
            continue
        carriers, _ = evaluate._crs_carriers(item)
        fired = next((r for r in (rules.scan(c) for c in carriers) if r), None)
        if not fired:
            print(f"  - {item['id']}: desc={item.get('desc')!r} carriers={carriers}")

    import time
    t0 = time.perf_counter()
    res = rules.scan_detailed("self." * 50_000)
    dt = (time.perf_counter() - t0) * 1000
    print(f"\n=== 4. Tiempo en 250 KB de 'self.' repetido: {dt:.1f} ms (hit={res}) ===")


if __name__ == "__main__":
    main()
