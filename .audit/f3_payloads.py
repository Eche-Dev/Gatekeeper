#!/usr/bin/env python3
"""Muestra los payloads que dependen de las firmas candidatas a endurecer."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "gatekeeper-v0.3" / "gatekeeper"
sys.path.insert(0, str(PKG / "src"))
sys.path.insert(0, str(PKG / "tools"))

from evaluate import _crs_carriers  # noqa: E402

CORPUS = PKG / "corpus"

INTERESADOS = {
    "propio": ["sqli-013", "sqli-107", "nosql-001", "nosql-002", "nosql-003",
               "nosql-004", "nosql-005", "nosql-006", "nosql-007",
               "ssti-006", "ssti-007"],
    "retenido": ["ho-nosql-001", "ho-nosql-003", "ho-nosql-004", "ho-nosql-005",
                 "ho-nosql-006", "ho-nosql-007", "ho-ssti-005", "ho-ssti-006"],
}


def _carga(nombre: str) -> list[dict]:
    return json.loads((CORPUS / nombre).read_text(encoding="utf-8"))["payloads"]


def main() -> int:
    for etiqueta, fichero in (("propio", "attacks.json"), ("retenido", "heldout_attacks.json")):
        ids = set(INTERESADOS[etiqueta])
        for item in _carga(fichero):
            if item["id"] in ids:
                print(f"{etiqueta:9s} {item['id']:14s} {item['payload']!r}")

    print("\n--- CRS ---")
    data = json.loads((CORPUS / "crs_payloads.json").read_text(encoding="utf-8"))
    for item in data["payloads"]:
        if not item["id"].startswith(("crs-942101", "crs-942240", "crs-942120", "crs-942290")):
            continue
        carriers, _ = _crs_carriers(item)
        texto = item.get("data") or item.get("uri") or ""
        print(f"{item['id']:28s} {texto!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
