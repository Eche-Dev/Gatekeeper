"""Mide el efecto de un cambio de reglas sobre TODOS los corpus a la vez.

Se usa al añadir una firma: hay que ver el coste (nuevos falsos positivos) y
el beneficio (nuevas detecciones) en el corpus propio, en el retenido y en los
negativos de OWASP CRS. Un cambio que mejora una cifra y rompe otra no vale.

Uso:
    python tools/measure_rules.py            # mide el estado actual
    python tools/measure_rules.py --baseline antes.json   # compara
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gatekeeper.body import content_type_of, extract_strings, is_inspectable  # noqa: E402
from gatekeeper.config import DEFAULT_INSPECT_HEADERS  # noqa: E402
from gatekeeper.rules import scan  # noqa: E402

CORPUS_DIR = ROOT / "corpus"


def _load(name: str) -> list[dict]:
    data = json.loads((CORPUS_DIR / name).read_text(encoding="utf-8"))
    return data["payloads"]


def medir() -> dict:
    """Detección sobre los corpus propios y FP sobre los negativos de CRS."""
    resultado: dict = {}

    for nombre, archivo in (("propio", "attacks.json"), ("retenido", "heldout_attacks.json")):
        items = _load(archivo)
        detectados = [i for i in items if scan(i["payload"])]
        resultado[nombre] = {
            "total": len(items),
            "detectados": len(detectados),
            "faltan": [i["id"] for i in items if not scan(i["payload"])],
        }

    benignos = _load("benign.json")
    fp = [i for i in benignos if scan(i["payload"])]
    resultado["benignos_propios"] = {
        "total": len(benignos),
        "flagged": len(fp),
        "sin_documentar": len([i for i in fp if not i.get("known_fp")]),
    }

    # Negativos de CRS: FP sobre su propio conjunto de negativos.
    crs_file = CORPUS_DIR / "crs_payloads.json"
    if crs_file.exists():
        data = json.loads(crs_file.read_text(encoding="utf-8"))
        negativos = [i for i in data["payloads"] if i["expect"] == "benign"]
        flagged = 0
        for item in negativos:
            uri = item.get("uri") or ""
            carriers = [uri] if uri else []
            carriers.extend(
                v for n, v in (item.get("headers") or {}).items()
                if n in DEFAULT_INSPECT_HEADERS
            )
            raw = item.get("content_type")
            ctype = content_type_of(raw) if raw else "application/x-www-form-urlencoded"
            data_body = item.get("data")
            if data_body and is_inspectable(ctype):
                carriers.extend(
                    v for _, v in extract_strings(ctype, data_body.encode("utf-8", "replace"))
                )
            if any(scan(c) for c in carriers):
                flagged += 1
        resultado["negativos_crs"] = {"total": len(negativos), "flagged": flagged}
    return resultado


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--baseline", help="fichero JSON con una medición anterior")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    actual = medir()
    if args.json:
        print(json.dumps(actual, indent=2, ensure_ascii=False))
        return 0

    anterior = json.loads(Path(args.baseline).read_text(encoding="utf-8")) if args.baseline else None

    for clave in ("propio", "retenido", "benignos_propios", "negativos_crs"):
        if clave not in actual:
            continue
        v = actual[clave]
        linea = f"{clave:20}"
        if "detectados" in v:
            linea += f" {v['detectados']}/{v['total']}"
            if anterior and clave in anterior:
                d = v["detectados"] - anterior[clave]["detectados"]
                linea += f" ({d:+d})"
        else:
            linea += f" flagged {v['flagged']}/{v['total']}"
            if anterior and clave in anterior:
                d = v["flagged"] - anterior[clave]["flagged"]
                linea += f" ({d:+d})"
            if "sin_documentar" in v:
                linea += f" | sin documentar: {v['sin_documentar']}"
        print(linea)

    if "retenido" in actual and actual["retenido"]["faltan"]:
        print("\nFaltan en el retenido:")
        for pid in actual["retenido"]["faltan"]:
            print(f"  {pid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
