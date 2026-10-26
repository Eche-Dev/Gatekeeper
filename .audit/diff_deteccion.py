"""Compara, payload a payload, lo que se detecta antes y despues de un cambio.

Se usa para no perder detecciones al tocar una regla: guarda el estado con
el codigo de HEAD (la version publicada) y con el codigo del arbol de
trabajo, y lista lo que ha cambiado.

Uso (desde ``gatekeeper-v0.3/gatekeeper``)::

    python .audit/diff_deteccion.py antes.txt
    python .audit/diff_deteccion.py despues.txt
    python .audit/diff_deteccion.py --compara antes.txt despues.txt
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
PKG = RAIZ / "gatekeeper-v0.3" / "gatekeeper"
sys.path.insert(0, str(PKG / "src"))
sys.path.insert(0, str(PKG / "tools"))

from evaluate import _crs_carriers  # noqa: E402
from gatekeeper.rules import scan  # noqa: E402

CRS = PKG / "corpus" / "crs_payloads.json"


def main() -> None:
    datos = json.loads(CRS.read_text(encoding="utf-8"))
    salida = []
    for item in datos["payloads"]:
        carriers, _ = _crs_carriers(item)
        fired = next((r for r in (scan(c) for c in carriers) if r), None)
        salida.append(
            f"{item['id']}\t{item.get('family')}\t{item['expect']}\t{fired or '-'}"
        )
    Path(sys.argv[1]).write_text("\n".join(salida) + "\n", encoding="utf-8")
    print(f"{len(salida)} casos -> {sys.argv[1]}")


if __name__ == "__main__":
    main()
