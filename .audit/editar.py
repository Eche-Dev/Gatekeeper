#!/usr/bin/env python3
"""Aplica cambios en un fichero preservando los finales de linea y exigiendo
que cada patron aparezca EXACTAMENTE una vez (si no, el script falla y no
escribe nada).

Los patrones se escriben con "\\n" y el script los traduce al final de linea
real del fichero (CRLF o LF), para que no haya que fights con el editor.

Uso: python .audit/editar.py <fichero> <pares.json>
El fichero de pares es un JSON: [[patron, sustitucion], ...]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("uso: editar.py <fichero> <pares.json>", file=sys.stderr)
        return 2
    destino = Path(sys.argv[1])
    pares = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

    with open(destino, "r", encoding="utf-8", newline="") as fh:
        texto = fh.read()

    crlf = "\r\n" in texto

    def adaptar(fragmento: str) -> str:
        if crlf:
            return fragmento.replace("\r\n", "\n").replace("\n", "\r\n")
        return fragmento.replace("\r\n", "\n")

    for par in pares:
        patron, sustitucion = par[0], par[1]
        todos = len(par) > 2 and par[2] == "todos"
        patron = adaptar(patron)
        sustitucion = adaptar(sustitucion)
        n = texto.count(patron)
        if n == 0:
            print(f"ERROR: el patron aparece 0 veces (se requiere 1):\n{patron[:160]}")
            return 1
        if n > 1 and not todos:
            print(f"ERROR: el patron aparece {n} veces (se requiere 1):\n{patron[:160]}")
            return 1
        texto = texto.replace(patron, sustitucion)
        if todos:
            print(f"  (reemplazo multiple: {n} ocurrencias)")

    with open(destino, "w", encoding="utf-8", newline="") as fh:
        fh.write(texto)
    print(f"OK: {destino} ({len(pares)} cambios)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
