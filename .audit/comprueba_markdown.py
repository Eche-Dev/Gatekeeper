#!/usr/bin/env python3
"""Comprueba que el markdown de los README se renderiza como se espera.

Renderizar en GitHub no es un misterio, pero dos cosas sí rompen la lectura:
un bloque de codigo sin cerrar y una tabla cuyas filas no tienen el mismo
numero de columnas que la cabecera. Esto lo comprueba de forma objetiva.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
FICHEROS = [
    RAIZ / "README.md",
    RAIZ / "gatekeeper-v0.3" / "gatekeeper" / "README.md",
    RAIZ / "gatekeeper-v0.3" / "gatekeeper" / "README.en.md",
]

SEP_TABLA = re.compile(r"^\|?[\s:-]*-[-\s:|]*\|[\s:-]*$")


def comprueba(ruta: Path) -> list[str]:
    fallos: list[str] = []
    texto = ruta.read_text(encoding="utf-8")
    lineas = texto.splitlines()

    # 1) bloques de codigo balanceados
    sorpresa = False
    for n, linea in enumerate(lineas, 1):
        if linea.lstrip().startswith("```"):
            sorpresa = not sorpresa
    if sorpresa:
        fallos.append("hay un bloque de codigo sin cerrar")

    # 2) tablas: cabecera, separador y filas con las mismas columnas
    i = 0
    tablas = 0
    while i < len(lineas) - 1:
        cabecera = lineas[i]
        separador = lineas[i + 1]
        if "|" in cabecera and SEP_TABLA.match(separador):
            tablas += 1
            columnas = cabecera.count("|")
            if separador.count("|") != columnas:
                fallos.append(
                    f"linea {i + 2}: el separador tiene {separador.count('|')} "
                    f"columnas y la cabecera {columnas}"
                )
            j = i + 2
            while j < len(lineas) and "|" in lineas[j] and lineas[j].strip():
                if lineas[j].count("|") != columnas:
                    fallos.append(
                        f"linea {j + 1}: la fila de la tabla tiene "
                        f"{lineas[j].count('|')} columnas y la cabecera {columnas}"
                    )
                j += 1
            i = j
        else:
            i += 1

    print(f"{ruta.relative_to(RAIZ).as_posix()}: {tablas} tablas, {len(lineas)} lineas")
    return fallos


def main() -> int:
    total = 0
    for ruta in FICHEROS:
        fallos = comprueba(ruta)
        for fallo in fallos:
            print(f"  !! {ruta.name}: {fallo}")
        total += len(fallos)
    print()
    print("markdown correcto" if total == 0 else f"{total} problemas")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
