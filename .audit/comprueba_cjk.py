#!/usr/bin/env python3
"""Verifica que no queden caracteres CJK en los ficheros de texto del paquete.

Un CJK colado es siempre un error mio: en un documento en español no aporta
nada y rompe la lectura. Este script las detecta y las muestra con contexto,
para poder corregirlas.

Uso:
    python .audit/comprueba_cjk.py                 # revisa el paquete del revisor
    python .audit/comprueba_cjk.py <fichero> ...   # revisa los ficheros dados
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

RAIZ = Path(r"D:\ADEV\ProyectosVScode\Gatekeeper")
PAQUETE = RAIZ / ".audit" / "PACK-REVISOR"

# CJK (unificado), sus extensions A y los signos de puntuacion CJK.
CJK = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3000-\u303f\uff00-\uffef]")


def revisar(ruta: Path) -> list[str]:
    try:
        texto = ruta.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    fallos: list[str] = []
    for numero, linea in enumerate(texto.splitlines(), 1):
        for coincidencia in CJK.finditer(linea):
            fallos.append(
                f"{ruta}:{numero}: {coincidencia.group(0)!r} (U+"
                f"{ord(coincidencia.group(0)):04X}) -> {linea.strip()[:100]}"
            )
    return fallos


def main(argv: list[str]) -> int:
    if argv:
        rutas = [Path(a) for a in argv]
    else:
        rutas = sorted(PAQUETE.rglob("*"))
        rutas = [r for r in rutas if r.is_file() and r.suffix in (".md", ".py", ".txt")]

    fallos: list[str] = []
    for ruta in rutas:
        fallos.extend(revisar(ruta))

    if fallos:
        print(f"CARACTERES CJK ENCONTRADOS ({len(fallos)}):")
        for fallo in fallos:
            print(f"  {fallo}")
        return 1
    print(f"OK: sin caracteres CJK en {len(rutas)} fichero(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
