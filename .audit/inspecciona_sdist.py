#!/usr/bin/env python3
"""Inspecciona el sdist publicado en PyPI: que lleva y cuanto pesa.

Sirve para comparar lo que se publica con lo que el repo genera hoy (F5
recorto el sdist a 95 KiB excluyendo corpus, web, demos, benchmarks y tests).
Si el sdist de PyPI todavia lleva todo eso, la F5 no ha llegado a quien
instala con pip: sigue siendo trabajo de GitHub, no del paquete.
"""
from __future__ import annotations

import sys
import tarfile
from collections import Counter
from pathlib import Path

RUTA = Path(sys.argv[1] if len(sys.argv) > 1 else ".audit/pub_0.7.0.tar.gz")

with tarfile.open(RUTA, "r:gz") as tar:
    miembros = [m for m in tar.getmembers() if m.isfile()]
    total = sum(m.size for m in miembros)
    # El prefijo es la carpeta raiz del sdist: gatekeeper_asgi-<version>/
    prefijo = ""
    if miembros:
        primero = miembros[0].name.split("/")[0]
        if primero.endswith("/") or "/" in miembros[0].name:
            prefijo = primero + "/"
    topes = Counter()
    for m in miembros:
        rel = m.name[len(prefijo):] if m.name.startswith(prefijo) else m.name
        partes = rel.split("/")
        if len(partes) > 1:
            topes[partes[0]] += 1
        else:
            topes["(raiz)"] += 1

print(f"fichero      : {RUTA} ({RUTA.stat().st_size} bytes)")
print(f"contenido    : {len(miembros)} ficheros, {total} bytes descomprimidos")
print("por carpeta  :")
for nombre, n in sorted(topes.items(), key=lambda kv: -kv[1]):
    marca = "  <-- recortado en F5" if nombre in {"corpus", "tests", "docs", "demo", "benchmarks", "web"} else ""
    print(f"   {nombre:<14} {n:>4}{marca}")
