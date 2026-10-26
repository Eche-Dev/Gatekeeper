#!/usr/bin/env python3
"""Comprueba que la guarda HABRIA cazado el error real de la portada.

Se vuelve a poner el 0.37 en una copia de docs/index.md y se pasa el
verificador. Si no se queja, la guarda no sirve: el unico error conocido
tiene que saltar.
"""
from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
PAQUETE = RAIZ / "gatekeeper-v0.3" / "gatekeeper"

spec = importlib.util.spec_from_file_location(
    "check_docs", PAQUETE / "tools" / "check_docs.py"
)
modulo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(modulo)

with tempfile.TemporaryDirectory() as tmp:
    destino = Path(tmp) / "index.md"
    shutil.copy(PAQUETE / "docs" / "index.md", destino)
    texto = destino.read_text(encoding="utf-8")
    texto = texto.replace("≥ 0.23", "≥ 0.37")
    destino.write_text(texto, encoding="utf-8")
    fallos, _ = modulo.comprobar([destino])
    print("fallos con el 0.37 de vuelta en la portada:")
    for fallo in fallos:
        print(f"  - {fallo}")
    if not fallos:
        print("  NINGUNO: la guarda NO caza el error real")
        sys.exit(1)
    print("\nLa guarda caza el error real.")
