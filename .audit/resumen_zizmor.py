#!/usr/bin/env python3
"""Resumen de los hallazgos de zizmor: que auditorias y en que workflows.

zizmor devuelve mucho detalle; lo que hace falta para decidir es la cuenta
por auditoria y por fichero, y si hay algo de severidad alta.
"""
from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
ZIZMOR = RAIZ / ".audit" / "venv-sast" / "Scripts" / "zizmor.exe"

proc = subprocess.run(
    [str(ZIZMOR), "--format", "json", ".github/workflows/"],
    capture_output=True,
    text=True,
    cwd=RAIZ,
)
try:
    datos = json.loads(proc.stdout)
except json.JSONDecodeError:
    print("No se pudo leer el JSON de zizmor:")
    print(proc.stdout[-2000:])
    print(proc.stderr[-2000:])
    sys.exit(1)

hallazgos = datos if isinstance(datos, list) else datos.get("findings", [])
print(f"hallazgos: {len(hallazgos)}\n")

por_audit = Counter()
por_fichero = Counter()
por_sev = Counter()
detalle = []
for h in hallazgos:
    audit = h.get("ident") or h.get("rule_id") or h.get("audit") or "?"
    sev = (h.get("severity") or "?").lower()
    loc = h.get("location") or h.get("locations") or {}
    if isinstance(loc, dict):
        ruta = loc.get("path", "?")
        linea = loc.get("line", "?")
    else:
        ruta, linea = "?", "?"
    conf = h.get("confidence") or "?"
    por_audit[(audit, sev)] += 1
    por_fichero[ruta] += 1
    por_sev[sev] += 1
    detalle.append((ruta, linea, audit, sev, conf, (h.get("message") or "")[:70]))

print("por auditoria:")
for (audit, sev), n in por_audit.most_common():
    print(f"   {n:>3}  {sev:<8} {audit}")
print("\npor fichero:")
for ruta, n in por_fichero.most_common():
    print(f"   {n:>3}  {ruta}")
print("\npor severidad:", dict(por_sev))
print("\ndetalle:")
for ruta, linea, audit, sev, conf, msg in detalle:
    print(f"   {ruta}:{linea}  [{audit}] {sev} conf={conf}  {msg}")
