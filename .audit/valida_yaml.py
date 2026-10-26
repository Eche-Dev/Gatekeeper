#!/usr/bin/env python3
"""Comprueba que los workflows siguen siendo YAML valido.

Un `with:` mal puesto rompe el workflow entero (y el error lo ve GitHub, no
nosotros). Esto lo comprueba antes de subir.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((RAIZ / ".github" / "workflows").glob("*.yml"))

errores = 0
for ruta in WORKFLOWS:
    try:
        datos = yaml.safe_load(ruta.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        print(f"!! {ruta.name}: YAML invalido: {exc}")
        errores += 1
        continue
    jobs = datos.get("jobs", {})
    print(f"{ruta.name}: {len(jobs)} jobs -> {', '.join(jobs)}")

# El job de SAST tiene que existir y bloquear con las reglas propias.
ci = yaml.safe_load((RAIZ / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
if "sast" not in ci.get("jobs", {}):
    print("!! ci.yml no tiene el job 'sast'")
    errores += 1
else:
    pasos = []
    for paso in ci["jobs"]["sast"]["steps"]:
        pasos.append(str(paso.get("name", "")))
        pasos.append(str(paso.get("run", "")))
        pasos.append(str(paso.get("with", "")))
    propios = any("semgrep_rules.yml" in p for p in pasos)
    zizmor = any("zizmor" in p for p in pasos)
    comunidad = any("p/default" in p for p in pasos)
    print(f"   job sast: reglas propias={'si' if propios else 'NO'}, zizmor={'si' if zizmor else 'NO'}, comunidad={'si' if comunidad else 'NO'}")
    if not (propios and zizmor and comunidad):
        print("!! el job sast no tiene las tres comprobaciones")
        errores += 1

print()
print("YAML correcto" if errores == 0 else f"{errores} problemas")
sys.exit(1 if errores else 0)
