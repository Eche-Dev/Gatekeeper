"""Segundo vector de DoS: el coste por peticion escala con el NUMERO DE CAMPOS
del body, no solo con los bytes. Medido, perfilado y comparado con el parche.
"""
from __future__ import annotations

import cProfile
import io
import json
import os
import pstats
import subprocess
import sys
import time

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")

from gatekeeper.body import extract_strings
from gatekeeper.rules import scan_detailed

# ------------------------------------------------ 1. escalado por numero de campos
print("=" * 78)
print("1) COSTE POR PETICION SEGUN EL NUMERO DE CAMPOS DEL BODY")
print("   (cada campo se escanea por separado: coste = n_campos x constante)")
print("=" * 78)
print(f"{'campos':>8} {'bytes':>9} {'segundos':>10} {'us/campo':>10}")
prev = None
for n in (1_000, 2_500, 5_000, 10_000, 20_000):
    cuerpo = json.dumps({f"campo_{i}": "valor" for i in range(n)}).encode()
    campos = extract_strings("application/json", cuerpo)
    t0 = time.perf_counter()
    for _pointer, value in campos:
        scan_detailed(value)
    dt = time.perf_counter() - t0
    print(f"{n:>8} {len(cuerpo):>9} {dt:>10.3f} {dt/n*1e6:>10.1f}"
          + (f"   (x{dt/prev:.2f} tiempo)" if prev else ""))
    prev = dt

# ------------------------------------------------ 2. peor caso con max_body_size
print()
print("=" * 78)
print("2) PEOR CASO REAL: body de 1 MiB (max_body_size por defecto) lleno de campos")
print("=" * 78)
n_max = 0
for n in (30_000, 40_000, 50_000):
    cuerpo = json.dumps({f"k{i}": "v" for i in range(n)}).encode()
    if len(cuerpo) > 1_048_576:
        break
    n_max = n
    campos = extract_strings("application/json", cuerpo)
    t0 = time.perf_counter()
    for _pointer, value in campos:
        scan_detailed(value)
    dt = time.perf_counter() - t0
    print(f"{n:>8} campos = {len(cuerpo)/1024:.0f} KiB -> {dt:.2f} s de CPU por peticion")

print()
print("   Y con inspect_cross_carrier=True el middleware además concatena y")
print("   vuelve a escanear todo el cuerpo como un string gigante:")

# ------------------------------------------------ 3. perfil del camino caliente
print()
print("=" * 78)
print("3) PERFIL: DONDE SE VA EL TIEMPO")
print("=" * 78)
cuerpo = json.dumps({f"k{i}": "valor" for i in range(8_000)}).encode()
campos = extract_strings("application/json", cuerpo)
pr = cProfile.Profile()
pr.enable()
for _pointer, value in campos:
    scan_detailed(value)
pr.disable()
s = io.StringIO()
pstats.Stats(pr, stream=s).sort_stats("cumulative").print_stats(12)
print(s.getvalue())

# ------------------------------------------------ 4. el parche lo arregla?
print("=" * 78)
print("4) ¿LO ARREGLA EL PARCHE fix-redos-comentarios-sql.patch?")
print("=" * 78)
CODIGO = r"""
import json, os, sys, time
sys.path.insert(0, os.environ["GK_SRC"])
from gatekeeper.body import extract_strings
from gatekeeper.rules import scan_detailed
cuerpo = json.dumps({f"k{i}": "valor" for i in range(8000)}).encode()
campos = extract_strings("application/json", cuerpo)
t0 = time.perf_counter()
for _p, v in campos:
    scan_detailed(v)
print(f"{time.perf_counter()-t0:.3f}")
"""
fuente = r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src"
parche = r"D:\ADEV\ProyectosVScode\Gatekeeper\.audit\patchtest_v1\gatekeeper-v0.3\gatekeeper\src"

for etiqueta, ruta in (("SIN parche", fuente), ("CON parche", parche)):
    if not os.path.isdir(ruta):
        print(f"  {etiqueta}: ruta no disponible ({ruta})")
        continue
    env = dict(os.environ)
    env["GK_SRC"] = ruta
    proc = subprocess.run([sys.executable, "-c", CODIGO], capture_output=True,
                          text=True, timeout=300, env=env)
    if proc.returncode != 0:
        print(f"  {etiqueta}: error {proc.stderr[-300:]}")
        continue
    print(f"  {etiqueta}: {proc.stdout.strip().splitlines()[-1]} s para 8.000 campos")
