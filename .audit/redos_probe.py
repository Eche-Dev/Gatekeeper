"""Prueba reproducible del ReDoS en las reglas propias (Fase 2.3).

Muestra, contra el codigo tal cual esta:

1. Que una regex catastrofica se RECHAZA al arrancar (no cuelga el proceso).
2. Que el riesgo cuadratico se AVISA pero no se rechaza.
3. Cuanto cuesta de verdad cada patron (la medicion que fija los dos niveles).

Uso (desde ``gatekeeper-v0.3/gatekeeper``)::

    python .audit/redos_probe.py
"""
from __future__ import annotations

import logging
import re
import time

from gatekeeper import Config
from gatekeeper.redos import analizar_redos

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

CASOS = [
    ("(a+)+$", "exponencial"),
    ("(a|a)+", "exponencial"),
    ("(https|http)+", "exponencial"),
    (r"(\w+)\1+", "exponencial"),
    (r"(?:\w+\.)+\w+", "cuadratico"),
    (r"\btk_[a-z0-9]{24}\b", "ninguno"),
]


def _arrancar(patron: str) -> str:
    try:
        Config(custom_rules={"prueba": patron})
    except ValueError as exc:
        return f"RECHAZADO: {str(exc)[:80]}"
    return "ACEPTADO"


print("=" * 78)
print("VALIDACION DE REGLAS PROPIAS AL ARRANCAR")
print("=" * 78)
for patron, esperado in CASOS:
    analisis = analizar_redos(patron)
    nivel = analisis[0] if analisis else "ninguno"
    marca = "ok " if nivel == esperado else "XX "
    print(f"{marca}{patron!r:26} nivel={nivel:12} -> {_arrancar(patron)}")

print()
print("=" * 78)
print("COSTE REAL DE CADA PATRON (entrada que NO casa, que es la que "
      "fuerza el backtracking)")
print("=" * 78)
for patron, _ in CASOS:
    if patron == r"\btk_[a-z0-9]{24}\b":
        continue
    for n in (1000, 10_000, 50_000):
        texto = "a" * n + "!"
        t0 = time.perf_counter()
        re.search(patron, texto)
        dt = time.perf_counter() - t0
        marca = " " if dt < 1 else "*"
        print(f"{marca} {patron!r:26} n={n:6} -> {dt:8.4f} s")
        if dt > 20:
            print("   (el patron cuelga: el proceso se quedaria enganchado)")
            break
    print()
