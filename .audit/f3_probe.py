"""Verificacion de los FN y FP de la Fase 3 (deteccion).

Para cada caso: que regla dispara (o que ninguna) y si el resultado es el
esperado. Es la evidencia de la que salen las correcciones: primero se
muestra, despues se arregla.

Uso (desde ``gatekeeper-v0.3/gatekeeper``)::

    python .audit/f3_probe.py
"""
from __future__ import annotations

import sys

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")

from gatekeeper.rules import scan_detailed

# (etiqueta, payload, familia_esperada_o_None, que_hemos_querido)
CASOS = [
    # --- Falsos negativos: hoy NO se detectan y deberian detectarse --------
    ("FN tautologia con comillas vacias", "' or ''=", "sqli", "detectar"),
    ("FN booleano ciego (substring invertida)",
     "substring(version(),1,1)=5", "sqli", "detectar"),
    ("FN cmdi con salto de linea (sin separador)",
     "foo\nrm -rf /", "cmdi", "detectar"),
    ("FN SSRF: IP de metadata en decimal",
     "http://2852039166/admin", "ssrf", "detectar"),
    ("FN SSRF: IP de metadata en hex",
     "http://0xa9fea9fe/admin", "ssrf", "detectar"),
    ("FN SSRF: IP de metadata en octal",
     "http://0252.0376.0252.0376/admin", "ssrf", "detectar"),
    # --- Falsos positivos: hoy SI se detectan y no deberian ----------------
    ("FP <script> en prosa",
     "En el manual pone: <script> para incrustar codigo", None, "no detectar"),
    ("FP sleep(8 hours) en prosa",
     "La consulta sleep(8 hours) devuelve un error de sintaxis", None, "no detectar"),
    ("FP union en prosa (sindicalismo)",
     "el sindicalismo unido union workers", None, "no detectar"),
    # --- Referencias: casos que NO deben cambiar --------------------------
    ("REF tautologia normal", "' or '1'='1", "sqli", "detectar"),
    ("REF blind boolean clasico", "ASCII(SUBSTRING(user,1,1))>64", "sqli", "detectar"),
    ("REF sleep numerico", "1 AND SLEEP(5)", "sqli", "detectar"),
    ("REF script real", "<script>alert(1)</script>", "xss", "detectar"),
    ("REF cmdi con separador", "; rm -rf /", "cmdi", "detectar"),
    ("REF metadata dotted", "http://169.254.169.254/latest/meta-data/", "ssrf", "detectar"),
]


def main() -> None:
    fallos = 0
    for etiqueta, payload, esperado, quiero in CASOS:
        hit = scan_detailed(payload)
        detectado = hit[0] if hit else None
        regla = hit[1] if hit else "-"
        if quiero == "detectar":
            ok = detectado == esperado
        else:
            ok = detectado is None
        marca = "ok " if ok else "XX "
        if not ok:
            fallos += 1
        muestra = payload.replace("\n", "\\n")
        print(f"{marca}{etiqueta}")
        print(f"     payload   : {muestra!r}")
        print(f"     detectado : {detectado!r} (regla: {regla!r})")
        print(f"     esperado  : {esperado!r} [{quiero}]")
    print()
    print(f"{len(CASOS) - fallos}/{len(CASOS)} en el estado esperado "
          f"({fallos} por arreglar)")


if __name__ == "__main__":
    main()
