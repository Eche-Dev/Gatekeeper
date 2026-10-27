"""Mide la cobertura del paquete y deja el informe en `.audit/cov_detallada.txt`.

Es el volcado de la fase 7 (cobertura por modulo): el informe se commitea
para que se pueda comparar sin volver a ejecutar la suite.

Uso:
    python .audit/mide_cobertura.py            # mide y escribe el informe
    python .audit/mide_cobertura.py --mostrar  # ademas lo enseña por pantalla
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

RAIZ = Path(r"D:\ADEV\ProyectosVScode\Gatekeeper")
PAQUETE = RAIZ / "gatekeeper-v0.3" / "gatekeeper"
INFORME = RAIZ / ".audit" / "cov_detallada.txt"

COMANDO = [
    sys.executable, "-m", "pytest",
    "--cov=gatekeeper", "--cov-report=term-missing", "--cov-precision=2",
    "-q", "-p", "no:cacheprovider",
]


def main(argv: list[str]) -> int:
    proceso = subprocess.run(
        COMANDO, cwd=PAQUETE, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    salida = proceso.stdout + proceso.stderr
    INFORME.write_text(salida, encoding="utf-8")
    if "--mostrar" in argv:
        print(salida)
    else:
        print(f"informe escrito en {INFORME}")
        for linea in salida.splitlines():
            if "TOTAL" in linea or "passed" in linea:
                print(linea)
    return proceso.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
