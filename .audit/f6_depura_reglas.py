#!/usr/bin/env python3
"""Segunda ronda de depuracion: la excepcion del `$` en R2 y R4 con el
fichero de reglas real (a ver si el problema es la config o el patron).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
SEMGREP = RAIZ / ".audit" / "venv-sast" / "Scripts" / "semgrep.exe"
REGLAS_REAL = RAIZ / "gatekeeper-v0.3" / "gatekeeper" / "tools" / "semgrep_rules.yml"

CASO_REGEX_MALO = """
import re

PATRON = re.compile(r"\\s*")
"""

CASO_REGEX_BONO = """
import re

PATRON = re.compile(r"\\s*$")
"""

CASO_PROXY = """
def f():
    return Config(trust_proxy=True)
"""

CUANTIFICADORES = r"(\\s\*|\\S\*|\\w\*|\\W\*|\\d\*|\\D\*|\.\*|\.\+|\{[0-9]+,\})"

VARIANTES: list[tuple[str, str, str, str | None]] = [
    (
        "R2 con excepcion del $",
        CASO_REGEX_MALO,
        """
rules:
  - id: prueba
    languages: [python]
    severity: ERROR
    message: prueba
    patterns:
      - pattern-inside: re.compile(...)
      - pattern-regex: '__CUANT__([^\\$]|$)'
      - pattern-not-regex: '__CUANT__\\$'
""".replace("__CUANT__", CUANTIFICADORES),
        "prueba",
        None,
    ),
    (
        "R2 excepcion: el $ no debe marcar",
        CASO_REGEX_BONO,
        """
rules:
  - id: prueba
    languages: [python]
    severity: ERROR
    message: prueba
    patterns:
      - pattern-inside: re.compile(...)
      - pattern-regex: '__CUANT__([^\\$]|$)'
      - pattern-not-regex: '__CUANT__\\$'
""".replace("__CUANT__", CUANTIFICADORES),
        "prueba",
        None,
    ),
    (
        "R4 con el fichero de reglas real",
        CASO_PROXY,
        "",
        "prueba",
    ),
]


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        temporal = Path(tmp)
        for variante in VARIANTES:
            etiqueta, caso, yml = variante[0], variante[1], variante[2]
            fichero = temporal / "caso.py"
            fichero.write_text(caso, encoding="utf-8")
            if yml:
                regla = temporal / "regla.yml"
                regla.write_text(yml, encoding="utf-8")
                config = str(regla)
            else:
                config = str(REGLAS_REAL)
            proc = subprocess.run(
                [
                    str(SEMGREP),
                    "scan",
                    "--config",
                    config,
                    "--metrics=off",
                    "--no-git-ignore",
                    "--json",
                    str(fichero),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            try:
                datos = json.loads(proc.stdout)
            except json.JSONDecodeError:
                print(f"{etiqueta}: semgrep no devolvio JSON")
                print(proc.stdout[-800:], proc.stderr[-800:])
                continue
            n = len(datos.get("results", []))
            marca = "OK   " if n > 0 else "FALLA"
            print(f"[{marca}] {etiqueta}: {n} hallazgo(s)")
            for r in datos.get("results", []):
                print(f"        {r.get('check_id')}  linea {r.get('start', {}).get('line')}")
            for error in datos.get("errors", []):
                mensaje = error.get("long_msg") or error.get("message") or str(error)
                print(f"        error: {str(mensaje)[:300]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
