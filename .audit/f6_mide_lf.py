#!/usr/bin/env python3
"""Reproduce el escaneo tal y como lo ve ubuntu (ficheros con LF).

En local el working copy esta en CRLF (core.autocrlf) y el checkout de GitHub
Actions esta en LF. Si el escaneo falla solo en el CI, la diferencia son los
finales de linea: este script copia el codigo a un temporal, lo pasa a LF y
escanea eso.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
PAQUETE = RAIZ / "gatekeeper-v0.3" / "gatekeeper"
SEMGREP = RAIZ / ".audit" / "venv-sast" / "Scripts" / "semgrep.exe"
REGLAS = PAQUETE / "tools" / "semgrep_rules.yml"


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        destino = Path(tmp) / "src"
        shutil.copytree(PAQUETE / "src", destino)
        # A LF, como el checkout de GitHub Actions.
        for fichero in destino.rglob("*.py"):
            texto = fichero.read_bytes().replace(b"\r\n", b"\n")
            fichero.write_bytes(texto)
        print("copiado y pasado a LF")

        proc = subprocess.run(
            [
                str(SEMGREP),
                "scan",
                "--config",
                str(REGLAS),
                "--metrics=off",
                "--no-git-ignore",
                "--json",
                str(destino),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            datos = json.loads(proc.stdout)
        except json.JSONDecodeError:
            print("semgrep no devolvio JSON:")
            print(proc.stdout[-2000:])
            print(proc.stderr[-2000:])
            return 1
        for error in datos.get("errors", []):
            print("error:", json.dumps(error, ensure_ascii=False)[:400])
        resultados = datos.get("results", [])
        print(f"hallazgos: {len(resultados)}")
        for r in resultados:
            print(f"   - {r.get('check_id')}  {r.get('path')}:{r.get('start', {}).get('line')}")
            extra = r.get("extra", {})
            if extra.get("lines"):
                print(f"       {extra['lines'].strip()[:120]}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
