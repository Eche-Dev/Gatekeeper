#!/usr/bin/env python3
"""Mide las reglas propias de semgrep en las DOS direcciones.

Con el codigo bueno tiene que dar 0 hallazgos. Con el bug metido a proposito
tiene que dar el hallazgo. Una regla que no suena con el bug presente no
esta vigilando nada; una que suena de mas acaba ignorandose.

Los bugs se meten en ficheros aparte (no se toca el codigo del paquete): lo
que se comprueba es que la regla ve el patron, no que el codigo lo tenga.
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

# (nombre, regla que debe saltar, codigo del bug)
CASOS: list[tuple[str, str, str]] = [
    (
        "f-string en el log",
        "gatekeeper-log-con-interpolacion",
        """
import logging

logger = logging.getLogger("gatekeeper")


def aviso(valor):
    logger.warning(f"valor: {valor}")
""",
    ),
    (
        "regex sin cota",
        "gatekeeper-regex-sin-cota",
        """
import re

PATRON = re.compile(r"\\s*")
""",
    ),
    (
        "bloqueante en async def",
        "gatekeeper-bloqueante-en-el-event-loop",
        """
import time


async def esperar():
    time.sleep(1)
""",
    ),
    (
        "confiar en el proxy",
        "gatekeeper-confiar-en-el-proxy-por-defecto",
        """
def construir():
    return Config(trust_proxy=True)
""",
    ),
]


def escanear(destino: Path) -> list[tuple[str, int]]:
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
        print(proc.stdout[-2000:])
        print(proc.stderr[-2000:])
        raise SystemExit("semgrep no devolvio JSON")
    for error in datos.get("errors", []):
        print("error de semgrep:", json.dumps(error, ensure_ascii=False)[:400])
    return [
        (r.get("check_id", "?"), r.get("start", {}).get("line", 0))
        for r in datos.get("results", [])
    ]


def main() -> int:
    fallos: list[str] = []

    # 1) El codigo real no puede dar hallazgos.
    print("1) codigo del paquete")
    actuales = escanear(PAQUETE / "src")
    for check, linea in actuales:
        print(f"   - {check}  linea {linea}")
    if actuales:
        fallos.append(f"el codigo del paquete da {len(actuales)} hallazgos (deberia dar 0)")
    else:
        print("   0 hallazgos")

    # 2) Cada bug tiene que ser detectado por su regla.
    print("\n2) cada bug, con su regla")
    with tempfile.TemporaryDirectory() as tmp:
        for nombre, regla, codigo in CASOS:
            caso = Path(tmp) / f"caso_{nombre.replace(' ', '_')}.py"
            caso.write_text(codigo, encoding="utf-8")
            hallazgos = escanear(caso)
            reglas = {c for c, _ in hallazgos}
            salta = any(regla in c for c in reglas)
            marca = "OK " if salta else "FALLA"
            print(f"   [{marca}] {nombre}: {regla} -> {len(hallazgos)} hallazgo(s)")
            if not salta:
                fallos.append(f"la regla {regla} no detecta: {nombre}")

    print()
    for fallo in fallos:
        print(f"ERROR: {fallo}")
    if not fallos:
        print("Las 4 reglas vigilan: 0 con el codigo bueno y saltan con su bug.")
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
