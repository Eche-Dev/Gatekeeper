"""Banco de coste: mide si normalize()/scan() escalan de forma lineal o cuadratica.

Cada medicion se ejecuta en un PROCESO SEPARADO con timeout duro, para que un
ReDoS real no cuelgue la auditoria.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

CHILD = r"""
import json, os, sys, time
sys.path.insert(0, os.environ["GK_SRC"])
from gatekeeper.rules import normalize, scan
payload_kind = sys.argv[1]
size = int(sys.argv[2])
if payload_kind == "unclosed":
    text = "/*a" * (size // 3)
elif payload_kind == "benign":
    text = ('{"user": "nombre", "note": "texto normal sin ataque", "n": 1, ' * (size // 55))[:size]
elif payload_kind == "versioned":
    text = "/*!50000" * (size // 8)
else:
    raise SystemExit("kind desconocido")
t0 = time.perf_counter()
scan("/?q=" + text)
dt = time.perf_counter() - t0
print(json.dumps({"seconds": dt, "bytes": len(text)}))
"""

TIMEOUT = 180


def measure(kind: str, size: int) -> dict:
    t0 = time.perf_counter()
    env = dict(os.environ)
    env["GK_SRC"] = os.environ.get(
        "GK_SRC",
        r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src",
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", CHILD, kind, str(size)],
            capture_output=True, text=True, timeout=TIMEOUT, env=env,
        )
    except subprocess.TimeoutExpired:
        return {"kind": kind, "bytes": size, "seconds": None, "timeout": True,
                "wall": time.perf_counter() - t0}
    wall = time.perf_counter() - t0
    if proc.returncode != 0:
        return {"kind": kind, "bytes": size, "seconds": None, "error": proc.stderr[-400:],
                "wall": wall}
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    data.update({"kind": kind, "wall": wall, "timeout": False})
    return data


def main() -> None:
    print("== normalize()/scan() con '/*a' repetido (comentario SQL sin cerrar) ==")
    print(f"{'bytes':>10} {'segundos':>12} {'x tamano':>10} {'x tiempo':>10}")
    prev = None
    rows = []
    for size in (8_000, 16_000, 32_000, 64_000, 128_000):
        r = measure("unclosed", size)
        rows.append(r)
        if r.get("seconds") is None:
            print(f"{size:>10} {'TIMEOUT' if r.get('timeout') else 'ERROR':>12}")
            break
        xs = f"{r['seconds'] / prev['seconds']:.2f}" if prev else "-"
        xb = f"{size / prev['bytes']:.2f}" if prev else "-"
        print(f"{size:>10} {r['seconds']:>12.3f} {xb:>10} {xs:>10}")
        prev = r

    print()
    print("== Mismo trafico pero con un payload BENIGNO de 1 MiB (coste legitimo) ==")
    r = measure("benign", 1_048_576)
    print(json.dumps(r, indent=2))

    print()
    print("== Comentarios versionados '/*!50000' repetidos (con cierre implícito al final) ==")
    prev = None
    for size in (16_000, 32_000, 64_000, 128_000):
        r = measure("versioned", size)
        if r.get("seconds") is None:
            print(f"{size:>10} {'TIMEOUT' if r.get('timeout') else 'ERROR':>12}")
            break
        xs = f"{r['seconds'] / prev['seconds']:.2f}" if prev else "-"
        print(f"{size:>10} {r['seconds']:>12.3f} {xs:>10}")
        prev = r


if __name__ == "__main__":
    main()
