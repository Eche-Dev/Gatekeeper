"""Compara dos volcados de deteccion (formato de diff_deteccion.py).

Uso:
    python .audit/compara.py antes.txt despues.txt
"""
from __future__ import annotations

import sys
from pathlib import Path


def _carga(ruta: str) -> dict[str, str]:
    salida: dict[str, str] = {}
    for linea in Path(ruta).read_text(encoding="utf-8").splitlines():
        if not linea.strip():
            continue
        partes = linea.split("\t")
        if len(partes) >= 4:
            salida[partes[0]] = partes[3]
    return salida


def main() -> int:
    antes = _carga(sys.argv[1])
    despues = _carga(sys.argv[2])
    ids = sorted(set(antes) | set(despues))

    perdidos, ganados, cambiados = [], [], []
    for id_ in ids:
        a, d = antes.get(id_, "-"), despues.get(id_, "-")
        if a != "-":
            if d == "-":
                perdidos.append(id_)
            elif a != d:
                cambiados.append((id_, a, d))
        elif d != "-":
            ganados.append(id_)

    print(f"{sys.argv[1]} -> {sys.argv[2]}")
    print(f"  casos: {len(ids)}  perdidos: {len(perdidos)}  "
          f"ganados: {len(ganados)}  familia cambiada: {len(cambiados)}")
    for id_ in perdidos[:40]:
        print(f"  PERDIDO {id_} (antes: {antes[id_]})")
    for id_ in ganados[:40]:
        print(f"  GANADO  {id_} (ahora: {despues[id_]})")
    for id_, a, d in cambiados[:40]:
        print(f"  CAMBIA  {id_}: {a} -> {d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
