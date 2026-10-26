#!/usr/bin/env python3
"""Sondeo v2: patrones de minimo con el nombre de la dependencia en la frase.

El v1 media ruido: un parrafo que habla de Starlette y de Redis capturaba
"Redis >= 5.0" como si fuera un minimo de Starlette. Aqui cada patron exige
que el nombre de la dependencia aparezca en la MISMA frase, asi que el ruido
desaparece sin listas de excepciones.

Ademas comprueba que la comparacion de versiones no confunda 0.23 con 0.23.0.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

RAIZ = Path(__file__).resolve().parents[1]
PAQUETE = RAIZ / "gatekeeper-v0.3" / "gatekeeper"

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]

FICHEROS: list[Path] = sorted(PAQUETE.glob("*.md")) + sorted(
    (PAQUETE / "docs").rglob("*.md")
) + sorted((PAQUETE / "corpus").glob("*.md")) + [
    RAIZ / "README.md",
    RAIZ / "SECURITY.md",
    RAIZ / "CONTRIBUTING.md",
    RAIZ / "CODE_OF_CONDUCT.md",
]

V = r"(\d+(?:\.\d+)*)"


def patrones(dep: str) -> list[tuple[str, re.Pattern[str]]]:
    d = re.escape(dep)
    return [
        (
            "comparador",
            re.compile(rf"{d}[^|\n]{{0,40}}?(?:≥|>=)\s*{V}", re.I),
        ),
        (
            "o superior",
            re.compile(rf"{d}[^|\n]{{0,40}}?{V}\s*o\s+superior", re.I),
        ),
        (
            "minimo de",
            re.compile(rf"m[ií]nimo[^|\n]{{0,40}}?{d}[^|\n]{{0,30}}?{V}", re.I),
        ),
    ]


def pares(valor: str) -> tuple[int, ...]:
    return tuple(int(x) for x in valor.split("."))


def main() -> int:
    pyproject = tomllib.loads((PAQUETE / "pyproject.toml").read_text(encoding="utf-8"))
    for dep in pyproject["project"]["dependencies"]:
        nombre = re.split(r"[<>=!~\[]", dep)[0].strip()
        real = re.search(r">=\s*([\d.]+)", dep).group(1)
        real_pares = pares(real)
        print(f"=== {nombre} (pyproject dice >= {real}) ===")
        for ruta in FICHEROS:
            if not ruta.exists():
                continue
            texto = ruta.read_text(encoding="utf-8")
            for tipo, patron in patrones(nombre):
                for m in patron.finditer(texto):
                    valor = m.group(1)
                    ok = pares(valor)[:2] == real_pares[:2]
                    linea = texto.count("\n", 0, m.start()) + 1
                    rel = ruta.relative_to(RAIZ).as_posix()
                    marca = "  " if ok else "!!"
                    frag = " ".join(texto[m.start(): m.end() + 30].split())
                    print(f"{marca} {rel}:{linea} [{tipo}] {valor}  ::  {frag}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
