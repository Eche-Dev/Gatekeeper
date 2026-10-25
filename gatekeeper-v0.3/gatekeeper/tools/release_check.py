"""Ayuda a decidir la version y preparar el release.

SemVer y este caso concreto:
- el minimo de Starlette BAJA (0.37 -> 0.23): eso es un AMPLIAMENTO de lo
  soportado, no una rotura. Nadie se rompe por que una dependencia tenga un
  minimo mas bajo.
- las cabeceras de seguridad ahora tambien van en los rechazos: es un
  CAMBIO DE COMPORTAMIENTO, pero solo anade cabeceras. Nadie que dependa de
  su ausencia se rompe (y si dependia, era un bug).
- se anaden features, corpus, guias y herramientas: MINOR.
- no se quita nada de la API publica: no hay nada que deprecate todavia.

Conclusión: MINOR -> 0.4.0.

El salto a 0.4.0 (y no 0.3.2) tiene una razon ademas: es la PRIMERA version
que se publica en PyPI. Una 0.3.x nueva tampoco estaria en PyPI, y las
notas de migracion de 0.3.0 yaspoken de cosas que nunca vio un usuario de
PyPI. Empezar la serie publicada en 0.4.0 deja claro que 0.3.x fue
"pre-PyPI".
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"


def version_actual() -> str:
    import tomllib

    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def breaking_changes() -> list[str]:
    """Busca en el CHANGELOG 'Sin publicar' cambios que rompan compatibilidad."""
    texto = CHANGELOG.read_text(encoding="utf-8")
    bloque = texto.split("## [Sin publicar]", 1)[1].split("\n## [", 1)[0]
    patrones = [
        r"romp", r"breaking", r"incompatib", r"deprecad", r"elimina", r"quita",
    ]
    for linea in bloque.splitlines():
        linea = linea.strip()
        if not linea.startswith("-"):
            continue
        if any(re.search(p, linea, re.IGNORECASE) for p in patrones):
            yield linea


def main() -> int:
    v = version_actual()
    print(f"Version actual: {v}")
    print()

    print("Cambios que mencionan rotura:")
    encontrados = list(breaking_changes())
    if encontrados:
        for linea in encontrados:
            print(f"  - {linea[:100]}")
    else:
        print("  (ninguno explicitamente)")
    print()

    print("Analisis SemVer:")
    print("  MINOR (0.4.0) si:")
    print("    - hay features nuevas            -> SI")
    print("    - hay cambios de comportamiento    -> SI (cabeceras en los rechazos)")
    print("    - se amplia el minimo soportado    -> SI (Starlette 0.23)")
    print("    - se rompe la API publica         -> NO")
    print("    - se deprecia algo                -> NO")
    print()
    print("  PATCH (0.3.2) solo si:")
    print("    - solo fixes sin cambios de comportamiento ni features")
    print()
    print("  Recomendacion: 0.4.0 (ademas es la primera publicacion en PyPI)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
