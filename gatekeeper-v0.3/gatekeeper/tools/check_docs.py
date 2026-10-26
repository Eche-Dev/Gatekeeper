#!/usr/bin/env python3
"""Comprueba que la documentacion no miente.

Tres cosas, y las tres se pueden comprobar de forma automatica:

1. **La version es la misma en todas partes.** El numero sale de
   `pyproject.toml` (que es lo que se publica en PyPI) y se comprueba en los
   sitios donde la version de Gatekeeper se nombra de forma explicita: la
   guia de instalacion, la tabla de versiones de SECURITY.md y el CHANGELOG.
   Un numero suelto no dice nada: "0.23.0" es Starlette y "3.14.8" es Python.
2. **Los enlaces internos existen.** Un enlace relativo a un fichero que no
   esta, o a un ancla que no existe, rompe la web y la ficha de PyPI.
3. **Higiene editorial.** Una lista de erratas que ya se colaron una vez y
   que no deben volver a colarse.

Salida: 0 si todo esta bien, 1 si hay algun fallo. Se ejecuta en CI.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[3]
PAQUETE = RAIZ / "gatekeeper-v0.3" / "gatekeeper"

# Ficheros que se vigilan: la documentacion del paquete y los del repo.
FICHEROS: list[Path] = sorted(PAQUETE.glob("*.md")) + sorted(
    (PAQUETE / "docs").rglob("*.md")
) + sorted((PAQUETE / "corpus").glob("*.md")) + [
    RAIZ / "README.md",
    RAIZ / "SECURITY.md",
    RAIZ / "CONTRIBUTING.md",
    RAIZ / "CODE_OF_CONDUCT.md",
]

# El CHANGELOG y las notas de version hablar de versiones viejas es lo
# correcto: son un registro historico.
HISTORICOS = {"CHANGELOG.md", "SECURITY_REVIEW.md", "ARTICLE.md"}

# Erratas que ya se colaron (auditria B-9) y palabras inglesas sin traducir.
HIGIENE: list[tuple[str, str]] = [
    (r"aThird parties", "falta el espacio en «aThird parties»"),
    (r"\bfunctionality\b", "anglicismo: «functionality»"),
    (r"\bconsequences\b", "anglicismo: «consequences»"),
    (r"exímino", "«exímino» no es una palabra"),
    (r"\bangel98dev26@gmail\.com\b", "email personal: usa GitHub Security Advisories"),
    (r"[ \t]+$", "espacios al final de la linea"),
]

ENLACE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
ENLACE_IMG = re.compile(r"!\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

# Version de Gatekeeper nombrada de forma explicita: "Gatekeeper 0.7.0",
# "gatekeeper-asgi 0.7.0", "Gatekeeper v0.7.0"... Exige los TRES componentes:
# "Gatekeeper v0.3" habla de la carpeta del repo, no de una version.
VERSION_DE_GATEKEEPER = re.compile(
    r"(?i)gatekeeper[ -]?(?:asgi)?[ ,:]*(?:v)?(\d+\.\d+\.\d+)\b"
)
# La frase que dice que version esta publicada en PyPI.
VERSION_PUBLICA = re.compile(r"La versi[oó]n publicada es la \*\*(\d+\.\d+)\.x\*\*")
# La rama que SECURITY.md declara activa.
RAMA_ACTIVA = re.compile(r"^\|\s*(\d+\.\d+)\.x\s*\|\s*\*\*Activa\*\*", re.M)
# La primera entrada de version del CHANGELOG.
ENTRADA_CHANGELOG = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.M)


def _sin_codigo(texto: str) -> str:
    """Quita el codigo (bloques y `inline`) conservando los numeros de linea.

    Se usa para la higiene y para las versiones: una errata citada dentro de
    un bloque de codigo no es una errata, y un numero dentro de un ejemplo no
    es la version del paquete.

    El codigo inline se sustituye por una cadena de la MISMA longitud que no
    sean espacios: si no, una linea terminada en codigo inline pareceria
    tener espacios al final y el propio comprobador se detectaria a si mismo.
    """
    def bloque(match: re.Match[str]) -> str:
        return "\n" * match.group(0).count("\n")

    # El `^[ \t]*` se lleva la indentacion del bloque: si no, la linea de
    # apertura se queda con sus espacios y parece un trailing space.
    texto = re.sub(r"(?m)^[ \t]*```.*?```", bloque, texto, flags=re.S)
    texto = re.sub(r"`[^`\n]*`", lambda m: "z" * len(m.group(0)), texto)
    return texto


def _anclas(texto: str) -> set[str]:
    """Anclas estilo GitHub (que es lo que usa mkdocs para los titulos)."""
    salida: set[str] = set()
    for linea in texto.splitlines():
        match = re.match(r"^(#{1,6})\s+(.*)$", linea)
        if not match:
            continue
        titulo = match.group(2).strip()
        explicito = re.search(r"\{#([^}]+)\}", titulo)
        if explicito:
            salida.add(explicito.group(1).lower())
            continue
        titulo = re.sub(r"`([^`]*)`", r"\1", titulo)
        titulo = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", titulo)
        titulo = titulo.rstrip("#").strip().lower()
        slug = re.sub(r"[^\w\- ]", "", titulo, flags=re.UNICODE)
        slug = slug.replace(" ", "-")
        salida.add(slug)
    return salida


def _cache_anclas(ficheros: list[Path]) -> dict[Path, set[str]]:
    cache: dict[Path, set[str]] = {}
    for ruta in ficheros:
        if ruta.exists() and ruta.suffix == ".md":
            cache[ruta.resolve()] = _anclas(ruta.read_text(encoding="utf-8"))
    return cache


def _nombre(ruta: Path) -> str:
    try:
        return ruta.resolve().relative_to(RAIZ).as_posix()
    except ValueError:
        return ruta.name


def comprobar_fichero(
    ruta: Path,
    anclas: dict[Path, set[str]],
    version: str,
    mayor: int,
    menor: int,
) -> list[str]:
    """Comprueba un fichero. Devuelve la lista de fallos (vacia si esta bien)."""
    fallos: list[str] = []
    texto = ruta.read_text(encoding="utf-8")
    limpio = _sin_codigo(texto)
    rel = _nombre(ruta)
    historico = ruta.name in HISTORICOS or ruta.name.startswith("RELEASE_NOTES_")

    # 1. version (solo donde se nombra a Gatekeeper)
    if not historico:
        for encontrado in VERSION_DE_GATEKEEPER.findall(limpio):
            if encontrado != version:
                fallos.append(
                    f"{rel}: dice que Gatekeeper es la {encontrado} y la real es {version}"
                )

    # 2. enlaces
    for patron in (ENLACE, ENLACE_IMG):
        for destino in patron.findall(texto):
            if destino.startswith(("http://", "https://", "mailto:", "#", "tel:")):
                continue
            ruta_rel, _, ancla = destino.partition("#")
            if not ruta_rel:
                continue
            objetivo = (ruta.parent / ruta_rel).resolve()
            if not objetivo.exists():
                fallos.append(f"{rel}: enlace roto -> {destino}")
                continue
            if ancla and objetivo.suffix == ".md":
                if ancla not in anclas.get(objetivo, set()):
                    fallos.append(f"{rel}: ancla inexistente -> {destino}")

    # 3. higiene
    for patron, mensaje in HIGIENE:
        for match in re.finditer(patron, limpio, flags=re.M):
            linea = limpio[: match.start()].count("\n") + 1
            fallos.append(f"{rel}:{linea}: {mensaje}")

    return fallos


def comprobar(ficheros: list[Path] | None = None) -> tuple[list[str], str]:
    """Comprueba la documentacion. Devuelve (fallos, version)."""
    try:
        import tomllib
    except ImportError:  # Python 3.10 no tiene tomllib (esta en 3.11+)
        import tomli as tomllib  # type: ignore[no-redef]

    pyproject = tomllib.loads((PAQUETE / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    mayor, menor = (int(x) for x in version.split(".")[:2])

    ficheros = FICHEROS if ficheros is None else ficheros
    fallos: list[str] = []
    anclas = _cache_anclas(ficheros)

    for ruta in ficheros:
        if not ruta.exists():
            continue
        fallos.extend(comprobar_fichero(ruta, anclas, version, mayor, menor))

    # --- la version publicada tiene que ser la real
    instalacion = PAQUETE / "docs" / "instalacion.md"
    if instalacion.exists():
        texto = instalacion.read_text(encoding="utf-8")
        for encontrada in VERSION_PUBLICA.findall(texto):
            if encontrada != f"{mayor}.{menor}":
                fallos.append(
                    f"docs/instalacion.md: dice que la version publicada es la "
                    f"{encontrada}.x y la real es {version}"
                )

    # --- la rama activa de SECURITY.md tiene que ser la actual
    security = PAQUETE / "SECURITY.md"
    if security.exists():
        texto = security.read_text(encoding="utf-8")
        activas = RAMA_ACTIVA.findall(texto)
        if not activas:
            fallos.append("SECURITY.md: no dice que rama esta activa")
        elif activas[0] != f"{mayor}.{menor}":
            fallos.append(
                f"SECURITY.md: la rama activa es la {activas[0]}.x y la version "
                f"publicada es {version}"
            )

    # --- la primera entrada del CHANGELOG tiene que ser la version actual
    changelog = PAQUETE / "CHANGELOG.md"
    if changelog.exists():
        texto = changelog.read_text(encoding="utf-8")
        entradas = ENTRADA_CHANGELOG.findall(texto)
        if entradas and entradas[0] != version:
            fallos.append(
                f"CHANGELOG.md: la primera entrada es la {entradas[0]} y la version "
                f"publicada es {version}"
            )

    return fallos, version


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:  # pragma: no cover
        pass

    fallos, version = comprobar()

    if fallos:
        print(f"FALLOS ({len(fallos)}):")
        for fallo in fallos:
            print(f"  - {fallo}")
        return 1

    print(
        f"Documentacion coherente: version {version}, enlaces y anclas correctos, "
        f"higiene sin erratas ({len(FICHEROS)} ficheros vigilados)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
