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
    RAIZ / "AUDITORIA-IA-COMPARATIVA.md",
    RAIZ / "PLAN-CIERRE-97.md",
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
# La frase que dice que version esta publicada en PyPI (con o sin negritas).
VERSION_PUBLICA = re.compile(
    r"La versi[oó]n publicada es la \*{0,2}(\d+\.\d+)\.x"
)
# La rama que SECURITY.md declara activa.
RAMA_ACTIVA = re.compile(r"^\|\s*(\d+\.\d+)\.x\s*\|\s*\*\*Activa\*\*", re.M)
# La primera entrada de version del CHANGELOG.
ENTRADA_CHANGELOG = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.M)

# --- minimos de las dependencias del nucleo ---------------------------------
# Un numero suelto no dice nada: "0.23" es Starlette y "3.14" es Python. Lo
# que se comprueba es la AFIRMACION de un minimo, y cada afirmacion tiene que
# nombrar a la dependencia en su propia frase.
#
# Sin esta comprobacion la portada de la web anunciaba "Starlette >= 0.37"
# mientras pyproject declaraba 0.23: el minimo ANTIGUO, que era
# precisamente el que rompia a quien usara FastAPI 0.103.x (CHANGELOG de la
# 0.4.0). El verificador de versiones no lo cazaba porque compara la version
# de Gatekeeper, no la de sus dependencias.
VERSION_NUM = r"(\d+(?:\.\d+)*)"

# Dependencias que se citan en la documentacion y que NO son el nucleo. Si uno
# de estos nombres aparece entre el nombre de la dependencia y su minimo, ese
# numero es de otra dependencia ("redis >= 5.0" cerca de "starlette").
OTRAS_DEPENDENCIAS = ("fastapi", "redis", "pydantic", "httpx", "uvicorn", "yaml")


def _patrones_minimo(dep: str) -> list[tuple[str, re.Pattern[str]]]:
    """Patrones que afirman un minimo de `dep` en su propia frase."""
    d = re.escape(dep)
    return [
        (
            "comparador",
            re.compile(rf"{d}[^|\n]{{0,25}}?(?:≥|>=)\s*{VERSION_NUM}", re.I),
        ),
        (
            "o superior",
            re.compile(rf"{d}[^|\n]{{0,25}}?{VERSION_NUM}\s*o\s+superior", re.I),
        ),
        (
            "minimo de",
            re.compile(
                rf"m[ií]nimo[^|\n]{{0,25}}?{d}[^|\n]{{0,25}}?{VERSION_NUM}", re.I
            ),
        ),
    ]


def _pares(version: str) -> tuple[int, ...]:
    """("0.23.0") -> (0, 23, 0). Se comparan los dos primeros componentes."""
    return tuple(int(x) for x in version.split("."))


def _comprobar_minimos(ficheros: list[Path], dependencias: list[str]) -> list[str]:
    """El minimo que dice la documentacion tiene que ser el que se instala."""
    fallos: list[str] = []
    for dep in dependencias:
        nombre = re.split(r"[<>=!~\[]", dep)[0].strip()
        encontrado = re.search(r">=\s*([\d.]+)", dep)
        if not nombre or not encontrado:
            continue
        real = _pares(encontrado.group(1))
        for ruta in ficheros:
            if not ruta.exists():
                continue
            if ruta.name in HISTORICOS or ruta.name.startswith("RELEASE_NOTES_"):
                continue  # un registro historico puede citar el minimo antiguo
            texto = ruta.read_text(encoding="utf-8")
            # Los enlaces markdown se vacian: la URL entre el nombre de la
            # dependencia y su minimo no es parte de la frase.
            limpio = re.sub(r"\]\([^)]*\)", "]", texto)
            for _tipo, patron in _patrones_minimo(nombre):
                for coincidencia in patron.finditer(limpio):
                    fragmento = limpio[coincidencia.start(): coincidencia.start(1)]
                    if any(
                        re.search(rf"\b{re.escape(otra)}\b", fragmento, re.I)
                        for otra in OTRAS_DEPENDENCIAS
                    ):
                        continue  # ese numero es de otra dependencia
                    if _pares(coincidencia.group(1))[:2] == real[:2]:
                        continue
                    linea = limpio.count("\n", 0, coincidencia.start()) + 1
                    fallos.append(
                        f"{_nombre(ruta)}:{linea}: dice que el minimo de {nombre} es "
                        f"{coincidencia.group(1)} y pyproject declara "
                        f"{encontrado.group(1)}"
                    )
    return fallos


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
        for encontrada in VERSION_PUBLICA.findall(limpio):
            if encontrada != f"{mayor}.{menor}":
                fallos.append(
                    f"{rel}: dice que la version publicada es la {encontrada}.x "
                    f"y la real es {version}"
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

    # --- el minimo de cada dependencia es el que dice pyproject
    fallos.extend(
        _comprobar_minimos(ficheros, pyproject["project"]["dependencies"])
    )

    # --- la version publicada se comprueba fichero a fichero (arriba)
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
        f"minimos de dependencias correctos, higiene sin erratas "
        f"({len(FICHEROS)} ficheros vigilados)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
