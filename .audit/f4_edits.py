"""Fase 4 - ediciones textuales puntuales (con verificacion de que casan).

Cada par (viejo, nuevo) se comprueba antes de escribir: si el texto no
aparece tal cual, el script avisa y NO toca el fichero. Es a proposito: una
edicion silenciosa que no casa es una edicion que no pasa.
"""
from __future__ import annotations

import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
PKG = RAIZ / "gatekeeper-v0.3" / "gatekeeper"

EDICIONES: list[tuple[str, str, str]] = [
    # --- instalacion.md: la version publicada
    (
        "gatekeeper-v0.3/gatekeeper/docs/instalacion.md",
        "La versión publicada es la **0.4.x** (la carpeta del repositorio se llama\n"
        "`v0.3` por razones históricas). El paquete se publica con *Trusted Publishing*\n"
        "y lleva **provenance verificado** por GitHub: en la ficha de PyPI verás que\n"
        "todos los ficheros se subieron con metadatos de provenance firmados.",
        "La versión publicada es la **0.7.x** (la carpeta del repositorio se llama\n"
        "`v0.3` por razones históricas; el número exacto de cada versión está en el\n"
        "[CHANGELOG](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/CHANGELOG.md)).\n"
        "El paquete se publica con *Trusted Publishing* y lleva **provenance\n"
        "verificado** por GitHub: en la ficha de PyPI verás que todos los ficheros\n"
        "se subieron con metadatos de provenance firmados.",
    ),
    (
        "gatekeeper-v0.3/gatekeeper/docs/instalacion.md",
        '!!! warning "0.4.0 tiene un DoS de disponibilidad corregido en 0.4.1"\n'
        "    La 0.4.0 bloqueaba el event loop con una petición grande y sin\n"
        "    autenticación. **Actualiza a 0.4.1 o superior.** Detalle y PoC en",
        '!!! warning "La 0.4.0 tenía un DoS de disponibilidad, corregido en la 0.4.1"\n'
        "    La 0.4.0 (la primera publicación) bloqueaba el event loop con una\n"
        "    petición grande y sin autenticación. **Usa 0.4.1 o superior** (la\n"
        "    recomendada es la última). Detalle y PoC en",
    ),
    # --- instalacion.md: el extra `dev` no se ofrece a usuarios finales
    (
        "gatekeeper-v0.3/gatekeeper/docs/instalacion.md",
        "| `gatekeeper-asgi[yaml]` | PyYAML | Quieres `Config.from_yaml(\"gatekeeper.yaml\")` |\n"
        "| `gatekeeper-asgi[redis]` | redis | Rate limit compartido entre workers |\n"
        "| `gatekeeper-asgi[dev]` | herramientas de desarrollo | Contribuyes al proyecto |\n"
        "| `gatekeeper-asgi[servers]` | hypercorn, daphne | Pruebas con servidores ASGI reales |",
        "| `gatekeeper-asgi[yaml]` | PyYAML | Quieres `Config.from_yaml(\"gatekeeper.yaml\")` |\n"
        "| `gatekeeper-asgi[redis]` | redis | Rate limit compartido entre workers |\n"
        "| `gatekeeper-asgi[servers]` | hypercorn, daphne | Pruebas con servidores ASGI reales |",
    ),
    (
        "gatekeeper-v0.3/gatekeeper/docs/instalacion.md",
        "El núcleo solo depende de `starlette` (cualquier versión ≥ 0.23; FastAPI ya la\n"
        "incluye).",
        "El núcleo solo depende de `starlette` (cualquier versión ≥ 0.23; FastAPI ya la\n"
        "incluye).\n"
        "\n"
        "!!! info \"El extra `dev` existe, pero no se ofrece a quien instala\"\n"
        "    `pip install \"gatekeeper-asgi[dev]\"` arrastra pytest, mypy, bandit, ruff,\n"
        "    hypothesis, mkdocs y más: es para **contribuir al proyecto**, no para\n"
        "    instalar el WAF. En producción, el núcleo (o `yaml`/`redis`) es todo lo\n"
        "    que necesitas.",
    ),
    # --- pyproject: fuera el email personal de los metadatos
    (
        "gatekeeper-v0.3/gatekeeper/pyproject.toml",
        'authors = [{ name = "Ángel David Echenique Villanueva", email = "angel98dev26@gmail.com" }]\n'
        'maintainers = [{ name = "Ángel David Echenique Villanueva", email = "angel98dev26@gmail.com" }]',
        "# Sin email en los metadatos: PyPI lo muestra en la ficha y el aviso\n"
        "# de privacidad no lo cubre. El canal de contacto es GitHub\n"
        "# Security Advisories (ver SECURITY.md).\n"
        'authors = [{ name = "Ángel David Echenique Villanueva" }]\n'
        'maintainers = [{ name = "Ángel David Echenique Villanueva" }]',
    ),
    (
        "gatekeeper-v0.3/gatekeeper/pyproject.toml",
        '  "Programming Language :: Python :: 3.13",\n',
        '  "Programming Language :: Python :: 3.13",\n'
        '  "Programming Language :: Python :: 3.14",\n',
    ),
    (
        "gatekeeper-v0.3/gatekeeper/pyproject.toml",
        "# Sin cota superior en starlette a propósito: se verificó que los 247 tests\n"
        "# pasan con 0.37 (el mínimo declarado) y con 1.9 (la actual), así que acotarla",
        "# Sin cota superior en starlette a propósito: se verificó que la suite\n"
        "# completa pasa con 0.23 (el mínimo declarado) y con la última, así que acotarla",
    ),
    # --- CODE_OF_CONDUCT: el contacto por el canal privado del repo
    (
        "CODE_OF_CONDUCT.md",
        "Si presientes o sufres un comportamiento inaceptable, repórtalo escribiendo a\n"
        "**angel98dev26@gmail.com**. Todas las quejas se revisarán y investigarán con",
        "Si presientes o sufres un comportamiento inaceptable, repórtalo por el canal\n"
        "privado del repo (**Security Advisories**, en la pestaña *Security*): es\n"
        "privado y solo lo ve quien mantiene el proyecto. Todas las quejas se\n"
        "revisarán e investigarán con",
    ),
    # --- README: el numero de valores del corpus
    (
        "gatekeeper-v0.3/gatekeeper/README.md",
        "escaneo con y sin pre filtro sobre los 1787 valores de ambos corpus (payloads",
        "escaneo con y sin pre filtro sobre los 2086 valores de ambos corpus (payloads",
    ),
    # --- desarrollo.md: ya se publica en PyPI
    (
        "gatekeeper-v0.3/gatekeeper/docs/desarrollo.md",
        "Se filtra el paquete local porque hasta la primera publicación no está en PyPI\n"
        "y `--strict` sale con error por eso, que no es una vulnerabilidad sino que el\n"
        "paquete aún no existe.",
        "Se filtra el paquete local porque `gatekeeper-asgi` ya está publicado en\n"
        "PyPI y `--strict` sale con error al encontrarlo instalado en editable desde\n"
        "el repo. Eso no es una vulnerabilidad: es el paquete local.",
    ),
    # --- demo/README: ya se publica en PyPI
    (
        "gatekeeper-v0.3/gatekeeper/demo/README.md",
        "`requirements.txt` instala Gatekeeper desde el repo (aún no está en PyPI) y\n"
        "`vercel.json` apunta al runtime de Python. Sale en `tu-proyecto.vercel.app`.",
        "`requirements.txt` instala Gatekeeper desde el repo (para probar el demo con\n"
        "el código local; en producción, `pip install gatekeeper-asgi` desde PyPI) y\n"
        "`vercel.json` apunta al runtime de Python. Sale en `tu-proyecto.vercel.app`.",
    ),
    # --- enlaces que el verificador de documentacion encontro rotos
    (
        "gatekeeper-v0.3/gatekeeper/docs/despliegue.md",
        "## Detrás de un proxy inverso\n",
        "## Detrás de un proxy inverso {#detras-de-un-proxy-inverso}\n",
    ),
    (
        "gatekeeper-v0.3/gatekeeper/SECURITY.md",
        "Usa [GitHub Security Advisories](../../security/advisories/new) para reportar de",
        "Usa [GitHub Security Advisories](https://github.com/Eche-Dev/Gatekeeper/security/advisories/new) para reportar de",
    ),
    (
        "gatekeeper-v0.3/gatekeeper/SECURITY.md",
        "[uso](gatekeeper-v0.3/gatekeeper/docs/uso.md)",
        "[uso](docs/uso.md)",
    ),
    # --- el ejemplo del proceso de release no puede llevar una version real
    (
        "gatekeeper-v0.3/gatekeeper/docs/compatibilidad.md",
        '3. **Etiquetar**: `git tag -a v0.4.1 -m "Gatekeeper 0.4.1"` y subirlo\n'
        "   (`git push origin v0.4.1`).",
        '3. **Etiquetar**: `git tag -a vX.Y.Z -m "Gatekeeper X.Y.Z"` y subirlo\n'
        "   (`git push origin vX.Y.Z`).",
    ),
    (
        "gatekeeper-v0.3/gatekeeper/docs/compatibilidad.md",
        "la CLI con `gh release create v0.4.1`). El workflow `publicar.yml` construye",
        "la CLI con `gh release create vX.Y.Z`). El workflow `publicar.yml` construye",
    ),
]


def main() -> int:
    # la consola de Windows no siempre puede imprimir el texto (cp1252)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:  # pragma: no cover - Python < 3.7
        pass

    fallos = 0
    for relativo, viejo, nuevo in EDICIONES:
        ruta = RAIZ / relativo
        texto = ruta.read_text(encoding="utf-8")
        if viejo not in texto:
            if nuevo in texto:
                print(f"YA ESTA {relativo}")
                continue
            print(f"NO CASA  {relativo}: {viejo.splitlines()[0][:70]}")
            fallos += 1
            continue
        if texto.count(viejo) != 1:
            print(f"AMBIGUO {relativo} ({texto.count(viejo)} veces): "
                  f"{viejo.splitlines()[0][:70]}")
            fallos += 1
            continue
        ruta.write_text(texto.replace(viejo, nuevo), encoding="utf-8")
        print(f"OK      {relativo}: {viejo.splitlines()[0][:60]}")
    if fallos:
        print(f"\n{fallos} edicion(es) sin aplicar")
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(main())
