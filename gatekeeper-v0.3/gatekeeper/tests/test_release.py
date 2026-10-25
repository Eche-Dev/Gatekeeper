"""La release tiene que ser coherente: version, changelog y tag.

Un release a medias es un bug de proceso: el paquete dice una version, el
CHANGELOG dice otra, y el tag apunta a otra. Eso se detecta tarde, cuando ya
hay un artefacto publicado.

Este test comprueba lo que se puede comprobar sin red:
- la version de pyproject.toml coincide con la del CHANGELOG;
- la seccion "Sin publicar" esta vacia tras una release (o tiene contenido si
  hay trabajo en curso);
- el workflow de publicacion verifica el tag contra la version (para que un tag
  equivocado no publique una version que no es);
- los metadatos del paquete son coherentes con lo que se documenta.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
WORKFLOW = REPO / ".github" / "workflows" / "publicar.yml"


def _proyecto() -> dict:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)


def _changelog() -> str:
    return CHANGELOG.read_text(encoding="utf-8")


def test_la_version_del_paquete_coincide_con_la_del_changelog():
    """La version de `pyproject.toml` tiene que ser la ultima del CHANGELOG."""
    version = _proyecto()["project"]["version"]
    texto = _changelog()

    # La primera seccion con fecha (la que no es "Sin publicar") es la ultima
    # version released.
    secciones = re.findall(r"^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})$", texto, re.M)
    assert secciones, "el CHANGELOG no tiene ninguna version con fecha"
    ultima = secciones[0][0]
    assert version == ultima, (
        f"pyproject.toml dice {version} y el CHANGELOG dice {ultima}"
    )


def test_la_seccion_sin_publicar_no_tiene_contenido_tras_un_release():
    """Tras un release, "Sin publicar" está vacía (o dice que no hay nada)."""
    texto = _changelog()
    bloque = texto.split("## [Sin publicar]", 1)[1].split("\n## [", 1)[0]
    lineas = [x.strip() for x in bloque.splitlines() if x.strip()]
    assert not lineas or lineas == ["Nada pendiente."], (
        f"la seccion 'Sin publicar' tiene contenido sin publicar: {lineas}"
    )


def test_la_primera_version_publicada_empieza_en_0_4():
    """0.3.x fue "pre-PyPI"; la serie publicada empieza en 0.4.0.

    Documentarlo evita la confusion de "instalo gatekeeper-asgi==0.3.1 y no
    existe" (0.3.x nunca se publico en PyPI).
    """
    version = _proyecto()["project"]["version"]
    assert version.startswith("0.4."), (
        f"la version es {version}; la serie publicada deberia empezar en 0.4.x"
    )


def test_el_workflow_verifica_el_tag_contra_la_version():
    """Un tag equivocado no debe poder publicar una version que no es."""
    texto = WORKFLOW.read_text(encoding="utf-8")
    assert "GITHUB_REF_NAME" in texto, "el workflow no lee el nombre del tag"
    assert "pyproject.toml" in texto, "el workflow no compara con pyproject.toml"
    assert "exit 1" in texto, "el workflow no falla si el tag no coincide"


def test_el_workflow_no_tiene_tokens_de_pypi_en_secrets():
    """La publicacion usa Trusted Publishing: no hay ningun token guardado."""
    texto = WORKFLOW.read_text(encoding="utf-8")
    # Ni `secrets.PYPI_TOKEN` ni `password:` con un token de PyPI.
    assert "secrets.PYPI_TOKEN" not in texto
    assert "pypi-ApiToken" not in texto


def test_el_nombre_del_paquete_es_el_esperado():
    """El nombre en PyPI es `gatekeeper-asgi` (el corto `gatekeeper` ya existe)."""
    assert _proyecto()["project"]["name"] == "gatekeeper-asgi"


def test_la_licencia_y_el_autor_coinciden_con_la_documentacion():
    """Los metadatos del paquete tienen que ser los del repositorio."""
    proyecto = _proyecto()["project"]
    assert proyecto["license"] == "MIT"
    assert proyecto["authors"], "falta el autor"
    assert proyecto["urls"]["Repository"], "falta la URL del repositorio"
    assert proyecto["urls"]["Changelog"], "falta la URL del CHANGELOG"
    assert proyecto["urls"]["Issues"], "falta la URL de los issues"


def test_la_version_importada_coincide_con_la_del_paquete():
    """`gatekeeper.__version__` tiene que ser la version del paquete.

    REGRESION: `__version__` estaba escrita a mano y se quedo en "0.3.1"
    cuando el paquete paso a 0.4.0: el wheel instalado decia 0.4.0 y
    `import gatekeeper; gatekeeper.__version__` decia 0.3.1. Se publico
    durante el desarrollo, antes de llegar a PyPI.
    """
    import gatekeeper

    assert gatekeeper.__version__ == _proyecto()["project"]["version"], (
        f"gatekeeper.__version__ dice {gatekeeper.__version__} y el paquete "
        f"es {_proyecto()['project']['version']}"
    )


def test_la_version_no_esta_escrita_a_mano():
    """La version no puede volver a quedarse desfasada.

    Se comprueba que el modulo la SACA de los metadatos, no que la tenga
    escrita: si alguien vuelve a poner `__version__ = "0.4.1"`, este test
    sigue viniendo bien, pero la RELEASE_NOTES y el CHANGELOG ya no
    quadrarian con el paquete.
    """
    fuente = (ROOT / "src" / "gatekeeper" / "__init__.py").read_text(encoding="utf-8")
    # Buscar una asignacion DIRECTA de __version__ a un literal (no a una
    # llamada a _version()).
    asignacion_directa = re.search(
        r"^\s*__version__\s*=\s*[\"']\d", fuente, re.M
    )
    assert asignacion_directa is None, (
        "la version esta escrita a mano: leela de los metadatos del paquete"
    )


def test_existe_el_fichero_de_notas_de_la_version():
    """Cada versión publicada tiene sus release notes."""
    version = _proyecto()["project"]["version"]
    notas = ROOT / f"RELEASE_NOTES_{version}.md"
    assert notas.exists(), f"faltan las release notes de {version}: {notas.name}"
    texto = notas.read_text(encoding="utf-8")
    assert f"Gatekeeper {version}" in texto, "las notas no dicen la version"
    # Y tienen que cubrir la migracion, que es lo que se busca al actualizar.
    assert "Migración" in texto, "las notas no tienen sección de migración"


@pytest.mark.parametrize("fichero", ["SECURITY.md", "README.md"])
def test_los_ficheros_de_soporte_existen_y_no_estan_vacios(fichero: str):
    """SECURITY.md y README.md son parte del contrato con el usuario."""
    ruta = ROOT / fichero
    assert ruta.exists(), f"falta {fichero}"
    assert len(ruta.read_text(encoding="utf-8")) > 500, f"{fichero} esta vacio"
