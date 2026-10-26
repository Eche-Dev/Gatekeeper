"""La API publica: lo que `import gatekeeper` tiene que exponer.

Este archivo es la garantia de que la documentacion no miente. Si la doc
dice que `gatekeeper.scan` existe, tiene que existir; si la doc lista los
nombres de `__all__`, tienen que ser los mismos y todos importables.
"""
from __future__ import annotations

import importlib
import re
from pathlib import Path

import gatekeeper


def _version_del_pyproject() -> str:
    texto = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    encontrado = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', texto)
    return encontrado.group(1) if encontrado else "desconocida"


def test_lo_que_dice_el_dunder_all_se_puede_importar():
    for nombre in gatekeeper.__all__:
        assert hasattr(gatekeeper, nombre), f"{nombre} esta en __all__ pero no existe"


def test_la_lista_de_nombres_publicos_es_la_documentada():
    """Si esto cambia, hay que actualizar docs/api.md en el mismo commit."""
    esperados = {
        "Config",
        "GatekeeperMiddleware",
        "PACK_NAMES",
        "RULES",
        "resolve_rules",
        "scan",
        "scan_all",
        "scan_detailed",
    }
    assert set(gatekeeper.__all__) == esperados


def test_las_familias_de_reglas_y_los_packs_estan_expuestos():
    assert "sqli" in gatekeeper.RULES
    assert "xss" in gatekeeper.RULES
    assert isinstance(gatekeeper.PACK_NAMES, tuple)
    assert "web" in gatekeeper.PACK_NAMES
    assert gatekeeper.resolve_rules() >= {"sqli", "xss"}


def test_scan_devuelve_la_familia_que_detecta():
    assert gatekeeper.scan("1' OR '1'='1") == "sqli"
    assert gatekeeper.scan("<script>alert(1)</script>") == "xss"
    assert gatekeeper.scan("/search?q=como+se+hace+una+consulta") is None


def test_scan_all_recorre_valores_y_devuelve_la_primera_coincidencia():
    """El nombre puede confundir: "all" viene de que recorre TODOS los valores."""
    assert gatekeeper.scan_all(["/search?q=normal", "1' OR '1'='1"]) == "sqli"
    assert gatekeeper.scan_all(["/search?q=normal", "/otra?ruta=normal"]) is None


def test_scan_detailed_devuelve_la_familia_y_su_regla():
    familia, regla = gatekeeper.scan_detailed("1' OR '1'='1")
    assert familia == "sqli"
    assert isinstance(regla, str) and regla


def test_la_version_leida_del_fuente_es_la_del_pyproject():
    """Sin el paquete instalado, la version sale del pyproject.toml."""
    from gatekeeper import _version_desde_fuente

    assert _version_desde_fuente() == _version_del_pyproject()


def test_el_modulo_se_puede_recargar():
    """Recargar el modulo no debe romperse (lo hacen los tests de cobertura)."""
    importlib.reload(gatekeeper)
    assert gatekeeper.__version__
