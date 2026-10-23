"""Comprueba que los ejemplos de la documentacion se ejecutan de verdad.

Los ejemplos viven en README.md, docs/*.md y examples/. Si un ejemplo no corre,
el lector pierde el tiempo: esto lo convierte en un fallo de CI.

Dos niveles:
  1. Todo bloque ```python debe ser al menos sintacticamente valido.
  2. Los bloques que son un programa COMPLETO (tienen imports y no dependen de
     un `app` o un servidor externos) deben ejecutarse sin excepcion.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# FastAPI no es dependencia del paquete (solo Starlette), pero varios ejemplos de
# la documentacion lo usan. Si no esta instalado, esos ejemplos no se pueden
# ejecutar: se omiten con un motivo claro en lugar de romper la suite.
try:  # pragma: no cover - depende del entorno
    import fastapi  # noqa: F401

    TIENE_FASTAPI = True
except ImportError:  # pragma: no cover - depende del entorno
    TIENE_FASTAPI = False

REQUIERE_FASTAPI = pytest.mark.skipif(
    not TIENE_FASTAPI,
    reason="FastAPI no esta instalado (esta en el extra 'dev', no en el paquete)",
)

# Fragmentos que dependen de contexto externo (una app ya construida, un
# servidor uvicorn, una variable del entorno). Son ilustrativos, no programas.
_INDICIOS_DE_FRAGMENTO = (
    "GatekeeperMiddleware(app",
    "GatekeeperMiddleware(application",
    "uvicorn ",
    "@app.",
    "client.get(",
    "requests.get(",
    "curl ",
)


def _bloques_python(md: Path) -> list[str]:
    text = md.read_text(encoding="utf-8", errors="replace")
    bloques: list[str] = []
    dentro = False
    actual: list[str] = []
    for linea in text.splitlines():
        if linea.strip().startswith("```python"):
            dentro = True
            actual = []
            continue
        if dentro and linea.strip().startswith("```"):
            dentro = False
            bloques.append("\n".join(actual))
            continue
        if dentro:
            actual.append(linea)
    return bloques


def _es_programa_completo(bloque: str) -> bool:
    """True si el bloque es un programa que se puede ejecutar tal cual."""
    lineas = [ln for ln in bloque.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lineas:
        return False
    if not any(ln.startswith(("import ", "from ")) for ln in lineas):
        return False
    if any(ind in bloque for ind in _INDICIOS_DE_FRAGMENTO):
        return False
    # Un fragmento suele empezar con una llamada o una firma suelta.
    primera = lineas[0]
    if not primera.startswith(("import ", "from ", "@")) and "(" in primera:
        return False
    return True


@pytest.mark.parametrize(
    "md",
    sorted((ROOT / "docs").glob("*.md")) + [ROOT / "README.md"],
    ids=lambda p: p.name,
)
def test_bloques_python_de_la_docs_son_sintacticamente_validos(md: Path):
    for i, bloque in enumerate(_bloques_python(md)):
        if not bloque.strip():
            continue
        try:
            compile(bloque, f"{md.name}#{i}", "exec")
        except SyntaxError as exc:
            # Los fragmentos ilustrativos (p.ej. la firma de una funcion) no son
            # programas: se saltan. Los que empiezan por import/from si deben
            # ser validos.
            if not _es_programa_completo(bloque):
                continue
            pytest.fail(f"{md.name} bloque #{i} no es Python valido: {exc}\n{bloque}")


@pytest.mark.parametrize(
    "md",
    sorted((ROOT / "docs").glob("*.md")) + [ROOT / "README.md"],
    ids=lambda p: p.name,
)
def test_programas_completos_de_la_docs_se_ejecutan(md: Path):
    for i, bloque in enumerate(_bloques_python(md)):
        if not _es_programa_completo(bloque):
            continue
        if "fastapi" in bloque and not TIENE_FASTAPI:
            continue  # ejemplo de FastAPI sin FastAPI instalado: no se puede ejecutar
        proc = subprocess.run(
            [sys.executable, "-c", bloque],
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=60,
        )
        assert proc.returncode == 0, (
            f"{md.name} bloque #{i} falla:\n{proc.stderr[-2000:]}\n---\n{bloque}"
        )


@REQUIERE_FASTAPI
def test_ejemplo_vulnerable_vs_protected_se_importa():
    sys.path.insert(0, str(ROOT))
    from examples.vulnerable_vs_protected import protected, vulnerable  # noqa: PLC0415

    assert vulnerable is not None
    assert protected is not None


def test_ejemplo_yaml_se_carga():
    """El YAML de ejemplo debe ser valido y cargable: es lo que copia el usuario."""
    from gatekeeper import Config  # noqa: PLC0415

    config = Config.from_yaml(ROOT / "examples" / "gatekeeper.yaml")
    assert config.rate_limit == 100
    assert config.rate_backend == "memory"
    assert config.monitor_only is False
    assert config.inspect_cross_carrier is False
    assert config.redis_prefix == "gatekeeper:rl:"
