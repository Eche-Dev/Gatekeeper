"""Los workflows de CI tienen que ser YAML VALIDO, y sus pasos tienen que existir.

Un `:` sin comillas en el nombre de un paso rompe el YAML entero, y el
workflow falla ANTES de ejecutar nada: GitHub no ve ningun job, el pipeline
sale en rojo y no hay tests que lo expliquen. Es un fallo silencioso de
configuracion, y por eso tiene su propio test.

Tambien se comprueba que cada `run:` que ejecuta un script de `tools/` o
`tests/` apunte a un archivo que existe: un script renombrado deja el CI
llamando a un archivo que ya no esta, y el fallo aparece tarde y sin contexto.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"
PROJECT = ROOT / "gatekeeper-v0.3" / "gatekeeper"


@pytest.mark.parametrize("workflow", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_el_workflow_es_yaml_valido(workflow: Path):
    """Si el YAML no parsea, GitHub no crea ningun job y el CI no dice por que."""
    with workflow.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert data, f"{workflow.name} esta vacio"
    assert "jobs" in data, f"{workflow.name} no define jobs"
    assert data["jobs"], f"{workflow.name} no tiene jobs"


@pytest.mark.parametrize("workflow", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_los_jobs_tienen_pasos(workflow: Path):
    """Un job sin pasos no hace nada."""
    with workflow.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    for nombre, job in data["jobs"].items():
        assert job.get("steps"), f"{workflow.name}: el job {nombre} no tiene pasos"
        for paso in job["steps"]:
            assert "uses" in paso or "run" in paso, (
                f"{workflow.name}: el job {nombre} tiene un paso sin uses ni run"
            )


@pytest.mark.parametrize("workflow", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_los_scripts_invocados_existen(workflow: Path):
    """Cada `python tools/x.py` o `pytest tests/x.py` debe apuntar a algo real.

    No todos los workflows invocan scripts (el de docs solo construye el
    sitio), asi que solo se comprueban los que lo hacen.
    """
    with workflow.open(encoding="utf-8") as fh:
        texto = fh.read()

    encontrados = re.findall(r"(?:tools|tests)/[\w\-/]+\.py", texto)
    for relativo in set(encontrados):
        assert (PROJECT / relativo).exists(), (
            f"{workflow.name} invoca {relativo}, que no existe"
        )


def test_el_job_de_test_cubre_las_versiones_de_python_soportadas():
    """La matriz de Python del CI tiene que incluir todas las soportadas."""
    with (WORKFLOWS / "ci.yml").open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    versiones = data["jobs"]["test"]["strategy"]["matrix"]["python"]
    assert versiones == ["3.10", "3.11", "3.12", "3.13"], versiones


def test_los_cuatro_evaluadores_estan_en_ci():
    """Cada corpus tiene su guarda: si uno no se ejecuta, su cifra no se vigila."""
    with (WORKFLOWS / "ci.yml").open(encoding="utf-8") as fh:
        texto = fh.read()
    for script in (
        "tools/evaluate.py",
        "tools/evaluate_heldout.py",
        "tools/evaluate_cross.py",
        "tools/evaluate_cross.py --heldout",
        "tools/import_crs.py",
    ):
        assert script in texto, f"{script} no se ejecuta en CI"


def test_el_job_de_redis_levanta_un_servicio():
    """El job de Redis tiene que levantar Redis de verdad, no un mock."""
    with (WORKFLOWS / "ci.yml").open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    job = data["jobs"]["redis"]
    assert "services" in job, "el job de redis no define servicios"
    assert "redis" in job["services"]
    # La imagen tiene que estar fijada por version: `redis:latest` puede
    # cambiar de comportamiento entre dos ejecuciones del workflow.
    imagen = job["services"]["redis"]["image"]
    assert ":" in imagen and not imagen.endswith(":latest"), (
        f"la imagen de Redis deberia ir fijada por version, no es {imagen!r}"
    )
