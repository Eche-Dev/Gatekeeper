"""El verificador de documentacion tiene que funcionar (y saber que funciona).

`tools/check_docs.py` se ejecuta en CI: si se rompe, el workflow falla, pero
si se rompe *mal* (sin avisar) deja pasar lo que deberia avisar. Estos tests
fijan su comportamiento con casos conocidos.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "check_docs.py"


def _carga():
    spec = importlib.util.spec_from_file_location("check_docs", SCRIPT)
    assert spec and spec.loader
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def test_el_verificador_pasa_sobre_el_repo_actual():
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_quitar_el_codigo_no_inventa_espacios_al_final():
    """Si no, el comprobador se detecta a si mismo."""
    modulo = _carga()
    limpio = modulo._sin_codigo("texto con `codigo` al final de la linea\n")
    for linea in limpio.splitlines():
        assert linea == linea.rstrip(), repr(linea)


def test_quitar_el_codigo_conserva_el_numero_de_lineas():
    modulo = _carga()
    texto = "uno\n```python\ndos\ntres\n```\ncuatro\n"
    limpio = modulo._sin_codigo(texto)
    assert len(limpio.splitlines()) == len(texto.splitlines())


def test_las_anchas_explicitas_se_reconocen():
    modulo = _carga()
    anclas = modulo._anclas("## Detrás de un proxy {#detras-de-un-proxy}\n")
    assert "detras-de-un-proxy" in anclas


def test_las_anchas_con_tilde_se_reconocen():
    modulo = _carga()
    anclas = modulo._anclas("## Notas de migración\n")
    assert "notas-de-migración" in anclas


def test_el_regex_distingue_imagenes_de_enlaces():
    modulo = _carga()
    texto = "![img](a.png) y [enlace](b.md)"
    assert modulo.ENLACE_IMG.findall(texto) == ["a.png"]
    assert modulo.ENLACE.findall(texto) == ["b.md"]


def test_un_enlace_roto_se_detecta(tmp_path: Path):
    """Con un fichero de mentira, el verificador tiene que quejarse."""
    modulo = _carga()
    (tmp_path / "doc.md").write_text(
        "texto con [un enlace roto](no-existe.md) y otro [bueno](existe.md)\n",
        encoding="utf-8",
    )
    (tmp_path / "existe.md").write_text("## Titulo\n", encoding="utf-8")
    fallos, _ = modulo.comprobar([tmp_path / "doc.md"])
    assert any("enlace roto -> no-existe.md" in fallo for fallo in fallos), fallos
    assert not any("existe.md)" in fallo for fallo in fallos), fallos


def test_un_ancla_inexistente_se_detecta(tmp_path: Path):
    modulo = _carga()
    (tmp_path / "destino.md").write_text("## Un titulo\n", encoding="utf-8")
    (tmp_path / "doc.md").write_text("enlace [aqui](destino.md#ancla-que-no-existe)\n",
                                     encoding="utf-8")
    fallos, _ = modulo.comprobar([tmp_path / "doc.md"])
    assert any("ancla inexistente" in fallo for fallo in fallos), fallos


def test_una_errata_se_detecta(tmp_path: Path):
    modulo = _carga()
    (tmp_path / "doc.md").write_text("no se envia aThird parties\n", encoding="utf-8")
    fallos, _ = modulo.comprobar([tmp_path / "doc.md"])
    assert any("aThird parties" in fallo for fallo in fallos), fallos


def test_una_errata_citada_en_codigo_no_se_detecta(tmp_path: Path):
    """Citar la errata para explicar el arreglo no es tener la errata."""
    modulo = _carga()
    (tmp_path / "doc.md").write_text(
        "se corrigio `aThird parties` y `functionality`\n", encoding="utf-8"
    )
    fallos, _ = modulo.comprobar([tmp_path / "doc.md"])
    assert not fallos, fallos


def test_la_version_se_saca_del_pyproject():
    import tomllib

    modulo = _carga()
    datos = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = datos["project"]["version"]
    partes = version.split(".")
    assert len(partes) == 3 and all(p.isdigit() for p in partes)
    assert modulo.VERSION_DE_GATEKEEPER.search(f"Gatekeeper {version}")
