"""Cierres de la Fase 2 que no son presupuestos ni log (Fase 2.5).

Cuatro cosas:

1. El puntero JSON a 64 niveles **perdia el segmento nuevo**: la atribucion
   apuntaba al padre y `exclude_fields` (que compara por el ultimo
   segmento) no casaba con el campo real.
2. Dos patrones de inyeccion SQL estaban en la familia `sensitive_files`, de
   modo que `disabled_rules=["sqli"]` no los apagaba.
3. La documentacion nombraba un evento (`rl_backend_unavailable`) que el
   middleware nunca emitia, y describia cuerpos de error que no eran los
   reales. Estos tests son la red que evita que la deriva vuelva.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.body import _iter_fields
from gatekeeper.rules import RULES, scan

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


async def _ok(request):
    return PlainTextResponse("ok")


def _app(**cfg):
    cfg.setdefault("rate_limit", 0)
    app = Starlette(routes=[Route("/{path:path}", _ok, methods=["GET", "POST"])])
    return GatekeeperMiddleware(app, Config(**cfg))


# ------------------------------------------------- el puntero JSON profundo


def _json_profundo(niveles: int, hoja: str = "hoja"):
    obj = {f"n{niveles}": hoja}
    for i in range(niveles - 1, 0, -1):
        obj = {f"n{i}": obj}
    return obj


def test_el_puntero_profundo_apunta_al_campo_real():
    """A 80 niveles, el puntero acaba en el campo que salta.

    Antes perdia el segmento nuevo: el puntero acababa en el padre, asi que
    la atribucion era falsa.
    """
    campos = [(p, v) for p, v, _ in _iter_fields(_json_profundo(80))]
    punteros = [p for p, v in campos if v == "hoja"]
    assert punteros, "no se ha encontrado el campo hoja"
    assert punteros[0].endswith("/n80"), punteros[0]
    assert "…" in punteros[0], "el corte deberia estar marcado"
    assert punteros[0].startswith("/n1"), "la clave exterior deberia conservarse"


def test_a_64_niveles_ya_apunta_al_campo_real():
    """El limite es 64: justo en el limite, el puntero tiene que ser correcto."""
    campos = [(p, v) for p, v, _ in _iter_fields(_json_profundo(64))]
    punteros = [p for p, v in campos if v == "hoja"]
    assert punteros[0].endswith("/n64"), punteros[0]


def test_exclude_fields_casa_en_profundidad():
    """Un campo exento a 70 niveles tiene que quedar exento de verdad.

    `exclude_fields` compara por el ultimo segmento: si el puntero pierde el
    segmento final, la exencion no casa y el campo se bloquea igual.
    """
    app = _app(exclude_fields=["n70"])
    with TestClient(app) as client:
        r = client.post(
            "/x",
            content=json.dumps(_json_profundo(70)).encode(),
            headers={"content-type": "application/json"},
        )
    assert r.status_code == 200, r.text


def test_sin_exencion_el_campo_profundo_sigue_bloqueando():
    """El arreglo del puntero no puede abrir un agujero: sin exencion, 403."""
    app = _app()
    with TestClient(app) as client:
        r = client.post(
            "/x",
            content=json.dumps(
                {"n1": {f"n{i}": {"x": "1' or '1'='1"} for i in range(2, 70)}}
            ).encode(),
            headers={"content-type": "application/json"},
        )
    assert r.status_code == 403, r.text


# ------------------------------------------------- los SQLi en su familia


def test_los_patrones_de_sqli_estan_en_la_familia_sqli():
    """`union all` y el `or ...` de la ruta son SQLi, no ficheros sensibles."""
    assert scan("/union all") == "sqli"
    assert scan("/or 'and") == "sqli"


def test_desactivar_sqli_apaga_de_verdad_los_patrones_de_la_ruta():
    """El bug: con `disabled_rules=["sqli"]` seguian detectandose."""
    config = Config(disabled_rules={"sqli"})
    assert scan("/union all", config.disabled_rules) is None
    assert scan("/or 'and", config.disabled_rules) is None
    # Y con la familia activa, se detectan.
    assert scan("/union all") == "sqli"


def test_la_familia_sensitive_files_sigue_detectando_lo_suyo():
    """Mover los SQLi no debe habitar un agujero en la otra familia."""
    assert scan("/etc/shadow") == "sensitive_files"
    assert scan("/var/www/app/.env") == "sensitive_files"


def test_no_hay_patrones_duplicados_en_la_misma_familia():
    """Estaba duplicado el patron de logs dentro de `sensitive_files`."""
    for nombre, patrones in RULES.items():
        vistos = [p.pattern for p in patrones]
        duplicados = {p for p in vistos if vistos.count(p) > 1}
        assert not duplicados, f"{nombre}: {duplicados}"


# ------------------------------------------- la documentacion no inventa


def _ficheros_doc():
    return sorted(DOCS.glob("*.md")) + [ROOT / "README.md", ROOT / "SECURITY.md"]


def test_la_doc_no_nombra_eventos_que_no_existen():
    """`rl_backend_unavailable` no lo emitia nadie: el evento real es otro."""
    for ruta in _ficheros_doc():
        texto = ruta.read_text(encoding="utf-8")
        assert "rl_backend_unavailable" not in texto, ruta.name


def test_los_cuerpos_de_error_documentados_son_los_reales():
    """Lo que dice la tabla de `docs/api.md` es lo que responde el middleware."""
    doc = (DOCS / "api.md").read_text(encoding="utf-8")
    esperados = {}
    for linea in doc.splitlines():
        m = re.match(r"\|\s*`(\d{3})`\s*\|\s*`(\{[^`]+\})`", linea)
        if m:
            esperados[m.group(1)] = json.loads(m.group(2))
    assert {"429", "413", "503"} <= set(esperados), esperados

    # 429 de verdad
    app = _app(rate_limit=1, rate_window=60)
    with TestClient(app) as client:
        client.get("/x")
        r = client.get("/x")
    assert r.status_code == 429
    assert r.json() == esperados["429"], (r.json(), esperados["429"])

    # 413 de verdad (el presupuesto de campos)
    app = _app(max_fields=2)
    with TestClient(app) as client:
        r = client.post("/x", content=json.dumps({"a": 1, "b": 2, "c": 3}).encode(),
                        headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert r.json() == esperados["413"], (r.json(), esperados["413"])


def test_el_cuerpo_del_503_es_el_real():
    """El 503 de Redis caido dice `Service Unavailable`."""
    from gatekeeper import middleware

    texto = Path(middleware.__file__).read_text(encoding="utf-8")
    assert '"Service Unavailable"' in texto, texto[:200]
