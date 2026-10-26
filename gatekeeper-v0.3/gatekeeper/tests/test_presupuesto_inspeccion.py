"""Presupuesto de inspeccion: campos y tiempo (Fase 2.2).

El limite de tamano del body NO acota el trabajo de inspeccion: el coste
escala con el numero de CAMPOS (~67 us por campo), no con los bytes. Medido
en la auditoria: 20.000 campos costaban 1,34 s de CPU en una sola peticion,
y el `max_body_size` no los cubria.

Aqui se fija el contrato:

- al superar `max_fields`, la peticion se RECHAZA con 413 (no se ignoran
  campos: ignorarlos seria un bypass);
- al superar `max_inspection_ms`, tambien 413 (no hay fail-open: un
  presupuesto agotado a proposito seria una forma de saltarse la deteccion);
- el presupuesto se AGOTA en el limite, no despues: el trabajo se corta.
"""
from __future__ import annotations

import json
import logging
import time

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.body import InspectionBudget, InspectionTimeout, TooManyFields


async def _ok(request):
    return PlainTextResponse("ok")


def make_app(**cfg_kwargs):
    app = Starlette(routes=[Route("/{path:path}", _ok, methods=["GET", "POST"])])
    return GatekeeperMiddleware(app, Config(**cfg_kwargs))


def _json_con_campos(n: int) -> bytes:
    return json.dumps({f"campo{i}": "x" for i in range(n)}).encode()


# ------------------------------------------------------- el presupuesto


def test_el_presupuesto_cuenta_los_campos():
    """Cada texto inspeccionado cuenta: una clave y su valor son dos."""
    presupuesto = InspectionBudget(max_fields=10)
    presupuesto.cuenta(5)
    assert presupuesto.campos == 5
    presupuesto.cuenta(5)
    assert presupuesto.campos == 10


def test_al_superar_los_campos_salta_la_excepcion():
    presupuesto = InspectionBudget(max_fields=3)
    with pytest.raises(TooManyFields):
        presupuesto.cuenta(4)


def test_el_presupuesto_sin_limite_no_salta():
    presupuesto = InspectionBudget(max_fields=0)
    for _ in range(10_000):
        presupuesto.cuenta()
    assert presupuesto.campos == 10_000


def test_el_reloj_del_presupuesto_es_inyectable():
    """Con un reloj falso, el final del plazo es determinista."""
    ahora = [0.0]
    presupuesto = InspectionBudget(max_ms=100, clock=lambda: ahora[0])
    ahora[0] = 0.05
    presupuesto.comprueba_tiempo()  # todavia dentro del plazo
    ahora[0] = 0.2
    with pytest.raises(InspectionTimeout):
        presupuesto.comprueba_tiempo()


def test_reiniciar_el_reloj_no_cuenta_la_espera():
    """Esperar por la red no es inspeccionar: el reloj se reinicia."""
    ahora = [0.0]
    presupuesto = InspectionBudget(max_ms=100, clock=lambda: ahora[0])
    ahora[0] = 50.0  # como si el body hubiera tardado 50 s en llegar
    presupuesto.reinicia_reloj()
    presupuesto.comprueba_tiempo()  # no salta: el plazo es nuevo


# ------------------------------------------------- en el middleware (HTTP)


def test_muchos_campos_dan_413():
    """Un cuerpo con mas campos de los permitidos se rechaza."""
    app = make_app(max_fields=100)
    with TestClient(app) as client:
        r = client.post("/x", content=_json_con_campos(200),
                        headers={"content-type": "application/json"})
    assert r.status_code == 413, r.text


def test_el_limite_de_campos_es_inclusivo():
    """En el limite exacto se admite: el tope es inclusivo."""
    app = make_app(max_fields=4)  # 2 campos JSON = 4 textos (clave + valor)
    with TestClient(app) as client:
        r = client.post("/x", content=_json_con_campos(2),
                        headers={"content-type": "application/json"})
    assert r.status_code == 200, r.text


def test_sin_limite_de_campos_no_se_rechaza():
    app = make_app(max_fields=0)
    with TestClient(app) as client:
        r = client.post("/x", content=_json_con_campos(500),
                        headers={"content-type": "application/json"})
    assert r.status_code == 200, r.text


def test_el_evento_de_campos_se_audita(caplog):
    app = make_app(max_fields=10)
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        with TestClient(app) as client:
            client.post("/x", content=_json_con_campos(100),
                        headers={"content-type": "application/json"})
    eventos = [json.loads(r.message) for r in caplog.records if r.name == "gatekeeper"]
    codes = [e["event"] for e in eventos]
    assert "too_many_fields" in codes, eventos
    evento = next(e for e in eventos if e["event"] == "too_many_fields")
    assert evento["limite"] == 10
    assert evento["campos"] > 10


def test_veintiseis_mil_campos_se_rechazan_rapido():
    """El criterio de aceptacion del plan: 26.000 campos -> 413, y pronto.

    No basta con devolver 413: si el middleware tardase un segundo en darlo,
    el atacante ya habria gastado la CPU que queria gastar.
    """
    app = make_app(max_fields=1000)
    cuerpo = _json_con_campos(26_000)
    inicio = time.perf_counter()
    with TestClient(app) as client:
        r = client.post("/x", content=cuerpo,
                        headers={"content-type": "application/json"})
    elapsed = time.perf_counter() - inicio
    assert r.status_code == 413, r.text
    assert elapsed < 2.0, f"tardo {elapsed:.2f} s en rechazar"


def test_el_tiempo_de_inspeccion_agotado_da_413():
    """Si se supera `max_inspection_ms`, la peticion se rechaza (no se pasa)."""
    app = make_app(max_fields=0, max_inspection_ms=1)
    with TestClient(app) as client:
        r = client.post("/x", content=_json_con_campos(5_000),
                        headers={"content-type": "application/json"})
    assert r.status_code == 413, r.text


def test_el_evento_de_tiempo_se_audita(caplog):
    app = make_app(max_fields=0, max_inspection_ms=1)
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        with TestClient(app) as client:
            client.post("/x", content=_json_con_campos(5_000),
                        headers={"content-type": "application/json"})
    eventos = [json.loads(r.message) for r in caplog.records if r.name == "gatekeeper"]
    codes = [e["event"] for e in eventos]
    assert "inspection_timeout" in codes, eventos


def test_los_parametros_de_la_query_cuentan():
    """La query tambien consume presupuesto: se cuenta ANTES de parsearla."""
    app = make_app(max_fields=10)
    with TestClient(app) as client:
        r = client.get("/x?" + "&".join(f"p{i}=v" for i in range(50)))
    assert r.status_code == 413, r.text


def test_el_multipart_cuenta_sus_partes():
    app = make_app(max_fields=10)
    partes = b"".join(
        b"--b\r\nContent-Disposition: form-data; name=f%d\r\n\r\nx\r\n" % i
        for i in range(50)
    ) + b"--b--\r\n"
    with TestClient(app) as client:
        r = client.post("/x", content=partes,
                        headers={"content-type": "multipart/form-data; boundary=b"})
    assert r.status_code == 413, r.text


def test_el_body_grande_por_defecto_da_413():
    """El limite por defecto baja a 256 KiB."""
    app = make_app()
    with TestClient(app) as client:
        r = client.post("/x", content=b"a" * (300 * 1024),
                        headers={"content-type": "application/json"})
    assert r.status_code == 413, r.text


def test_un_body_de_256_kib_cabe():
    app = make_app()
    with TestClient(app) as client:
        r = client.post("/x", content=b"a" * (256 * 1024),
                        headers={"content-type": "application/json"})
    assert r.status_code == 200, r.text


def test_el_413_del_presupuesto_lleva_cabeceras_de_seguridad():
    app = make_app(max_fields=10)
    with TestClient(app) as client:
        r = client.post("/x", content=_json_con_campos(100),
                        headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"


def test_la_configuracion_invalida_falla_al_arrancar():
    with pytest.raises(ValueError):
        Config(max_fields=-1)
    with pytest.raises(ValueError):
        Config(max_inspection_ms=-1)
