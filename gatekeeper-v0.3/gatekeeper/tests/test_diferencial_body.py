"""Tests diferenciales: el middleware y la app interpretan el body IGUAL.

El middleware lee el body para inspeccionarlo y despues se lo reinyecta a la
aplicacion (`read_body` + `replay`). Si los dos interpretaran el body de
forma distinta, el middleware estaria inspeccionando una cosa y la app
usando otra: eso es un BYPASS (el payload pasa por el campo que el middleware
no vio) o un falso positivo (el middleware bloquea lo que la app no iba a
usar).

Estos tests son DIFERENTIALES de verdad: se hace la misma peticion con y sin
middleware y se compara lo que recibe la aplicacion. Si el middleware
cambia una sola coma de lo que ve la app, el test falla.

La comparacion se hace contra Starlette y contra FastAPI, porque las dos
tienen su propio camino de parseo del body.

Los casos NO estan duplicados aqui: viven en `tools/diferencial_body.py`, que
es la fuente unica y la que ejecuta la matriz de compatibilidad en cada
version de Starlette y FastAPI. Lo que se comprueba aqui es exactamente lo
mismo que se comprueba alli.

Donde NO pueden coincidir (y por eso el limite esta documentado en
`docs/amenazas.md`): una aplicacion que interprete el body por su cuenta
—parsear `q=1' OR '1'='1` a mano sin decir que es un form— ve cosas que el
middleware no puede ver, porque el content-type es lo unico que le dice como
inspeccionar. Eso no lo arregla un test: lo arregla decir el content-type
correcto.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "diferencial_body.py"


def _carga():
    """Carga el modulo del diferencial (no es un paquete del proyecto)."""
    spec = importlib.util.spec_from_file_location("diferencial_body", SCRIPT)
    assert spec and spec.loader
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


MODULO = _carga()
MARCOS = ("starlette", "fastapi")


@pytest.mark.parametrize("marco", MARCOS)
@pytest.mark.parametrize(
    "nombre,content_type,body",
    MODULO.CASOS,
    ids=[caso[0] for caso in MODULO.CASOS],
)
def test_la_app_ve_lo_mismo_con_y_sin_middleware(marco, nombre, content_type, body):
    """La app tiene que recibir EXACTAMENTE lo mismo con y sin middleware.

    Si el middleware se comiera una parte del body, o lo reinyectara
    distinto, la aplicacion veria otra cosa: eso seria un fallo de Gatekeeper,
    no un detalle del test.
    """
    fallo = MODULO.fallo_igualdad(marco, nombre, content_type, body)
    assert fallo is None, fallo


@pytest.mark.parametrize("marco", MARCOS)
@pytest.mark.parametrize(
    "nombre,content_type,body",
    MODULO.MARCADORES,
    ids=[caso[0] for caso in MODULO.MARCADORES],
)
def test_el_middleware_inspecciona_el_valor_que_usa_la_app(
    marco, nombre, content_type, body
):
    """El middleware tiene que ver lo mismo que la app, no menos.

    Se mide con una regla propia que solo casa con el valor que la app ha
    declarado (por ejemplo `sleep(10+6)`) y con todas las reglas integradas
    desactivadas: si el middleware inspeccionara otra cosa, la peticion
    pasaria. Es la comprobacion que encuentra los BYPASS: el `+` de un body
    es literal para la app, y perderlo era dejar pasar el payload intacto.
    """
    fallo = MODULO.fallo_marcador(marco, nombre, content_type, body)
    if fallo is not None and fallo.startswith("SKIP: "):
        pytest.skip(fallo)
    assert fallo is None, fallo


@pytest.mark.parametrize("marco", MARCOS)
@pytest.mark.parametrize(
    "nombre,content_type,body,regla",
    MODULO.ATAQUES,
    ids=[caso[0] for caso in MODULO.ATAQUES],
)
def test_el_middleware_ve_lo_que_la_app_va_a_usar(
    marco, nombre, content_type, body, regla
):
    """Un payload en un campo que la app va a leer tiene que estar bloqueado.

    El body es el MISMO que la app leeria: si el middleware lo(parsea) de otra
    forma, el ataque llegaria intacto a la aplicacion y el WAF no habria
    servido de nada. Ademas se comprueba que salta la regla esperada y que
    el evento de auditoria dice que se bloqueo.
    """
    fallo = MODULO.fallo_ataque(marco, nombre, content_type, body, regla)
    assert fallo is None, fallo


# --- lo que NO se puede cubrir, documentado --------------------------------
async def eco(request):
    """Lo que la aplicacion VE del body, de todas las formas."""
    crudo = await request.body()
    info = {"bytes": crudo.decode("utf-8", "replace")}
    try:
        info["json"] = await request.json()
    except Exception as exc:  # noqa: BLE001
        info["json_error"] = type(exc).__name__
    try:
        form = await request.form()
        info["form"] = [[k, str(v)] for k, v in form.multi_items()]
    except Exception as exc:  # noqa: BLE001
        info["form_error"] = type(exc).__name__
    return JSONResponse(info)


def test_el_limite_conocido_no_es_un_bypass_del_middleware():
    """Una app que parsea el body por su cuenta ve mas que el middleware.

    El middleware decide COMO inspeccionar el body segun el content-type (y
    si no cuadra, inspecciona el texto crudo). Si la aplicacion interpreta el
    body de una forma que el content-type no anuncia, el middleware no puede
    saberlo: no es un fallo suyo, es el limite de ser una capa por delante.

    Este test no falla: deja el limite escrito y medido, para que no se
    "arregle" por error creyendo que hay un bypass.
    """
    # El cuerpo es un form, pero el content-type dice JSON: el middleware lo
    # parsea como JSON (falla) e inspecciona el texto crudo; el ataque se ve
    # igual, asi que el middleware bloquea.
    app = Starlette(routes=[Route("/eco", eco, methods=["GET", "POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    cliente = TestClient(app)
    respuesta = cliente.post(
        "/eco",
        content=b"q=1' OR '1'='1",
        headers={"content-type": "application/json"},
    )
    assert respuesta.status_code == 403
