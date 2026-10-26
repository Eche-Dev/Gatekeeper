"""REGRESION: DoS por punteros JSON cuadraticos.

Este test fija un fallo de seguridad encontrado en la revision de seguridad de
v0.3 (2026-10-24).

El fallo: el puntero JSON que identifica el campo en la auditoria se
construye concatenando un segmento por nivel de anidamiento. A profundidad N,
cada puntero mide O(N) caracteres, y con N campos el total es O(N^2).

Medido antes del arreglo:
- un body de 60 KiB con 10.000 niveles producia 193,6 MiB de memoria (2401x
  la entrada), a traves del middleware real;
- 10 peticiones simultaneas llegaban a 1,9 GiB y 24 segundos de CPU;
- la peticion respondia 200: el atacante recibia una respuesta normal y el
  consumo de memoria era invisible.

Por que `max_body_size` no lo acotaba: 60 KiB estan muy por debajo del
limite de 1 MiB. El problema no era el tamano del body, sino la estructura.

Despues del arreglo: el puntero se recorta a una profundidad maxima, asi que
el consumo es lineal en el tamano del body y el factor de amplificacion queda
acotado (~63x) con independencia de la profundidad.

Lo que NO se pierde:
- la atribucion por campo sigue diciendo QUE campo salio;
- `exclude_fields` sigue funcionando, porque compara por el ULTIMO segmento,
  que el recorte conserva intacto.
"""
from __future__ import annotations

import asyncio
import tracemalloc

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.body import (
    _iter_fields,
    extract_strings,
)


def _json_profundo(nivel: int) -> bytes:
    """JSON con `nivel` niveles de anidamiento."""
    return (b'{"a":' * nivel) + b"1" + (b"}" * nivel)


def _pico_de_memoria(funcion, *args) -> tuple[float, object]:
    tracemalloc.start()
    resultado = funcion(*args)
    _, pico = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return pico, resultado


# ------------------------------------------------------- el limite del puntero


def test_el_puntero_esta_acotado():
    """La longitud del puntero no crece con la profundidad."""
    from gatekeeper.body import MAX_POINTER_LENGTH

    obj: object = "hoja"
    for _ in range(500):
        obj = {"nivel": obj}
    punteros = [p for p, _, _ in _iter_fields(obj)]
    assert max(len(p) for p in punteros) <= MAX_POINTER_LENGTH, (
        f"el puntero mas largo mide {max(len(p) for p in punteros)} caracteres"
    )


def test_el_puntero_recortado_esta_marcado():
    """Un puntero recortado se marca con '…', para que no pase por ruta completa."""
    obj: object = "hoja"
    for _ in range(200):
        obj = {"nivel": obj}
    punteros = [p for p, _, _ in _iter_fields(obj)]
    assert any("…" in p for p in punteros), "el recorte no se marca"


def test_una_clave_larguisima_no_rompe_el_puntero():
    """Una clave de 10.000 caracteres tampoco puede hacer el puntero enorme."""
    from gatekeeper.body import MAX_POINTER_LENGTH

    obj: object = "hoja"
    for _ in range(10):
        obj = {"k" * 10000: obj}
    punteros = [p for p, _, _ in _iter_fields(obj)]
    assert max(len(p) for p in punteros) <= MAX_POINTER_LENGTH, (
        f"el puntero mas largo mide {max(len(p) for p in punteros)} caracteres"
    )


def test_el_ultimo_segmento_se_conserva():
    """El recorte NO rompe `exclude_fields`, que compara por el ultimo segmento.

    `exclude_fields` documenta que un puntero como `/user/bio` se puede
    excluir por `bio` o por `/user/bio`. Con el recorte, el ultimo segmento
    tiene que seguir intacto.
    """
    from gatekeeper.config import Config

    obj: object = "texto"
    for _ in range(100):
        obj = {"nivel": obj}
    obj = {"bio": obj}

    config = Config(exclude_fields=["bio"])
    puntero = next(p for p, v, _ in _iter_fields(obj) if v == "texto")
    assert config.field_excluded(puntero), (
        f"el puntero recortado {puntero!r} no se puede excluir por 'bio'"
    )


# --------------------------------------------------------- la amplificacion


@pytest.mark.parametrize("nivel", [1000, 5000, 10000])
def test_la_memoria_no_crece_cuadraticamente(nivel: int):
    """La memoria debe ser lineal en el tamano del body.

    Antes del arreglo, 10.000 niveles costaban 193 MiB (2401x la entrada).
    Ahora el factor queda acotado (~63x) con independencia de la profundidad.
    """
    cuerpo = _json_profundo(nivel)
    pico, campos = _pico_de_memoria(extract_strings, "application/json", cuerpo)
    factor = pico / len(cuerpo)
    assert factor < 100, (
        f"un body de {len(cuerpo) / 1024:.0f} KiB (nivel {nivel}) amplifica la "
        f"memoria {factor:.0f}x ({pico / 1024 / 1024:.1f} MiB)"
    )


def test_el_caso_peor_esta_acotado():
    """El caso que se midio antes del arreglo (10.000 niveles, 193,6 MiB)."""
    cuerpo = _json_profundo(10000)
    pico, _ = _pico_de_memoria(extract_strings, "application/json", cuerpo)
    assert pico < 32 * 1024 * 1024, (
        f"el pico fue de {pico / 1024 / 1024:.1f} MiB; deberia estar por debajo de 32"
    )


# ----------------------------------------------- a traves del middleware real


def _middleware(**cfg) -> GatekeeperMiddleware:
    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/{path:path}", ok, methods=["POST"])])
    return GatekeeperMiddleware(app, Config(rate_limit=0, **cfg))


def test_el_middleware_real_no_sufre_la_amplificacion():
    """La correccion esta en el camino real, no solo en la funcion suelta.

    Este es el test que importa: el fallo original se reproducía mandando una
    peticion HTTP de verdad a un `GatekeeperMiddleware`.

    El presupuesto de campos se desactiva aqui (`max_fields=0`) a proposito:
    este test mide el recorte del PUNTERO, que es una proteccion distinta y
    anterior. Con el presupuesto puesto, esta peticion ni siquiera llega al
    puntero (ver `test_el_presupuesto_de_campos_corta_el_json_profundo`).
    """
    cuerpo = _json_profundo(10000)

    async def receive():
        return {"type": "http.request", "body": cuerpo, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": [(b"content-type", b"application/json")],
        "client": ("1.2.3.4", 1234),
    }
    sent = []

    async def send(message):
        sent.append(message)

    app = _middleware(max_fields=0, max_inspection_ms=0)
    tracemalloc.start()
    asyncio.run(app(scope, receive, send))
    _, pico = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert sent[0]["status"] == 200, sent
    assert pico < 32 * 1024 * 1024, (
        f"el middleware consumio {pico / 1024 / 1024:.1f} MiB con un body de "
        f"{len(cuerpo) / 1024:.0f} KiB"
    )


def test_el_presupuesto_de_campos_corta_el_json_profundo():
    """Un JSON de 300 niveles agota el presupuesto de campos: 413.

    Es una proteccion ADICIONAL a la del puntero: ahora el ataque se corta
    antes de construir ningun puntero, y con un cuerpo mucho mas pequeno.

    La profundidad es 300 y no 10.000 a proposito: el limite de recursion de
    `json.loads` depende de la version de Python (en 3.10 no parsea ni 1.000
    niveles y el body se trata como texto opaco), y el test tiene que dar el
    mismo resultado en 3.10-3.14.
    """
    cuerpo = _json_profundo(300)

    async def receive():
        return {"type": "http.request", "body": cuerpo, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": [(b"content-type", b"application/json")],
        "client": ("1.2.3.4", 1234),
    }
    sent = []

    async def send(message):
        sent.append(message)

    app = _middleware(max_fields=100)
    asyncio.run(app(scope, receive, send))
    assert sent[0]["status"] == 413, sent


def test_veinte_peticiones_concurrentes_no_revientan_la_memoria():
    """El escenario de ataque: muchas peticiones a la vez.

    Antes del arreglo, 10 peticiones simultaneas llegaban a 1,9 GiB.
    """
    cuerpo = _json_profundo(5000)
    app = _middleware(max_fields=0, max_inspection_ms=0)

    async def una():
        async def receive():
            return {"type": "http.request", "body": cuerpo, "more_body": False}

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/x",
            "headers": [(b"content-type", b"application/json")],
            "client": ("1.2.3.4", 1234),
        }
        sent = []

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        return sent[0]["status"]

    async def scenario():
        return await asyncio.gather(*[una() for _ in range(20)])

    tracemalloc.start()
    estados = asyncio.run(scenario())
    _, pico = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert set(estados) == {200}, estados
    # 20 peticiones en paralelo: el pico no puede ser 20 veces el de una.
    assert pico < 128 * 1024 * 1024, (
        f"20 peticiones simultaneas consumieron {pico / 1024 / 1024:.1f} MiB"
    )


# ------------------------------------------------- la deteccion no se pierde


def test_el_json_profundo_no_impide_detectar_un_ataque():
    """El recorte es del PUNTERO, no del texto: la deteccion sigue funcionando.

    El texto del body se inspecciona igual, este o no estructurado.
    """
    from gatekeeper.rules import scan

    cuerpo = b'{"a": ' + (b'{"b": ' * 200) + b'"UNION SELECT password FROM users"'
    campos = extract_strings("application/json", cuerpo)
    valores = [v for _, v in campos]
    assert any("UNION SELECT" in v for v in valores), "no se extrajo el valor"
    assert any(scan(v) == "sqli" for v in valores), "no se detecto el ataque"


def test_el_cuerpo_completo_se_sigue_leyendo():
    """Un JSON profundo no puede hacer que el middleware ignore el body."""
    cuerpo = b'{"a": ' + (b'{"b": ' * 200) + b'"valor"'
    campos = extract_strings("application/json", cuerpo)
    assert any("valor" in v for _, v in campos)


def test_un_json_valido_normal_no_cambia():
    """El recorte no toca los JSON de verdad: punteros cortos, intactos."""
    cuerpo = b'{"user": {"name": "Ana", "tags": ["a", "b"]}}'
    punteros = [p for p, _ in extract_strings("application/json", cuerpo)]
    assert "/user/name" in punteros, punteros
    assert "/user/tags/0" in punteros, punteros
    assert not any(p.startswith("…") for p in punteros), punteros
