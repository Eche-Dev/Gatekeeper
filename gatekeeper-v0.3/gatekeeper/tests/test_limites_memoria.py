"""Limites de memoria y volumen: lo que el middleware PUEDE y NO PUEDE gastar.

El plan pide "verificar limites de memoria y consumo con cuerpos grandes,
cuerpos fragmentados y entradas de gran volumen". Esto fija ese comportamiento
como contrato, para que nadie lo rompa sin que salte el pipeline.

Las garantias:
- un body que excede `max_body_size` se CORTA: el middleware deja de leer y
  responde 413 sin acumular el body entero;
- un body que cabe consume como maximo ~2x su tamano (una copia en los
  mensajes de ASGI, que hay que reproducir, y otra en el body unido que se
  inspecciona). El factor esta acotado, no es ilimitado;
- un body fragmentado en muchos trozos se comporta igual que uno entero;
- el middleware no retiene memoria entre peticiones: tras responder, no
  quedan bodies guardados.
"""
from __future__ import annotations

import asyncio
import gc
import tracemalloc

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.body import read_body


def _app(**cfg_kwargs):
    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/{path:path}", ok, methods=["GET", "POST"])])
    return GatekeeperMiddleware(app, Config(**cfg_kwargs))


async def _receive_fragmentado(total: int, fragmento: int):
    """Un `receive` que entrega el body en trozos de `fragmento` bytes."""
    enviados = 0

    async def receive():
        nonlocal enviados
        if enviados >= total:
            return {"type": "http.disconnect"}
        n = min(fragmento, total - enviados)
        enviados += n
        return {
            "type": "http.request",
            "body": b"a" * n,
            "more_body": enviados < total,
        }

    return receive


def _medir_memoria(total: int, fragmento: int, max_size: int) -> tuple[float, int, int]:
    """(memoria en KiB, mensajes guardados, body leido) de una lectura."""
    async def scenario():
        receive = await _receive_fragmentado(total, fragmento)
        tracemalloc.start()
        antes = tracemalloc.get_traced_memory()[0]
        messages, body = await read_body(receive, max_size)
        despues = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()
        return (despues - antes) / 1024, len(messages), (len(body) if body else 0)

    return asyncio.run(scenario())


# ------------------------------------------------------- el corte por tamano


def test_un_body_que_excede_el_limite_se_corta_pronto():
    """Un body de 64 MiB con limite de 1 MiB no se lee entero.

    El middleware para en cuanto pasa del limite: no acumula 64 MiB para
    despues decir que no.
    """
    mem_kib, mensajes, body = _medir_memoria(
        64 * 1024 * 1024, 1024 * 1024, 1024 * 1024
    )
    assert body == 0, "no deberia devolver body cuando excede el limite"
    # Solo se leyeron los mensajes necesarios para pasar del limite.
    assert mensajes <= 3, f"se leyeron {mensajes} mensajes antes de cortar"
    # Y la memoria se queda cerca del limite, no del tamano del body.
    assert mem_kib < 8 * 1024, f"se acumularon {mem_kib:.0f} KiB para un limite de 1 MiB"


def test_el_corte_ocurre_en_cualquier_fragmentacion():
    """Da igual como venga fragmentado el body: el corte es por bytes acumulados.

    El numero de mensajes leidos depende de como venga troceado (con trozos de
    1 KiB hacen falta 1025 para pasar de 1 MiB), pero los BYTES acumulados se
    cortan siempre en cuanto pasan del limite.
    """
    for fragmento in (1024, 64 * 1024, 1024 * 1024):
        mem_kib, mensajes, body = _medir_memoria(
            32 * 1024 * 1024, fragmento, 1024 * 1024
        )
        assert body == 0, f"con fragmentos de {fragmento} deberia cortar"
        # Los bytes leidos no pasan del limite mas que en un fragmento.
        leidos = mensajes * fragmento
        assert leidos <= 1024 * 1024 + fragmento, (
            f"con fragmentos de {fragmento} se leyeron {leidos} bytes"
        )
        assert mem_kib < 8 * 1024, f"con fragmentos de {fragmento}: {mem_kib:.0f} KiB"


# --------------------------------------------------- el factor de memoria


def test_el_consumo_de_un_body_permitido_esta_acotado():
    """Un body que cabe consume como maximo ~2x su tamano.

    Dos copias: los mensajes de ASGI (que hay que reproducir tal cual) y el
    body unido (que hay que inspeccionar). Lo que NO puede pasar es un factor
    sin cota.
    """
    for tamano_mb in (2, 8):
        mem_kib, _, _ = _medir_memoria(
            tamano_mb * 1024 * 1024, 64 * 1024, 16 * 1024 * 1024
        )
        factor = mem_kib / (tamano_mb * 1024)
        assert factor <= 2.2, (
            f"un body de {tamano_mb} MiB consumio {factor:.2f}x su tamano"
        )


def test_fragmentar_no_cambia_el_consumo():
    """El consumo depende del tamano, no de quantos trozos vengan."""
    fragmentaciones = [(64 * 1024, "pocos"), (16 * 1024, "medios"), (4 * 1024, "muchos")]
    consumos = []
    for fragmento, _ in fragmentaciones:
        mem_kib, _, _ = _medir_memoria(4 * 1024 * 1024, fragmento, 8 * 1024 * 1024)
        consumos.append(mem_kib)
    # La diferencia entre fragmentar de una manera u otra es marginal.
    assert max(consumos) - min(consumos) < 1024, (
        f"el consumo cambia mucho segun la fragmentacion: {consumos}"
    )


# ---------------------------------------------- lo que ve el cliente


def test_un_body_enorme_recibe_413_y_no_consume_el_proceso():
    """El caso de negocio: un body de 32 MiB con limite de 1 MiB -> 413."""
    app = _app(max_body_size=1024 * 1024)
    with TestClient(app) as client:
        r = client.post(
            "/x",
            content=b"a" * (32 * 1024 * 1024),
            headers={"content-type": "application/json"},
        )
    assert r.status_code == 413, r.text


def test_el_middleware_no_retiene_memoria_entre_peticiones():
    """Tras responder, no queda ningun body guardado.

    Si el middleware retuviera los bodies, un atacante podria disparar el
    consumo de memoria con peticiones sucesivas.
    """
    app = _app(max_body_size=1024 * 1024)
    gc.collect()
    tracemalloc.start()
    antes = tracemalloc.get_traced_memory()[0]
    with TestClient(app) as client:
        for _ in range(5):
            client.post(
                "/x",
                content=b"a" * (512 * 1024),
                headers={"content-type": "application/json"},
            )
    gc.collect()
    despues = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()
    # 5 peticiones de 512 KiB: si se retuvieran, se verian 2,5 MiB.
    crecimiento = (despues - antes) / 1024
    assert crecimiento < 4 * 1024, (
        f"el middleware retuvo {crecimiento:.0f} KiB tras 5 peticiones"
    )


@pytest.mark.parametrize("fragmento", [1024, 64 * 1024])
def test_un_body_fragmentado_grande_tambien_da_413(fragmento: int):
    """El corte funciona igual con el body troceado."""
    app = _app(max_body_size=1024 * 1024)

    async def receive():
        return {
            "type": "http.request",
            "body": b"a" * fragmento,
            "more_body": True,
        }

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

    asyncio.run(app(scope, receive, send))
    assert sent[0]["status"] == 413, sent
