"""Varios PROCESOS de Python real, no varios clientes en el mismo proceso.

`tests/test_redis_real.py` usa varios clientes de Redis en el MISMO proceso.
Para Redis eso es equivalente a varios workers, pero no demuestra el reparto
entre procesos del sistema operativo: el plan pide justo esa garantia.

Aqui se lanzan procesos de Python de verdad (con `multiprocessing`), cada uno
con su propio backend de Redis, y se comprueba que el limite es GLOBAL entre
ellos: es la garantia que hace que `rate_backend="redis"` sea necesario en
despliegues con varios workers.

Requiere un Redis real. Si no hay, se omite con un motivo claro.
"""
from __future__ import annotations

import multiprocessing
import os
import uuid

import pytest

from gatekeeper.ratelimit import RedisBackend

REDIS_URL = os.environ.get("GATEKEEPER_REDIS_URL", "redis://127.0.0.1:6379/0")


def _redis_disponible() -> bool:
    try:
        import redis as redis_sync
    except ImportError:  # pragma: no cover - depende del entorno
        return False
    try:
        client = redis_sync.Redis.from_url(
            REDIS_URL, socket_connect_timeout=1.0, socket_timeout=1.0, protocol=2
        )
        client.ping()
        client.close()
        return True
    except Exception:
        return False


REQUIERE_REDIS = pytest.mark.skipif(
    not _redis_disponible(),
    reason=(
        "no hay un Redis real disponible "
        f"(GATEKEEPER_REDIS_URL={REDIS_URL}). En CI lo levanta el job de Redis."
    ),
)


def _worker(ip: str, prefijo: str, limite: int, cola) -> None:
    """Proceso hijo: pide permiso N veces y dice cuantas se concedieron.

    Vive en un proceso aparte (lo levanta `multiprocessing`), con su propio
    cliente de Redis: es un worker de verdad, no un hilo.
    """
    import asyncio

    from redis.asyncio import Redis

    async def scenario():
        client = Redis.from_url(
            REDIS_URL, socket_connect_timeout=2.0, socket_timeout=2.0, protocol=2
        )
        backend = RedisBackend(client, limite, 60.0, prefix=prefijo)
        concedidos = 0
        for _ in range(limite * 2):
            if await backend.allow(ip):
                concedidos += 1
        await client.aclose()
        return concedidos

    cola.put(asyncio.run(scenario()))


def _worker_memoria(ip: str, prefijo: str, limite: int, cola) -> None:
    """El MISMO reparto, pero con el backend en memoria.

    Sirve de contraste: con memoria cada proceso cuenta lo suyo y se conceden
    `limite` permisos POR PROCESO. Con Redis se conceden `limite` en total.
    """
    import asyncio

    from gatekeeper.ratelimit import MemoryBackend

    async def scenario():
        backend = MemoryBackend(limite, 60.0)
        concedidos = 0
        for _ in range(limite * 2):
            if await backend.allow(ip):
                concedidos += 1
        return concedidos

    cola.put(asyncio.run(scenario()))


def _limpiar(prefijo: str) -> None:
    try:
        import redis as redis_sync

        client = redis_sync.Redis.from_url(
            REDIS_URL, socket_connect_timeout=2.0, socket_timeout=2.0, protocol=2
        )
        claves = client.keys(prefijo + "*")
        if claves:
            client.delete(*claves)
        client.close()
    except Exception:
        pass


@REQUIERE_REDIS
def test_cuatro_procesos_comparten_un_solo_contador():
    """La garantia: con Redis, el limite es global entre PROCESOS.

    Cuatro procesos, la misma IP y el mismo prefijo. Entre todos se
    conceden exactamente `limite` permisos, no `limite` por proceso.

    Con el backend en memoria serian 4 × limite: por eso, en un despliegue
    con varios workers, Redis no es opcional.
    """
    prefijo = f"gk:multi:{uuid.uuid4().hex}:"
    ip = "10.7.7.7"
    limite = 5
    n_procesos = 4

    ctx = multiprocessing.get_context("spawn")
    cola = ctx.Queue()
    procesos = [
        ctx.Process(target=_worker, args=(ip, prefijo, limite, cola))
        for _ in range(n_procesos)
    ]
    try:
        for p in procesos:
            p.start()
        for p in procesos:
            p.join(timeout=60)
            assert p.exitcode == 0, f"un proceso termino con codigo {p.exitcode}"

        totales = [cola.get(timeout=10) for _ in range(n_procesos)]
        suma = sum(totales)
        assert suma == limite, (
            f"se concedieron {suma} permisos con limite {limite} entre "
            f"{n_procesos} procesos (por proceso: {totales})"
        )
    finally:
        for p in procesos:
            if p.is_alive():
                p.kill()
        _limpiar(prefijo)


@REQUIERE_REDIS
def test_el_contraste_con_el_backend_en_memoria():
    """Por que Redis es necesario: con memoria, el limite se multiplica.

    Este test es el que le da sentido al anterior. Con el backend en memoria,
    cuatro procesos conceden `limite` permisos CADA UNO (4 × limite en total).
    Con Redis se conceden `limite` en total.

    Si alguien rompe el backend de Redis y pasa a contar en local, este test
    lo delata.
    """
    ctx = multiprocessing.get_context("spawn")
    cola = ctx.Queue()
    limite = 5
    n_procesos = 4
    procesos = [
        ctx.Process(target=_worker_memoria, args=("10.7.7.8", "x", limite, cola))
        for _ in range(n_procesos)
    ]
    try:
        for p in procesos:
            p.start()
        for p in procesos:
            p.join(timeout=60)
            assert p.exitcode == 0
        totales = [cola.get(timeout=10) for _ in range(n_procesos)]
        suma = sum(totales)
        assert suma == limite * n_procesos, (
            f"con memoria se concedieron {suma} (por proceso: {totales}); "
            f"lo esperado es {limite * n_procesos}"
        )
    finally:
        for p in procesos:
            if p.is_alive():
                p.kill()


@REQUIERE_REDIS
def test_un_proceso_no_puede_heredarse_el_contador_de_otro():
    """Cada proceso tiene su PROPIO cliente: aun asi, el contador es el mismo.

    El fallo tipico de un backend mal implementado es que cada proceso tenga
    su contador en local. Aqui se comprueba que el segundo proceso ve lo que
    dejo el primero, no solo que la suma cuadre.
    """
    prefijo = f"gk:multi:{uuid.uuid4().hex}:"
    ip = "10.8.8.8"
    limite = 2

    ctx = multiprocessing.get_context("spawn")
    cola = ctx.Queue()
    try:
        # Proceso 1: agota el limite.
        p1 = ctx.Process(target=_worker, args=(ip, prefijo, limite, cola))
        p1.start()
        p1.join(timeout=60)
        primero = cola.get(timeout=10)
        assert primero == limite, primero

        # Proceso 2 (nuevo, con su cliente): ya no queda permiso.
        p2 = ctx.Process(target=_worker, args=(ip, prefijo, limite, cola))
        p2.start()
        p2.join(timeout=60)
        segundo = cola.get(timeout=10)
        assert segundo == 0, (
            f"el segundo proceso obtuvo {segundo} permisos; deberia ser 0 "
            "porque el contador es compartido"
        )
    finally:
        _limpiar(prefijo)
