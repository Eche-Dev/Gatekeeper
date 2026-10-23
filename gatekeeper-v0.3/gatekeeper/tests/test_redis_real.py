"""Rate limiting contra un Redis REAL, no contra fakeredis.

`fakeredis` con Lua ejecuta el script de verdad, pero simula el servidor: no
reproduce el reparto entre procesos, ni los reinicios, ni el comportamiento
cuando Redis cae de verdad. Estas pruebas usan un Redis real (el servicio
`redis` de CI, o uno local) y comprueban lo que la guia de despliegue promete.

Si no hay Redis disponible, las pruebas se OMITEN con un motivo claro: la
suite tiene que pasar tambien en un entorno sin Redis (instalacion minima).

Variable de entorno: GATEKEEPER_REDIS_URL (por defecto redis://127.0.0.1:6379/0).
"""
from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.ratelimit import BackendUnavailable, RedisBackend

REDIS_URL = os.environ.get("GATEKEEPER_REDIS_URL", "redis://127.0.0.1:6379/0")


def _redis_disponible() -> bool:
    try:
        import redis as redis_sync
    except ImportError:  # pragma: no cover - depende del entorno
        return False
    try:
        # RESP2 explicito: el cliente moderno hace handshake RESP3 por defecto
        # y un Redis 5.x/6.0 no lo entiende ("unknown command HELLO").
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


def _cliente():
    """Cliente async contra el Redis real, con RESP2 explicito.

    RESP2 explicito porque el cliente redis-py moderno (8.x) hace handshake
    RESP3 por defecto, y un Redis 5.x/6.0 no lo entiende: falla con
    'unknown command HELLO'. Forzar RESP2 hace que Gatekeeper hable con
    cualquier Redis >= 5.0, que es lo que promete el extra [redis].
    """
    from redis.asyncio import Redis

    return Redis.from_url(
        REDIS_URL,
        socket_connect_timeout=2.0,
        socket_timeout=2.0,
        protocol=2,
    )


def _prefijo_unico() -> str:
    """Prefijo propio de cada test: no se pisa con otros ni entre workers."""
    return f"gk:test:{uuid.uuid4().hex}:"


def _backend(limit: int = 5, window: float = 60.0, prefix: str | None = None):
    prefix = prefix or _prefijo_unico()
    return RedisBackend(_cliente(), limit, window, prefix=prefix), prefix


def _limpiar(prefix: str) -> None:
    """Borra las claves del test (se ejecuta al final, pase lo que pase)."""
    try:
        import redis as redis_sync

        client = redis_sync.Redis.from_url(REDIS_URL, socket_connect_timeout=2.0,
                                           socket_timeout=2.0, protocol=2)
        claves = client.keys(prefix + "*")
        if claves:
            client.delete(*claves)
        client.close()
    except Exception:
        pass


# ----------------------------------------------------- el script Lua de verdad


@REQUIERE_REDIS
def test_el_script_lua_corre_en_redis_real():
    """La ventana deslizante se implementa con un script Lua: se ejecuta de verdad."""
    backend, prefix = _backend(limit=3, window=60.0)
    try:
        async def scenario():
            return [await backend.allow("1.2.3.4") for _ in range(5)]

        resultados = asyncio.run(scenario())
        # 3 permitidos (el limite), 2 rechazados.
        assert resultados == [True, True, True, False, False], resultados
    finally:
        _limpiar(prefix)


@REQUIERE_REDIS
def test_retry_after_calcula_el_segundo_restante():
    """El script de retry_after devuelve los segundos que faltan para la ventana."""
    backend, prefix = _backend(limit=5, window=10.0)
    try:
        async def scenario():
            await backend.allow("a")
            return await backend.retry_after("a")

        # Ventana de 10 s: debe pedir entre 1 y 10 segundos.
        restantes = asyncio.run(scenario())
        assert 1 <= restantes <= 10, restantes
    finally:
        _limpiar(prefix)


@REQUIERE_REDIS
def test_las_claves_expiran_y_no_se_acumulan():
    """La clave tiene TTL: un Redis real la borra sola, sin crecer sin limite."""
    import redis as redis_sync

    backend, prefix = _backend(limit=5, window=10.0)
    try:
        asyncio.run(backend.allow("1.1.1.1"))
        client = redis_sync.Redis.from_url(REDIS_URL, socket_connect_timeout=2.0,
                                           socket_timeout=2.0, protocol=2)
        ttl = client.ttl(prefix + "1.1.1.1")
        client.close()
        assert 0 < ttl <= 10, f"TTL inesperado: {ttl}"
    finally:
        _limpiar(prefix)


@REQUIERE_REDIS
def test_la_ventana_se_desplaza_y_se_recupera():
    """Pasada la ventana, la IP vuelve a estar admitida."""
    backend, prefix = _backend(limit=2, window=2.0)
    try:
        async def scenario():
            primero = [await backend.allow("a") for _ in range(3)]
            await asyncio.sleep(2.2)  # la ventana de 2 s ya paso
            despues = await backend.allow("a")
            return primero, despues

        primero, despues = asyncio.run(scenario())
        assert primero == [True, True, False], primero
        assert despues is True
    finally:
        _limpiar(prefix)


# ------------------------------------------ la garantia de multi-worker


@REQUIERE_REDIS
def test_dos_procesos_comparten_el_mismo_contador():
    """LA GARANTIA DEL PLAN: con Redis, el limite es global, no por worker.

    Dos clientes Redis independientes (como dos workers con su propio proceso)
    ven el MISMO contador. Sin backend compartido, cada uno contaria lo suyo y
    el limite se multiplicaria por el numero de workers.
    """
    prefix = _prefijo_unico()

    async def scenario():
        worker_a = RedisBackend(_cliente(), 3, 60.0, prefix=prefix)
        worker_b = RedisBackend(_cliente(), 3, 60.0, prefix=prefix)

        admitidos = []
        # Alternan entre los dos workers, como si el balanceador repartiera.
        for _ in range(6):
            worker = worker_a if len(admitidos) % 2 == 0 else worker_b
            admitidos.append(await worker.allow("9.9.9.9"))
        return admitidos

    try:
        admitidos = asyncio.run(scenario())
        # 3 en total entre los dos workers, NO 3+3.
        assert sum(admitidos) == 3, f"se admitieron {sum(admitidos)}; deberian ser 3"
        assert admitidos == [True, True, True, False, False, False], admitidos
    finally:
        _limpiar(prefix)


@REQUIERE_REDIS
def test_ips_distintas_tienen_contadores_separados():
    """El limite es por IP: un cliente que agota el suyo no afecta a otro."""
    prefix = _prefijo_unico()

    async def scenario():
        backend = RedisBackend(_cliente(), 2, 60.0, prefix=prefix)
        cliente_a = [await backend.allow("1.1.1.1") for _ in range(3)]
        cliente_b = await backend.allow("2.2.2.2")
        return cliente_a, cliente_b

    try:
        cliente_a, cliente_b = asyncio.run(scenario())
        assert cliente_a == [True, True, False], cliente_a
        assert cliente_b is True, "la IP del otro cliente no debe verse afectada"
    finally:
        _limpiar(prefix)


@REQUIERE_REDIS
def test_la_concurrencia_no_deja_colarse_ninguna_peticion():
    """El script Lua es atomico: N peticiones simultaneas respetan el limite.

    Este es el motivo de usar un script y no un pipeline de comandos: con el
    pipeline, dos workers que llegan a la vez pueden colarse por encima del
    limite.
    """
    prefix = _prefijo_unico()

    async def scenario():
        # 50 workers distintas (procesos distintos) contra la misma IP.
        backends = [RedisBackend(_cliente(), 10, 60.0, prefix=prefix) for _ in range(50)]
        resultados = await asyncio.gather(*[b.allow("7.7.7.7") for b in backends])
        return sum(resultados)

    try:
        admitidos = asyncio.run(scenario())
        assert admitidos == 10, f"se admitieron {admitidos}; el limite era 10"
    finally:
        _limpiar(prefix)


# ------------------------------------------- reinicios y persistencia


@REQUIERE_REDIS
def test_el_contador_sobrevive_a_un_reinicio_del_proceso():
    """Reiniciar el proceso NO reinicia el contador: esta en Redis, no en memoria.

    Con el backend en memoria, un reinicio del worker pone el contador a cero y
    el limite se puede evadir reiniciando. Con Redis no.
    """
    prefix = _prefijo_unico()

    async def scenario():
        backend = RedisBackend(_cliente(), 2, 60.0, prefix=prefix)
        return [await backend.allow("8.8.8.8") for _ in range(2)]

    try:
        # "Proceso 1": agota el limite.
        assert asyncio.run(scenario()) == [True, True]
        # "Proceso 2" (nuevo backend, como tras un reinicio): ya no cabe.
        backend, _ = _backend(limit=2, window=60.0, prefix=prefix)
        assert asyncio.run(backend.allow("8.8.8.8")) is False
    finally:
        _limpiar(prefix)


@REQUIERE_REDIS
def test_el_prefijo_aisla_las_claves_de_otro_servicio():
    """El prefijo evita colisionar con otras claves del mismo Redis.

    Sin prefijo, Gatekeeper escribiria en '1.2.3.4' y podria pisar la clave de
    otra aplicacion que comparte Redis.
    """
    prefix = _prefijo_unico()
    backend, _ = _backend(limit=5, window=60.0, prefix=prefix)
    try:
        asyncio.run(backend.allow("1.2.3.4"))

        import redis as redis_sync

        client = redis_sync.Redis.from_url(REDIS_URL, socket_connect_timeout=2.0,
                                           socket_timeout=2.0, protocol=2)
        existe = client.exists(prefix + "1.2.3.4")
        suelta = client.exists("1.2.3.4")
        client.close()
        assert existe == 1
        assert suelta == 0, "la clave deberia llevar el prefijo, no ir suelta"
    finally:
        _limpiar(prefix)


# ----------------------------------------------- el backend cae de verdad


@REQUIERE_REDIS
def test_redis_caido_durante_el_uso_levanta_backend_unavailable():
    """Si Redis cae durante el uso, el backend lo dice (no falla en silencio)."""
    import redis as redis_sync

    client_roto = redis_sync.Redis.from_url(
        "redis://127.0.0.1:63999/0",  # puerto sin nada escuchando
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
    )
    backend = RedisBackend(client_roto, 5, 60.0)
    with pytest.raises(BackendUnavailable):
        asyncio.run(backend.allow("a"))


@REQUIERE_REDIS
def test_redis_caido_con_fail_open_sigue_admitiendo(caplog):
    """Con la politica por defecto, Redis caido no tumba el servicio."""
    import logging

    async def home(request):
        return PlainTextResponse("ok")

    inner = Starlette(routes=[Route("/", home)])
    mw = GatekeeperMiddleware(inner, config=Config(rate_limit=5, rate_window=60,
                                                   rate_backend="redis",
                                                   redis_url=REDIS_URL))
    # Se fuerza un backend con la conexion rota (Redis real caido).
    mw.limiter = RedisBackend(
        _cliente_roto(), 5, 60.0, prefix=_prefijo_unico()
    )
    client = TestClient(mw)
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        r = client.get("/")
    assert r.status_code == 200, r.text
    assert "rate_backend_error" in caplog.text


@REQUIERE_REDIS
def test_redis_caido_con_fail_closed_devuelve_503():
    """Con rate_fail_open=False, Redis caido se traduce en 503."""
    async def home(request):
        return PlainTextResponse("ok")

    inner = Starlette(routes=[Route("/", home)])
    mw = GatekeeperMiddleware(inner, config=Config(rate_limit=5, rate_window=60,
                                                   rate_backend="redis",
                                                   redis_url=REDIS_URL,
                                                   rate_fail_open=False))
    mw.limiter = RedisBackend(_cliente_roto(), 5, 60.0, prefix=_prefijo_unico())
    client = TestClient(mw)
    assert client.get("/").status_code == 503


def _cliente_roto():
    """Cliente async que no puede conectar (puerto cerrado)."""
    from redis.asyncio import Redis

    return Redis.from_url(
        "redis://127.0.0.1:63999/0",
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
        protocol=2,
    )


# ------------------------------------- el middleware contra Redis de verdad


@REQUIERE_REDIS
def test_el_middleware_limita_a_traves_de_dos_instancias():
    """Dos middlewares (dos workers) sobre el Redis real comparten el limite.

    El cliente `redis.asyncio` queda ligado al event loop en el que se usa. El
    TestClient corre la app en su propio loop, así que el cliente se crea
    DENTRO de la app (en el lifespan): si se crea antes, las peticiones fallan
    con "Event loop is closed".

    La IP es unica por test: el contador vive en Redis y sobrevive entre
    ejecuciones, asi que con la IP por defecto ("testclient") este test
    dependeria de lo que hizo el anterior.
    """
    prefix = _prefijo_unico()
    ip = f"10.9.9.{uuid.uuid4().int % 250 + 1}"

    def worker():
        async def home(request):
            return PlainTextResponse("ok")

        inner = Starlette(routes=[Route("/", home)])
        mw = GatekeeperMiddleware(inner, config=Config(rate_limit=2, rate_window=60,
                                                       rate_backend="redis",
                                                       redis_url=REDIS_URL))

        @inner.router.lifespan_context
        async def lifespan(app):
            # El backend se construye aqui: ya estamos en el loop de la app.
            mw.limiter = RedisBackend(_cliente(), 2, 60.0, prefix=prefix)
            yield

        inner.router.lifespan_context = lifespan
        return TestClient(mw, client=(ip, 1234))

    try:
        with worker() as a, worker() as b:
            assert a.get("/").status_code == 200
            assert b.get("/").status_code == 200
            # El limite es global: el tercero recibe 429, este middleware el sea.
            assert a.get("/").status_code == 429
            assert b.get("/").status_code == 429
    finally:
        _limpiar(prefix)
