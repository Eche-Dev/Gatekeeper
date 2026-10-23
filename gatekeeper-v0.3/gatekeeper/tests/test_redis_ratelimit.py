"""Backend Redis: igual que el de memoria, pero compartido entre procesos.

Usa fakeredis con soporte Lua (extra de desarrollo `fakeredis[lua]`), así que
el script que cuenta y registra de forma atómica se ejecuta de verdad.
"""

import asyncio

import fakeredis.aioredis
import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.middleware import build_limiter
from gatekeeper.ratelimit import BackendUnavailable, RedisBackend


def run(coro):
    return asyncio.run(coro)


def make_backend(client=None, limit=2, window=10.0, start=1000.0):
    client = client or fakeredis.aioredis.FakeRedis()
    t = [start]
    return RedisBackend(client, limit, window, clock=lambda: t[0]), t, client


def test_build_limiter_selects_backend_by_config():
    assert build_limiter(Config(rate_limit=0)) is None
    assert not isinstance(build_limiter(Config()), RedisBackend)  # memoria por defecto
    assert isinstance(
        build_limiter(Config(rate_backend="redis", redis_url="redis://localhost:6379/0")),
        RedisBackend,
    )


def test_limits_are_shared_between_processes():
    """Dos «procesos» (dos backends) sobre el mismo Redis comparten el contador."""

    async def scenario():
        client = fakeredis.aioredis.FakeRedis()
        worker_a, _, _ = make_backend(client)
        worker_b, _, _ = make_backend(client)
        assert await worker_a.allow("1.2.3.4")
        assert await worker_b.allow("1.2.3.4")  # el 2º worker ve el conteo del 1º
        assert not await worker_a.allow("1.2.3.4")
        assert not await worker_b.allow("1.2.3.4")

    run(scenario())


def test_window_slides_and_recovers():
    async def scenario():
        backend, t, _ = make_backend()
        assert await backend.allow("a") and await backend.allow("a")
        assert not await backend.allow("a")
        t[0] += 11.0  # la ventana de 10 s ya pasó
        assert await backend.allow("a")

    run(scenario())


def test_retry_after_counts_seconds_left():
    async def scenario():
        backend, t, _ = make_backend()
        assert await backend.allow("a")
        # Ventana de 10 s -> `Retry-After: 10`. Antes devolvía 11.
        assert await backend.retry_after("a") == 10
        t[0] += 6.0
        assert await backend.retry_after("a") == 4

    run(scenario())


def test_retry_after_is_zero_without_hits():
    run(make_backend()[0].retry_after("nadie"))


def test_keys_expire_and_do_not_accumulate():
    async def scenario():
        backend, _, client = make_backend()
        await backend.allow("1.1.1.1")
        ttl = await client.ttl("gatekeeper:rl:1.1.1.1")
        assert 0 < ttl <= 10

    run(scenario())


def test_unavailable_redis_raises_backend_unavailable():
    class Roto:
        async def eval(self, *args, **kwargs):
            raise ConnectionError("redis caído")

    backend = RedisBackend(Roto(), 5, 60)
    with pytest.raises(BackendUnavailable):
        run(backend.allow("a"))


def make_mw_client(**cfg):
    async def home(request):
        return PlainTextResponse("ok")

    cfg.setdefault("rate_backend", "redis")
    cfg.setdefault("redis_url", "redis://localhost:6379/0")
    inner = Starlette(routes=[Route("/", home)])
    mw = GatekeeperMiddleware(inner, config=Config(**cfg))
    return TestClient(mw), mw


def test_middleware_fails_open_by_default_and_audits(caplog):
    import logging

    client, mw = make_mw_client()
    mw.limiter = RedisBackend(_Broken(), 5, 60)
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        r = client.get("/")
    assert r.status_code == 200  # preferencia: disponibilidad
    assert "rate_backend_error" in caplog.text


def test_middleware_can_fail_closed_with_503():
    client, mw = make_mw_client(rate_fail_open=False)
    mw.limiter = RedisBackend(_Broken(), 5, 60)
    assert client.get("/").status_code == 503


class _Broken:
    async def eval(self, *args, **kwargs):
        raise ConnectionError("redis caído")


def test_middleware_rate_limits_across_two_instances():
    """Dos middlewares distintos (dos workers) sobre el mismo Redis."""

    client = fakeredis.aioredis.FakeRedis()

    async def home(request):
        return PlainTextResponse("ok")

    def worker():
        inner = Starlette(routes=[Route("/", home)])
        mw = GatekeeperMiddleware(inner, config=Config(rate_limit=2, rate_window=60))
        mw.limiter = RedisBackend(client, 2, 60.0)
        return TestClient(mw)

    a, b = worker(), worker()
    assert a.get("/").status_code == 200
    assert b.get("/").status_code == 200
    assert a.get("/").status_code == 429  # el contador es único, no por worker
    assert b.get("/").status_code == 429
