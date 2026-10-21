import asyncio

from gatekeeper.ratelimit import MemoryBackend


def run(coro):
    return asyncio.run(coro)


def test_blocks_after_limit_and_recovers():
    t = [0.0]
    rl = MemoryBackend(2, 10, clock=lambda: t[0])
    assert run(rl.allow("a")) and run(rl.allow("a"))
    assert not run(rl.allow("a"))
    assert run(rl.allow("b"))  # otra IP no se ve afectada
    t[0] = 11.0
    assert run(rl.allow("a"))


def test_stale_keys_are_pruned():
    t = [0.0]
    rl = MemoryBackend(5, 10, clock=lambda: t[0], prune_interval=5)
    for i in range(10):
        run(rl.allow(f"ip{i}"))
    assert len(rl._hits) == 10
    t[0] = 100.0
    for _ in range(5):
        run(rl.allow("z"))
    assert list(rl._hits) == ["z"]


def test_retry_after_follows_the_window():
    t = [0.0]
    rl = MemoryBackend(1, 10, clock=lambda: t[0])
    assert run(rl.allow("a"))
    assert run(rl.retry_after("a")) == 11  # la más antigua sale en 10 s
    t[0] = 6.0
    assert run(rl.retry_after("a")) == 5
    t[0] = 20.0
    assert run(rl.allow("a"))  # la ventana ya pasó
