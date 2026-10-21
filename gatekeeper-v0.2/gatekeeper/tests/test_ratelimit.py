from gatekeeper.ratelimit import RateLimiter


def test_blocks_after_limit_and_recovers():
    t = [0.0]
    rl = RateLimiter(2, 10, clock=lambda: t[0])
    assert rl.allow("a") and rl.allow("a")
    assert not rl.allow("a")
    assert rl.allow("b")  # otra IP no se ve afectada
    t[0] = 11.0
    assert rl.allow("a")


def test_stale_keys_are_pruned():
    t = [0.0]
    rl = RateLimiter(5, 10, clock=lambda: t[0], prune_interval=5)
    for i in range(10):
        rl.allow(f"ip{i}")
    assert len(rl._hits) == 10
    t[0] = 100.0
    for _ in range(5):
        rl.allow("z")
    assert list(rl._hits) == ["z"]
