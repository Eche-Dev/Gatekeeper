from gatekeeper.ratelimit import RateLimiter


def test_blocks_after_limit_and_recovers():
    t = [0.0]
    rl = RateLimiter(2, 10, clock=lambda: t[0])
    assert rl.allow("a") and rl.allow("a")
    assert not rl.allow("a")
    assert rl.allow("b")  # otra IP no se ve afectada
    t[0] = 11.0
    assert rl.allow("a")
