"""Prueba reproducible del rate limiter (Fase 2.1).

Muestra, contra el codigo tal cual esta:

1. Cuanto crece ``MemoryBackend._hits`` con IPs distintas (tope de claves).
2. Que ``blocked_ips`` bloquea la forma IPv4-mapped de una IP bloqueada.
3. Que las IPv6 de un mismo /64 cuentan en un solo cubo.

Uso (desde ``gatekeeper-v0.3/gatekeeper``)::

    python .audit/rl_probe.py
"""
from __future__ import annotations

import asyncio
import tracemalloc

from gatekeeper.config import Config
from gatekeeper.ratelimit import MemoryBackend, normalize_rate_key

IPS = 200_000


async def main() -> None:
    # 1. Crecimiento con tope --------------------------------------------------
    rl = MemoryBackend(100, 60)
    tracemalloc.start()
    for i in range(IPS):
        await rl.allow(f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}")
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"1. {IPS} IPs distintas -> {len(rl._hits)} claves, "
          f"{current / 1e6:.1f} MB (pico {peak / 1e6:.1f} MB)")
    print(f"   tope configurado: {rl.max_keys} claves")

    # 2. blocked_ips con IPv4-mapped -------------------------------------------
    literal = Config(blocked_ips=["127.0.0.1"])
    mapped = Config(blocked_ips=["::ffff:127.0.0.1"])
    rango = Config(blocked_ips=["::ffff:0:0/96"])
    print(f"2. blocked_ips=['127.0.0.1'] vs '::ffff:127.0.0.1' -> "
          f"{literal.blocked_match('::ffff:127.0.0.1')!r}")
    print(f"   blocked_ips=['::ffff:127.0.0.1'] vs '127.0.0.1' -> "
          f"{mapped.blocked_match('127.0.0.1')!r}")
    print(f"   blocked_ips=['::ffff:0:0/96'] vs '1.2.3.4' -> "
          f"{rango.blocked_match('1.2.3.4')!r}")

    # 3. Rotacion IPv6 dentro de un /64 ----------------------------------------
    rl6 = MemoryBackend(5, 60)
    for i in range(10):
        await rl6.allow(normalize_rate_key(f"2001:db8:abcd:5600::{i:x}"))
    print(f"3. 10 direcciones del mismo /64 -> {len(rl6._hits)} clave(s) "
          f"(deberia ser 1)")


if __name__ == "__main__":
    asyncio.run(main())
