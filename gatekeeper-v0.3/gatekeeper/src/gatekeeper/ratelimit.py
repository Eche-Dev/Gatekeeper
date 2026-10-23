"""Rate limiting con dos backends intercambiables.

- ``MemoryBackend``: ventana deslizante en memoria. Un solo proceso: con varios
  workers el límite efectivo se multiplica (cada proceso cuenta aparte).
- ``RedisBackend``: ventana deslizante atómica en Redis (script Lua), compartida
  entre todos los procesos y workers. Requiere ``pip install "gatekeeper-asgi[redis]"``.

AMBOS implementan una interfaz ``async`` aunque ``MemoryBackend`` no haga I/O,
para que el middleware no tenga dos caminos de código y para que la decisión de
política (ver más abajo) sea única.

POLÍTICA DE FALLO: si Redis no responde, estos backends lanzan
``BackendUnavailable``. Quien decide qué hacer (seguir admitiendo o devolver 503)
es el middleware, con ``Config.rate_fail_open``. Así el mecanismo y la política
no se mezclan y ambos casos están testeados.
"""
from __future__ import annotations

import math
import time
import uuid
from collections import deque
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redis.asyncio import Redis

# Ventana deslizante atómica: recorta las peticiones fuera de ventana, cuenta
# las que quedan y solo registra la nueva si cabe. Devuelve 1 (permitido) o 0.
_SLIDING_WINDOW = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
if redis.call('ZCARD', key) < limit then
  redis.call('ZADD', key, now, ARGV[4])
  redis.call('PEXPIRE', key, math.ceil(window * 1000))
  return 1
end
return 0
"""

# Segundos enteros que faltan para que la petición más antigua salga de la
# ventana (0 si no hay peticiones registradas).
#
# La petición más antigua sale cuando `now - oldest >= window` (ZREMRANGEBYSCORE
# borra con límite INCLUSIVO), así que faltan `window - (now - oldest)` segundos.
# Se redondea hacia arriba porque `Retry-After` es un entero de segundos: con
# una ventana de 60 s y una petición recién registrada devuelve 60, no 61.
#
# Esta fórmula es la misma que la de MemoryBackend.retry_after: los dos backends
# deben devolver el mismo número, o cambiar de backend cambiaría la cabecera.
_RETRY_AFTER = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
if #oldest == 0 then
  return 0
end
local left = window - (now - tonumber(oldest[2]))
if left <= 0 then
  return 0
end
return math.ceil(left)
"""


class BackendUnavailable(RuntimeError):
    """El backend externo (Redis) no ha respondido o ha fallado."""


class RateLimitBackend(Protocol):
    async def allow(self, key: str) -> bool: ...

    async def retry_after(self, key: str) -> int: ...


class MemoryBackend:
    """Ventana deslizante en memoria, por clave (IP). Un solo proceso.

    ``clock`` es inyectable para tests deterministas (por defecto
    ``time.monotonic``, que no salta con cambios de reloj del sistema).
    """

    def __init__(
        self,
        limit: int,
        window: float,
        clock: Callable[[], float] = time.monotonic,
        prune_interval: int = 1000,
    ):
        self.limit = limit
        self.window = window
        self.clock = clock
        self.prune_interval = prune_interval
        self._calls = 0
        self._hits: dict[str, deque[float]] = {}

    def _prune(self, now: float) -> None:
        stale = [k for k, q in self._hits.items() if not q or now - q[-1] >= self.window]
        for key in stale:
            del self._hits[key]

    async def allow(self, key: str) -> bool:
        now = self.clock()
        self._calls += 1
        if self._calls % self.prune_interval == 0:
            self._prune(now)  # evita crecimiento sin límite con muchas IPs distintas
        q = self._hits.setdefault(key, deque())
        while q and now - q[0] >= self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

    async def retry_after(self, key: str) -> int:
        """Segundos que el cliente debe esperar (`Retry-After`).

        La petición más antigua sale de la ventana cuando `now - q[0] >= window`
        (el límite de la ventana es inclusivo). Faltan `window - (now - q[0])`
        segundos, redondeados hacia ARRIBA porque `Retry-After` es un entero
        de segundos: si faltan 0,3 s, el cliente espera 1 s, no 0.

        Con una ventana de 60 s y una petición recién registrada, esto devuelve
        60 (no 61): el valor es lo que dice la cabecera, no un contador
        desplazado.
        """
        q = self._hits.get(key)
        if not q:
            return 0
        restante = self.window - (self.clock() - q[0])
        if restante <= 0:
            return 0
        return int(math.ceil(restante))


class RedisBackend:
    """Ventana deslizante en Redis, compartida entre procesos y workers.

    Usa un script Lua, así que contar y registrar es atómico: dos workers que
    lleguen a la vez no pueden colarse por encima del límite (algo que un pipeline
    de varios comandos no garantiza).

    El reloj es ``time.time`` (reloj de pared), no ``time.monotonic``: las puntuaciones
    se comparten entre procesos y cada proceso tiene su propio monotónico.

    El cliente es ``redis.asyncio``: la petición a Redis no bloquea el event loop.
    """

    def __init__(
        self,
        client: Redis,
        limit: int,
        window: float,
        prefix: str = "gatekeeper:rl:",
        clock: Callable[[], float] = time.time,
    ):
        self.client = client
        self.limit = limit
        self.window = window
        self.prefix = prefix
        self.clock = clock

    async def allow(self, key: str) -> bool:
        try:
            result = await self.client.eval(
                _SLIDING_WINDOW,
                1,
                self.prefix + key,
                self.window,
                self.limit,
                self.clock(),
                uuid.uuid4().hex,
            )
        except Exception as exc:  # cualquier fallo de Redis es "no disponible"
            raise BackendUnavailable(str(exc)) from exc
        return bool(int(result))

    async def retry_after(self, key: str) -> int:
        try:
            result = await self.client.eval(
                _RETRY_AFTER,
                1,
                self.prefix + key,
                self.window,
                self.clock(),
            )
        except Exception as exc:  # cualquier fallo de Redis es "no disponible"
            raise BackendUnavailable(str(exc)) from exc
        return int(result)
