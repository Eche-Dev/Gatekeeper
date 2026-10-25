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

import ipaddress
import math
import time
import uuid
from collections import OrderedDict, deque
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redis.asyncio import Redis

# Prefijo IPv6 que se agrupa al contar (bits). Un /64 es el prefijo mas
# pequeno que se delega de forma rutinaria (RFC 6177): un cliente con un /64
# puede rotar 2^64 direcciones sin cambiar de ISP, asi que contar por
# direccion completa no limita a ese cliente (solo lo retrasa).
DEFAULT_IPV6_PREFIX = 64

# Tope de claves distintas que el backend en memoria recuerda. Medido: sin
# tope, 300.000 IPs distintas costaban ~245 MB de RAM (859 B por clave, casi
# todo el `deque` que se crea por clave). Con el tope, la memoria es acotada
# sea cual sea el numero de IPs que se inventen.
DEFAULT_MAX_KEYS = 10_000

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


def normalize_rate_key(ip: str, ipv6_prefix: int = DEFAULT_IPV6_PREFIX) -> str:
    """Clave de conteo del rate limit para una IP.

    - **IPv4-mapped IPv6** (`::ffff:1.2.3.4`) -> `1.2.3.4`: es la misma
      direccion con dos twitching, y con dos cubos el limite se podria eludir
      solo alternando la forma.
    - **IPv6** -> la direccion de red del prefijo (`/64` por defecto): rotar
      dentro del /64 es el evasion clasica de un limitador por IP.
    - **IPv4** -> la direccion tal cual (agrupar IPv4 por prefijo juntaria a
      Internet entero en el mismo cubo).
    - **Lo que no sea una IP** (p. ej. `unknown`) -> su texto en minusculas,
      para que dos escrituras equivalentes no ocupen dos claves.

    La IP CRUDA se sigue usando en la auditoria: aqui solo se decide de que
    cubo se cuenta.
    """
    value = ip.strip()
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return value.lower()
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        return str(mapped)
    if addr.version == 6:
        red = ipaddress.ip_network(f"{addr}/{ipv6_prefix}", strict=False)
        return str(red.network_address)
    return str(addr)


class RateLimitBackend(Protocol):
    """Contador de peticiones por clave.

    La clave es la salida de `normalize_rate_key`, no la IP cruda: el backend
    no sabe de IPs, solo de claves.
    """

    async def allow(self, key: str) -> bool: ...

    async def retry_after(self, key: str) -> int: ...


class MemoryBackend:
    """Ventana deslizante en memoria, por clave. Un solo proceso.

    ``clock`` es inyectable para tests deterministas (por defecto
    ``time.monotonic``, que no salta con cambios de reloj del sistema).

    ``max_keys`` acota la memoria: como mucho se recuerda ese numero de
    claves distintas. Al llegar al tope se descarta la MAS ANTIGUA (la que
    hace mas que no se usa, no la que se creo antes), y solo si no queda nada
    caducado. Un ataque que inunda de IPs inventadas, en vez de agotar la RAM
    del proceso, desplaza a los cubos viejos: el limite sigue valiendo para
    quien lo necesita y el proceso no crece sin limite.
    """

    def __init__(
        self,
        limit: int,
        window: float,
        clock: Callable[[], float] = time.monotonic,
        prune_interval: int = 1000,
        max_keys: int = DEFAULT_MAX_KEYS,
    ):
        if limit < 1:
            raise ValueError("limit debe ser >= 1")
        if window <= 0:
            raise ValueError("window debe ser mayor que 0")
        if max_keys < 1:
            raise ValueError("max_keys debe ser >= 1")
        if prune_interval < 1:
            raise ValueError("prune_interval debe ser >= 1")
        self.limit = limit
        self.window = window
        self.clock = clock
        self.prune_interval = prune_interval
        self.max_keys = max_keys
        self._calls = 0
        # OrderedDict: el primero es el menos usado (se mueve al final al
        # tocarlo), que es lo que permite evacuar por LRU sin un heap.
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def _prune(self, now: float) -> None:
        stale = [k for k, q in self._hits.items() if not q or now - q[-1] >= self.window]
        for key in stale:
            del self._hits[key]

    def _bucket(self, key: str) -> deque[float]:
        """Cubo de la clave, creandolo si hace falta y respetando el tope.

        Al llegar al tope sale la clave MENOS USADA (la primera del
        `OrderedDict`). Las claves caducadas son, por definicion, las que hace
        mas que no se tocan, asi que son las primeras en salir: no hace falta
        una poda completa aqui. Esa poda es O(n) y, con la tabla llena, se
        dispararia en cada insercion (200.000 IPsDistincts eran 1.900 millones
        de comparaciones). La poda periodica (cada `prune_interval` llamadas)
        es la que retira las claves caducadas.
        """
        q = self._hits.get(key)
        if q is not None:
            self._hits.move_to_end(key)
            return q
        while len(self._hits) >= self.max_keys:
            self._hits.popitem(last=False)
        q = deque()
        self._hits[key] = q
        return q

    async def allow(self, key: str) -> bool:
        now = self.clock()
        self._calls += 1
        if self._calls % self.prune_interval == 0:
            self._prune(now)  # evita crecimiento sin límite con muchas IPs distintas
        q = self._bucket(key)
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

    A diferencia de ``MemoryBackend``, aqui no hay tope de claves: cada clave
    es un ZSET de Redis que caduca a los ``window`` segundos (``PEXPIRE``), de
    modo que la memoria no crece sin limite, pero SI crece con el numero de
    IPs distintas que haya en una ventana. Si eso es un problema, la proteccion
    es del lado de Redis (``maxmemory`` + ``maxmemory-policy``), no del
    middleware. Lo que si hace el middleware es agrupar las IPv6 por /64 (ver
    ``normalize_rate_key``), que es donde se concentran las rotaciones.
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
