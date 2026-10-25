"""Endurecimiento del rate limit (Fase 2.1).

Cierra tres huecos MEDIDOS, no supuestos:

1. El backend en memoria CRECIA SIN TOPE: 200.000 IPs distintas -> 200.000
   claves y ~175 MB de RAM (875 B por clave, sobre todo el `deque` por clave).
   Ahora la tabla esta acotada (`rate_max_keys`) y al llegar al tope se
   descarta la clave menos usada.
2. La IPv6 se contaba por DIRECCION: quien tiene un /64 (el prefijo delegable
   mas pequeno, RFC 6177) rotaba direcciones sin que el limite se enterase.
   Ahora se agrupa por prefijo (`rate_ipv6_prefix`, /64 por defecto).
3. `blocked_ips` con una entrada en forma IPv4-mapped (`::ffff:1.2.3.4`) era un
   NO-OP SILENCIOSO: se aceptaba al arrancar y no bloqueaba nada, porque la IP
   entrante se normaliza a IPv4 y se comparaba contra una red IPv6.

Cada test fija una garantia observable. Si alguien cambia el rate limit sin
actualizar esto, salta.
"""
from __future__ import annotations

import asyncio
import json
import logging

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.ratelimit import MemoryBackend, normalize_rate_key


def run(coro):
    return asyncio.run(coro)


async def _ok(request):
    return PlainTextResponse("ok")


def make_app(**cfg_kwargs):
    app = Starlette(routes=[Route("/{path:path}", _ok, methods=["GET", "POST"])])
    return GatekeeperMiddleware(app, Config(**cfg_kwargs))


def _peticion(app, ip, method="GET", path="/x"):
    """Peticion ASGI cruda con una IP de cliente concreta."""
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [],
        "client": (ip, 1234),
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    run(app(scope, receive, send))
    return sent[0]


# ------------------------------------------------- la clave de conteo


def test_la_clave_normaliza_el_ipv4_mapped():
    """`::ffff:1.2.3.4` y `1.2.3.4` son el MISMO cubo.

    Sin esto, la misma direccion en dos formularios lleva dos contadores y el
    limite se puede eludir solo alternando la forma.
    """
    assert normalize_rate_key("::ffff:1.2.3.4") == "1.2.3.4"
    assert normalize_rate_key("1.2.3.4") == "1.2.3.4"
    assert normalize_rate_key("::ffff:1.2.3.4") == normalize_rate_key("1.2.3.4")


def test_la_clave_agrupa_las_ipv6_del_mismo_prefijo():
    """Dos direcciones del mismo /64 son el mismo cliente."""
    a = normalize_rate_key("2001:db8:abcd:5600::1")
    b = normalize_rate_key("2001:db8:abcd:5600::dead:beef")
    assert a == b, f"{a} != {b}"
    # Y un /64 DISTINTO es otro cliente (no se agrupa de mas).
    assert normalize_rate_key("2001:db8:abcd:5700::1") != a


def test_el_prefijo_ipv6_es_configurable():
    """Con /128 cada direccion va a su cubo (sin agrupar)."""
    a = normalize_rate_key("2001:db8:abcd:5600::1", ipv6_prefix=128)
    b = normalize_rate_key("2001:db8:abcd:5600::2", ipv6_prefix=128)
    assert a != b


def test_la_clave_no_inventa_agrupaciones_en_ipv4():
    """Agrupar IPv4 por prefijo juntaria a Internet entero en un cubo."""
    assert normalize_rate_key("1.2.3.4") != normalize_rate_key("5.6.7.8")


def test_lo_que_no_es_una_ip_se_normaliza_sin_inventar():
    """Un peer que no es IP (`unknown`) se compara en minusculas."""
    assert normalize_rate_key("  UNKNOWN ") == "unknown"
    assert normalize_rate_key("unknown") == "unknown"


# --------------------------------------------- el tope de claves (memoria)


def test_el_tope_de_claves_acota_la_tabla():
    """Inundar de IPs distintas no puede hacer crecer la tabla sin limite."""
    rl = MemoryBackend(10, 60, max_keys=100)
    for i in range(5_000):
        run(rl.allow(f"10.0.{i // 256}.{i % 256}"))
    assert len(rl._hits) <= 100, f"la tabla tiene {len(rl._hits)} claves"


def test_al_llegar_al_tope_se_descarta_la_clave_menos_usada():
    """La politica es LRU: se va la que hace mas que no se toca."""
    rl = MemoryBackend(10, 60, max_keys=2)
    run(rl.allow("a"))
    run(rl.allow("b"))
    run(rl.allow("a"))  # "a" vuelve a ser la mas reciente
    run(rl.allow("c"))  # entra "c": sale "b", que es la menos usada
    assert "b" not in rl._hits
    assert "a" in rl._hits
    assert "c" in rl._hits


def test_el_limite_por_cliente_sigue_mandando_tras_el_tope():
    """Acotar la tabla no relaja el limite: el cubo nuevo cuenta igual."""
    rl = MemoryBackend(2, 60, max_keys=10)
    for i in range(100):
        run(rl.allow(f"10.0.0.{i}"))
    assert run(rl.allow("recien_llegada"))
    assert run(rl.allow("recien_llegada"))  # el limite son 2 peticiones
    assert not run(rl.allow("recien_llegada"))  # y la tercera cae


def test_lo_caducado_es_lo_primero_que_sale_de_la_tabla():
    """Lo que hace mas que no se toca es lo primero que se descarta.

    Las claves caducadas son, por definicion, las menos usadas, asi que cuando
    la tabla se llena se van ellas y no las que estan en uso.
    """
    t = [0.0]
    rl = MemoryBackend(10, 10, clock=lambda: t[0], max_keys=2)
    run(rl.allow("vieja"))
    run(rl.allow("otra"))
    t[0] = 20.0  # las dos han caducado
    run(rl.allow("nueva"))
    assert "vieja" not in rl._hits
    assert "nueva" in rl._hits


def test_la_insercion_no_poda_en_el_camino_caliente():
    """Meter una clave nueva NO puede disparar una poda O(n).

    Con la tabla llena, podar en cada insercion convertia 200.000 IPs en
    ~1.900 millones de comparaciones: el proceso se hangueaba. La poda es
    periodica (cada `prune_interval` llamadas), no por insercion. Esta guarda
    es determinista: cuenta las podas, no mide tiempos.
    """
    rl = MemoryBackend(10, 60, max_keys=10)
    podas = 0
    original = rl._prune

    def contando(now: float) -> None:
        nonlocal podas
        podas += 1
        original(now)

    rl._prune = contando  # type: ignore[method-assign]
    for i in range(1_000):
        run(rl.allow(f"10.0.0.{i}"))
    assert podas <= 2, f"se podaron {podas} veces con 1.000 inserciones"


def test_el_backend_rechaza_argumentos_absurdos():
    with pytest.raises(ValueError):
        MemoryBackend(0, 60)
    with pytest.raises(ValueError):
        MemoryBackend(10, 0)
    with pytest.raises(ValueError):
        MemoryBackend(10, 60, max_keys=0)


# ------------------------------------------- el efecto en el middleware


def test_rotar_dentro_de_un_64_no_evade_el_limite():
    """La evasion clasica de un limitador por IP: cambiar de direccion IPv6."""
    app = make_app(rate_limit=1, rate_window=60)
    primera = _peticion(app, "2001:db8:abcd:5600::1")
    segunda = _peticion(app, "2001:db8:abcd:5600::2")
    assert primera["status"] == 200, primera
    assert segunda["status"] == 429, segunda


def test_el_ipv4_mapped_comparte_cubo_con_el_ipv4():
    """La misma persona en dos formularios es la misma persona."""
    app = make_app(rate_limit=1, rate_window=60)
    primera = _peticion(app, "::ffff:1.2.3.4")
    segunda = _peticion(app, "1.2.3.4")
    assert primera["status"] == 200, primera
    assert segunda["status"] == 429, segunda


def test_el_429_lleva_retry_after():
    app = make_app(rate_limit=1, rate_window=60)
    _peticion(app, "1.2.3.4")
    segunda = _peticion(app, "1.2.3.4")
    cabeceras = {k.decode(): v.decode() for k, v in segunda["headers"]}
    assert cabeceras.get("retry-after") == "60", cabeceras


def test_la_auditoria_conserva_la_ip_cruda(caplog):
    """Se cuenta por clave normalizada, pero se audita la IP real.

    La IP cruda es el dato que necesita el operador (es la que busca en los
    logs del servidor); la clave normalizada es una decision interna de
    conteo.
    """
    app = make_app(rate_limit=1, rate_window=60)
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        _peticion(app, "::ffff:1.2.3.4")
        _peticion(app, "::ffff:1.2.3.4")
    eventos = [json.loads(r.message) for r in caplog.records if r.name == "gatekeeper"]
    limited = [e for e in eventos if e["event"] == "rate_limited"]
    assert limited, f"no se audito el rate limit: {eventos}"
    assert limited[0]["ip"] == "::ffff:1.2.3.4", limited[0]


# ---------------------------------------------- blocked_ips con IPv4-mapped


def test_blocked_ips_acepta_entradas_ipv4_mapped():
    """`::ffff:127.0.0.1` bloquea las DOS formas de esa direccion."""
    cfg = Config(blocked_ips={"::ffff:127.0.0.1"})
    assert cfg.blocked_match("::ffff:127.0.0.1") == "::ffff:127.0.0.1"
    assert cfg.blocked_match("127.0.0.1") == "::ffff:127.0.0.1"


def test_blocked_ips_acepta_el_rango_ipv4_mapped():
    """`::ffff:0:0/96` es el rango de IPv4-mapped: debe bloquear IPv4."""
    cfg = Config(blocked_ips={"::ffff:0:0/96"})
    assert cfg.blocked_match("1.2.3.4") == "::ffff:0:0/96"
    assert cfg.blocked_match("::ffff:1.2.3.4") == "::ffff:0:0/96"


def test_bloquear_en_ipv4_sigue_bloqueando_el_ipv4_mapped():
    """La direccion de siempre no se ha roto al arreglar la otra forma."""
    cfg = Config(blocked_ips={"127.0.0.1"})
    assert cfg.blocked_match("::ffff:127.0.0.1") == "127.0.0.1"


def test_el_middleware_bloquea_el_ipv4_mapped():
    app = make_app(blocked_ips={"127.0.0.1"})
    r = _peticion(app, "::ffff:127.0.0.1")
    assert r["status"] == 403, r


# ------------------------------------------------------ validacion de config


def test_la_configuracion_invalida_falla_al_arrancar():
    with pytest.raises(ValueError):
        Config(rate_max_keys=0)
    with pytest.raises(ValueError):
        Config(rate_ipv6_prefix=8)
    with pytest.raises(ValueError):
        Config(rate_ipv6_prefix=200)
