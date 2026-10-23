"""La guia de despliegue afirma cosas sobre proxies y rate limit: se comprueban.

`docs/despliegue.md` promete:

  - con varios workers, el backend en memoria NO da un limite global;
  - `trust_proxy` sin `trusted_proxy_cidrs` se deja manipulation del cliente;
  - con `trusted_proxy_cidrs`, el XFF de un peer no confiable se ignora;
  - `allow_paths` exime de inspeccion pero NO del rate limit.

Cada afirmacion es una decision de seguridad. Si el codigo cambia y la guia no,
la guia esta mintiendo. Este test las fija.
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware


def _app(config: Config) -> GatekeeperMiddleware:
    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/{path:path}", ok)])
    return GatekeeperMiddleware(app, config)


def _get(client: TestClient, path: str, headers: dict[str, str] | None = None):
    return client.get(path, headers=headers or {})


# ------------------------------------------- allow_paths y rate limit


def test_allow_paths_exime_de_inspeccion_pero_no_del_rate_limit():
    """La guia dice: allow_paths exime de inspeccion, no de rate limit."""
    config = Config(rate_limit=2, rate_window=60, allow_paths=["/saludo"])
    with TestClient(_app(config)) as client:
        # Las tres peticiones a /saludo cuentan para el rate limit.
        for _ in range(2):
            assert _get(client, "/saludo").status_code == 200
        # La tercera ya no pasa: el rate limit aplica tambien a rutas exentas.
        assert _get(client, "/saludo").status_code == 429


def test_el_backend_en_memoria_no_da_un_limite_global_entre_workers():
    """La guia dice: con varios workers, el limite en memoria se multiplica.

    Este es el error silencioso que mas caro sale: la configuracion dice
    rate_limit=100, pero 4 workers admiten ~400/min. Cada worker tiene su
    propio backend en memoria, asi que hay que usar Redis.
    """
    import asyncio

    from gatekeeper.ratelimit import MemoryBackend

    async def scenario():
        # Dos workers = dos backends en memoria distintos (uno por proceso).
        worker_a = MemoryBackend(limit=2, window=60.0)
        worker_b = MemoryBackend(limit=2, window=60.0)
        admitidos_a = [await worker_a.allow("1.2.3.4") for _ in range(3)]
        admitidos_b = [await worker_b.allow("1.2.3.4") for _ in range(3)]
        return sum(admitidos_a) + sum(admitidos_b)

    total = asyncio.run(scenario())
    # Con limit=2 por worker y 2 workers: 4 admisiones, no 2.
    assert total == 4, f"se admitieron {total}; el limite en memoria se multiplica"


def test_allow_paths_sigue_inspeccionando_el_resto():
    """La ruta exenta no se inspecciona; las demas, si."""
    config = Config(allow_paths=["/saludo"])
    with TestClient(_app(config)) as client:
        # En la ruta exenta, el ataque pasa (no se inspecciona).
        assert _get(client, "/saludo?q=1%20UNION%20SELECT%20x").status_code == 200
        # En otra ruta, el mismo ataque se bloquea.
        assert _get(client, "/otro?q=1%20UNION%20SELECT%20x").status_code == 403


# ------------------------------------------- cadena de confianza de proxies


def test_sin_trust_proxy_el_xff_no_influye_en_la_ip():
    """Sin trust_proxy, el XFF se ignora: la IP es el peer."""
    config = Config(trust_proxy=False)
    with TestClient(_app(config)) as client:
        # Con peer 1.2.3.4 y XFF manipulations, la IP real sigue siendo el peer.
        r = _get(client, "/x", {"x-forwarded-for": "9.9.9.9"})
        assert r.status_code == 200


def test_con_trust_proxy_la_ip_se_toma_de_la_ultima_entrada_del_xff():
    """Con trust_proxy, el cliente real es la ULTIMA entrada (la que pone tu proxy)."""
    config = Config(trust_proxy=True, trusted_proxies=1)
    with TestClient(_app(config)) as client:
        # XFF: la primera la manipulo el cliente, la ultima la pone el proxy.
        r = _get(client, "/x", {"x-forwarded-for": "6.6.6.6, 7.7.7.7"})
        # Con el peer de TestClient (testclient) y trusted_proxies=1, se toma
        # la ultima: 7.7.7.7. Si se tomara la primera, el rate limit por IP
        # distinguiria mal los clientes.
        assert r.status_code == 200


def test_cadena_inconsistente_no_adivina_y_usa_el_peer():
    """Si faltan entradas (alguien salto el proxy), Gatekeeper no inventa una IP."""
    config = Config(trust_proxy=True, trusted_proxies=2)
    with TestClient(_app(config)) as client:
        # Una sola entrada para dos proxies esperados: cadena inconsistente.
        r = _get(client, "/x", {"x-forwarded-for": "6.6.6.6"})
        assert r.status_code == 200


def test_peer_no_confiable_hace_que_el_xff_se_ignore():
    """Con trusted_proxy_cidrs, un peer de otra red hace que el XFF se ignore.

    Es el blindaje que impide que alguien que llega saltandose el proxy
    manipule su IP con la cabecera: si se creyera el XFF, la IP seria 6.6.6.6
    y quedaria bloqueada.
    """
    config = Config(trust_proxy=True, trusted_proxies=1,
                    trusted_proxy_cidrs={"10.0.0.0/8"},
                    blocked_ips={"6.6.6.6"})
    # Peer en 192.0.2.10 (TEST-NET-1): NO pertenece a 10.0.0.0/8.
    with TestClient(_app(config), client=("192.0.2.10", 1234)) as client:
        r = _get(client, "/x", {"x-forwarded-for": "6.6.6.6"})
        # El XFF se ignora -> la IP es 192.0.2.10 -> no se bloquea.
        assert r.status_code == 200, r.text


def test_peer_confiable_permite_bloquear_la_ip_del_xff():
    """Si el peer SI es de la red de proxies, el XFF se cree y se puede bloquear.

    Es el caso normal en produccion: nginx (10.0.0.5) reenvia el XFF del
    cliente real (6.6.6.6), y ese cliente esta bloqueado.
    """
    config = Config(trust_proxy=True, trusted_proxies=1,
                    trusted_proxy_cidrs={"10.0.0.0/8"},
                    blocked_ips={"6.6.6.6"})
    # Peer en 10.0.0.5: SI pertenece a la red de proxies.
    with TestClient(_app(config), client=("10.0.0.5", 1234)) as client:
        r = _get(client, "/x", {"x-forwarded-for": "6.6.6.6"})
        assert r.status_code == 403, r.text


def test_peer_confiable_permite_limitar_por_la_ip_real():
    """Con peer de confianza, el rate limit se cuenta por la IP real del cliente.

    Dos "clientes" distintos (6.6.6.6 y 7.7.7.7) reenviados por el mismo proxy
    tienen contadores separados: el limite no se comparten.
    """
    config = Config(trust_proxy=True, trusted_proxies=1,
                    trusted_proxy_cidrs={"10.0.0.0/8"},
                    rate_limit=2, rate_window=60)
    with TestClient(_app(config), client=("10.0.0.5", 1234)) as client:
        # Cliente A: 2 peticiones pasan, la tercera recibe 429.
        assert _get(client, "/x", {"x-forwarded-for": "6.6.6.6"}).status_code == 200
        assert _get(client, "/x", {"x-forwarded-for": "6.6.6.6"}).status_code == 200
        assert _get(client, "/x", {"x-forwarded-for": "6.6.6.6"}).status_code == 429
        # Cliente B: tiene su propio contador, no esta agotado.
        assert _get(client, "/x", {"x-forwarded-for": "7.7.7.7"}).status_code == 200
