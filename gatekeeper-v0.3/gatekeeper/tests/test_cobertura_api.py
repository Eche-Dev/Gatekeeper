"""Cobertura de los caminos de repliegue de la API, el saneado y el rate limit.

Son ramas que solo se dan cuando algo va mal: el paquete no esta instalado,
el `pyproject.toml` no se puede leer, el texto no es un `str`, Redis no
responde. Ninguna se ejercita en el camino feliz, asi que sin estos tests
nadie sabe si siguen funcionando.

No cambia ningun comportamiento: solo se comprueba lo que ya hace el codigo.
"""

from __future__ import annotations

import asyncio

import pytest

from gatekeeper.ratelimit import BackendUnavailable, MemoryBackend, RedisBackend
from gatekeeper.sanitize import sanear


# --------------------------------------------------------------- sanitize
def test_sanear_no_rompe_con_un_texto_que_no_es_una_cadena():
    """El saneado nunca lanza: si no es un `str`, lo devuelve como estaba.

    La comprobacion de tipo la hace quien llama; aqui solo se vigila que el
    saneado no sea el que la haga.
    """
    assert sanear(123) == 123  # type: ignore[arg-type]
    assert sanear(None) is None  # type: ignore[arg-type]


# ------------------------------------------------------- la version del paquete
def test_la_version_desde_fuente_aguanta_un_pyproject_ilegible(monkeypatch):
    """Si el `pyproject.toml` no se puede leer, la version es 'desconocida'.

    Inventar una version seria peor: un `pip install` que cree que hay otra
    version es un problema de verdad.
    """
    import pathlib

    import gatekeeper

    def revienta(*_args: object, **_kwargs: object) -> str:
        raise OSError("no se puede leer")

    monkeypatch.setattr(pathlib.Path, "read_text", revienta)
    assert gatekeeper._version_desde_fuente() == "desconocida"


def test_la_version_desde_fuente_aguanta_un_pyproject_sin_version(monkeypatch):
    """Un `pyproject.toml` sin `version = "..."` no inventa una version."""
    import pathlib

    import gatekeeper

    monkeypatch.setattr(
        pathlib.Path, "read_text", lambda *a, **k: 'name = "gatekeeper-asgi"\n'
    )
    assert gatekeeper._version_desde_fuente() == "desconocida"


def test_la_version_cae_al_arbol_de_fuentes_si_el_paquete_no_esta_instalado(
    monkeypatch,
):
    """Sin el paquete instalado, la version se lee del `pyproject.toml`."""
    import importlib.metadata

    import gatekeeper

    def no_instalado(_nombre: str) -> str:
        raise importlib.metadata.PackageNotFoundError("gatekeeper-asgi")

    monkeypatch.setattr(importlib.metadata, "version", no_instalado)
    version = gatekeeper._version()
    assert version != "desconocida", "deberia leerla del arbol de fuentes"
    assert version[0].isdigit()


# ------------------------------------------------------------- rate limit
def test_el_intervalo_de_poda_no_puede_ser_cero():
    """Un `prune_interval` de 0 haria que la poda se hiciese cada peticion."""
    with pytest.raises(ValueError, match="prune_interval"):
        MemoryBackend(limit=10, window=60.0, prune_interval=0)


def test_la_espera_de_una_clave_que_no_existe_es_cero():
    """Preguntar por una clave que no se ha visto no inventa una espera."""
    backend = MemoryBackend(limit=10, window=60.0)
    assert asyncio.run(backend.retry_after("nunca-vista")) == 0


def test_la_espera_de_una_ventana_caducada_es_cero():
    """Una vez pasada la ventana, no queda nada que esperar."""
    ahora = [1000.0]
    backend = MemoryBackend(limit=10, window=60.0, clock=lambda: ahora[0])
    asyncio.run(backend.allow("ip"))
    ahora[0] += 120.0  # la ventana ya paso
    assert asyncio.run(backend.retry_after("ip")) == 0


def test_redis_caido_se_traduce_a_backend_no_disponible():
    """Un fallo de Redis en `retry_after` es 'no disponible', no una excepcion rara.

    El middleware distingue ese caso (politica fail-open o fail-closed) de un
    fallo de programacion: sin esta traduccion, un Redis caido seria un 500
    en vez de la respuesta que el operador configuro.
    """
    class _RedisQueFalla:
        async def eval(self, *_args: object, **_kwargs: object) -> int:
            raise ConnectionError("redis no responde")

    backend = RedisBackend(_RedisQueFalla(), limit=10, window=60.0)  # type: ignore[arg-type]
    with pytest.raises(BackendUnavailable):
        asyncio.run(backend.retry_after("ip"))
