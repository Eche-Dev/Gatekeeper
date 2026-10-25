r"""Regresión: los comentarios SQL sin cierre no pueden costar tiempo cuadrático.

Antes, `re.sub(r"/\*.*?\*/", " ", texto, flags=re.DOTALL)` recorría el resto del
texto por cada `/*` sin cierre: 128 KB de `/*a` tardaban ~21 s y el body admite
1 MiB (~20 min de event loop bloqueado por UNA petición).
"""
import time

import pytest

from gatekeeper.rules import normalize, scan

HOSTILES = {
    "abierto_repetido": "/*a" * 90_000,
    "versionado_repetido": "/*!50000" * 40_000,
    "union_versionado": "union/*!" * 40_000,
    "solo_apertura": "/*!" * 100_000,
    "cierre_solo_al_final": "/*a" * 90_000 + "*/",
}


@pytest.mark.parametrize("nombre", HOSTILES)
def test_comentarios_sin_cierre_son_lineales(nombre):
    texto = HOSTILES[nombre]  # ~270 KB
    inicio = time.perf_counter()
    scan("/?q=" + texto)
    # con la regex anterior esto tardaba decenas de segundos; margen enorme para CI lento
    assert time.perf_counter() - inicio < 3.0


def test_el_coste_crece_de_forma_lineal():
    def coste(n):
        inicio = time.perf_counter()
        normalize("/*a" * n)
        return time.perf_counter() - inicio

    coste(10_000)  # calentamiento
    pequeno, grande = coste(30_000), coste(240_000)  # x8 de tamaño
    # lineal ~x8; cuadrático ~x64. El umbral separa ambos con holgura.
    assert grande < pequeno * 30


@pytest.mark.parametrize(
    "payload",
    [
        "1 /*!50000union*/ /*!50000select*/ 1",
        "1 UnIoN/**/SeLeCt 1",
        "/*c*/union/*c*/select/*c*/1",
    ],
)
def test_sigue_detectando_los_ofuscadores_con_comentarios(payload):
    assert scan("/?q=" + payload) == "sqli"


def test_un_comentario_normal_no_es_un_ataque():
    assert scan("/?q=texto /* nota */ normal") is None
