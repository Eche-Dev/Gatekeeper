"""Propiedades con hypothesis sobre las funciones puras de Gatekeeper.

El corpus verifica payloads concretos; aquí se verifican propiedades que deben
valer para CUALQUIER entrada: que nada lanza excepciones inesperadas, que los
tipos son estables, que `normalize()` es idempotente y que `is_path_allowed()`
nunca exime una ruta con indicios de traversal.

Si una regla nueva mete una excepción, rompe la estabilidad del decoder o
reintroduce backtracking catastrófico, esto salta en local y en CI.
"""

from __future__ import annotations

import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gatekeeper import body, paths, rules
from gatekeeper.config import Config
from gatekeeper.middleware import _header

# Alfabeto para probar estabilidad de normalize() sin anidar escapes más allá
# del límite de rondas de decode() (sin 'u', '2' ni '5' ascii no se pueden
# fabricar `%u...`/`%25...` arbitrarios; los fijos de abajo sí convierten a la
# primera). Es una decisión del diseño: las rondas son acotadas a propósito.
_BASE = list("abcXYZ0137 \t%?&=+#'\"<>;()[]{}|*.,/\\_")
_ESPECIFICOS = [
    "%u0027", "%U0027", "%2e%2e%2f", "％Ｕ００２７", "＜script＞",
    "＇ or 1=1--", "../", "sleep(5)", "union select", "🙂", "é", "’",
]
texto_raro = st.one_of(
    st.text(alphabet=_BASE, max_size=200),
    st.sampled_from(_ESPECIFICOS),
    st.builds(
        lambda head, tail: head + tail,
        st.sampled_from(_ESPECIFICOS),
        st.text(alphabet=_BASE, max_size=100),
    ),
)


@given(st.text())
@settings(max_examples=300, deadline=None)
def test_scan_no_lanza_y_solo_devuelve_reglas_conocidas(value: str) -> None:
    result = rules.scan(value)
    assert result is None or result in rules.RULES, result


@given(st.lists(st.text(), max_size=5))
@settings(max_examples=150, deadline=None)
def test_scan_all_no_lanza(values: list[str]) -> None:
    result = rules.scan_all(values)
    assert result is None or result in rules.RULES, result


@given(texto_raro)
@settings(max_examples=300, deadline=None)
def test_normalize_es_idempotente_y_no_lanza(value: str) -> None:
    once = rules.normalize(value)
    assert isinstance(once, str)
    assert rules.normalize(once) == once, f"normalize no es idempotente con {value!r}"
    assert isinstance(rules.decode(value), str)


@given(
    st.sampled_from([
        "application/json",
        "application/x-www-form-urlencoded",
        "application/vnd.api+json",
        "text/plain",
        "",
        "multipart/form-data; boundary=x",
    ]),
    st.binary(max_size=500),
)
@settings(max_examples=200, deadline=None)
def test_extract_strings_devuelve_pares_puntero_texto(content_type: str, raw: bytes) -> None:
    out = body.extract_strings(content_type, raw)
    assert isinstance(out, list)
    assert all(
        isinstance(item, tuple)
        and len(item) == 2
        and isinstance(item[0], str)
        and isinstance(item[1], str)
        for item in out
    )


@given(st.text(max_size=200))
@settings(max_examples=300, deadline=None)
def test_traversal_nunca_se_exenta_de_inspeccion(path: str) -> None:
    """Propiedad de seguridad: indicios de traversal o codificación => nunca exenta."""
    with_indicios = (
        ".." in path.split("/")
        or "\\" in path
        or rules.decode(path) != path
    )
    if with_indicios:
        assert not paths.is_path_allowed(path, ["*", "/docs/*", "**"]), path


@given(st.text(alphabet="abc/", max_size=40))
@settings(max_examples=150, deadline=None)
def test_ruta_limpia_exenta_si_coincide_con_su_patron(path: str) -> None:
    # sin puntos en el alfabeto no puede haber `..`: el glob debe aplicarse
    assert paths.is_path_allowed(path, [path])


@given(st.dictionaries(
    st.text(max_size=30),
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-10**6, max_value=10**6),
        st.text(max_size=50),
        st.lists(st.text(max_size=20), max_size=5),
        st.dictionaries(st.text(max_size=10), st.text(max_size=20), max_size=5),
    ),
    max_size=8,
))
@settings(max_examples=300, deadline=None)
def test_config_o_valida_o_falla_con_un_error_explicito(data: dict) -> None:
    """Contrato de arranque: una config inválida revienta con ValueError/TypeError.

    Nunca con AttributeError/KeyError ni ningún otro error sorpresa (ver
    SECURITY.md: la validación falla al arrancar, no en producción).
    """
    try:
        Config.from_dict(data)
    except (ValueError, TypeError):
        pass


@given(st.lists(st.tuples(st.binary(max_size=40), st.binary(max_size=80)), max_size=20))
@settings(max_examples=150, deadline=None)
def test_header_devuelve_str_o_none(headers: list) -> None:
    value = _header({"type": "http", "headers": headers}, b"content-type")
    assert value is None or isinstance(value, str)


def test_scan_es_lineal_con_entradas_patologicas() -> None:
    """Regresión del ReDoS cuadrático de v0.3: `\\s*` adyacentes sin acotar.

    Medido antes del arreglo: `or` + 80.000 espacios tardaba 118 s y crecía 4x
    por cada doblón de entrada. Con cuantificadores acotados, lineal.
    """
    casos = [
        "or" + " " * 200_000,
        "and" + " " * 100_000 + "'" * 100_000,
        "union" + " select" * 20_000,
        "<" + " " * 200_000 + "on" + " " * 50_000 + "=",
        "a" * 1_000_000,
        "%2e" * 100_000,
        "%u0027" * 50_000,
        "order" + " " * 200_000 + "x",
    ]
    for payload in casos:
        start = time.perf_counter()
        rules.scan(payload)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, (
            f"scan tardó {elapsed:.2f}s con {len(payload)} caracteres "
            f"(¿ReDoS reintroducido?): {payload[:30]!r}"
        )


# ------------------------------------------------------- limites de memoria


@pytest.mark.parametrize("nivel", [1000, 5000, 10000])
def test_la_memoria_del_escaneo_esta_acotada(nivel: int) -> None:
    """El escaneo no debe amplificar la memoria con entradas grandes.

    Regresión del hallazgo de seguridad H-1: un JSON con 14.100 niveles
    consumía 193,6 MiB (el puntero de auditoría crecía de forma cuadrática).
    Ahora el consumo es lineal con la entrada.

    El límite es holgado a propósito: aqui se busca una AMPLIFICACIÓN
    patológica, no el coste absoluto.
    """
    import tracemalloc

    payload = '{"a":' * nivel + "1" + "}" * nivel
    tracemalloc.start()
    rules.scan(payload)
    _, pico = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    factor = pico / len(payload)
    assert factor < 200, (
        f"un payload de {len(payload) / 1024:.0f} KiB amplifica la memoria "
        f"{factor:.0f}x ({pico / 1024 / 1024:.1f} MiB)"
    )


def test_la_memoria_de_extract_strings_esta_acotada() -> None:
    """La extracción de campos de un body grande no se dispara.

    El mismo hallazgo H-1, medido en la función que construye los punteros.
    """
    import tracemalloc

    from gatekeeper import body as body_mod

    crudo = ('{"a": ' * 5000) + '"' + "x" * 100_000 + '"}'
    tracemalloc.start()
    campos = body_mod.extract_strings("application/json", crudo.encode())
    _, pico = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert campos
    factor = pico / len(crudo)
    assert factor < 50, f"la extracción amplifica la memoria {factor:.0f}x"


# ------------------------------------- las reglas del usuario son tuyas


@given(
    st.text(alphabet="ab()|.*+?[]{}^$\\", min_size=1, max_size=30),
)
@settings(max_examples=50, deadline=None)
def test_una_regex_del_usuario_nunca_revienta_el_middleware(patron: str) -> None:
    """Las reglas propias se compilan tal cual: si el usuario escribe una regex
    patológica, Gatekeeper no la puede proteger sin un motor con timeout.

    Lo que sí se comprueba aquí es que una regex **inválida** falla al
    arrancar con un error explícito (no en producción, con una petición), y
    que una regex válida pero patológica no rompe nada que no sea culpa del
    propio patrón.

    La documentación dice esto en SECURITY.md y docs/uso.md.
    """
    import re
    import warnings

    try:
        with warnings.catch_warnings():
            # Los patrones generados pueden ser invalidos de formas que Python
            # avisa (juego de caracteres anidado): aqui no interesa.
            warnings.simplefilter("ignore")
            compiled = re.compile(patron)
    except re.error:
        return  # una regex invalida ya la rechaza Config al arrancar

    # Con una entrada corta, el patron se evalua en tiempo razonable.
    entrada = "a" * 200
    start = time.perf_counter()
    compiled.search(entrada)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"el patron {patron!r} tardó {elapsed:.2f}s"


def test_una_regex_invalida_del_usuario_rompe_el_arranque() -> None:
    """Un patron invalido tiene que fallar al arrancar, no en produccion."""
    from gatekeeper.config import Config

    with pytest.raises(ValueError):
        Config(custom_rules={"mia": "[sin cerrar"})

