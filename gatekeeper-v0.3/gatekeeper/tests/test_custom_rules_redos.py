"""Red de seguridad para las reglas propias (Fase 2.3).

Las reglas integradas de Gatekeeper estan acotadas. Las reglas PROPIAS las
escribe el usuario, y ahi no habia red: `(a+)+$` sobre 60 caracteres no
termina ni en 20 segundos. Ese regex es un DoS en el propio WAF, y no hace
falta adversario: basta con que la regla reciba una entrada adversa.

Lo que se fija aqui:

- el riesgo EXPONENCIAL (cuelga con una entrada corta) se RECHAZA al
  arrancar, no en produccion;
- el riesgo CUADRATICO (se degrada con el tamaño) se AVISA, porque son
  patrones legitimos (una regex de dominio, por ejemplo) y el usuario
  decide;
- los patrones NORMALES no se rechazan: un falso positivo de la validacion
  seria peor que el problema que previene.
"""
from __future__ import annotations

import re
import time

import pytest

from gatekeeper import Config
from gatekeeper.redos import (
    NIVEL_CUADRATICO,
    NIVEL_EXPONENCIAL,
    analizar_redos,
)


# ------------------------------------------------- lo que hay que rechazar


@pytest.mark.parametrize(
    "patron",
    [
        r"(a+)+$",           # cuantificador anidado clasico
        r"(a*)*",
        r"(.*)*",
        r"^(\w+\s?)+$",      # anidado con grupo de palabras
        r"(\d+)*x",          # anidado con clases
        r"(a|a)+",           # alternativas identicas
        r"(a|ab)+",          # una alternativa es prefijo de la otra
        r"(https|http)+",    # el caso clasico de prefijos
        r"(\w+)\1+",         # referencia atras repetida
        r"(\w|\d)+$",        # clases abreviadas solapadas
        r"([a-z]|a)+$",      # rango y literal solapados
        r"(?:(?i:(a+))+)$",  # cuantificador anidado bajo grupo con flag en linea
    ],
)
def test_las_estructuras_catastroficas_se_detectan(patron: str):
    analisis = analizar_redos(patron)
    assert analisis is not None, f"no se ha detectado el riesgo de {patron!r}"
    assert analisis[0] == NIVEL_EXPONENCIAL, f"{patron!r} -> {analisis}"


@pytest.mark.parametrize(
    "patron",
    [
        r"(a+)+$",
        r"(a|a)+",
        r"(https|http)+",
    ],
)
def test_la_configuracion_rechaza_las_reglas_catastroficas(patron: str):
    """El rechazo es al arrancar: `ValueError`, no un fallo en produccion."""
    with pytest.raises(ValueError) as exc:
        Config(custom_rules={"peligrosa": patron})
    assert "ReDoS" in str(exc.value), str(exc.value)


def test_el_mensaje_explica_como_arreglarlo():
    with pytest.raises(ValueError) as exc:
        Config(custom_rules={"peligrosa": r"(a+)+$"})
    mensaje = str(exc.value)
    assert "peligrosa" in mensaje
    assert "allow_unsafe_custom_rules" in mensaje


# --------------------------------------------- lo que NO hay que rechazar


@pytest.mark.parametrize(
    "patron",
    [
        r"\btk_[a-z0-9]{24}\b",       # regla tipica
        r"([a-z0-9_-]+)",             # grupo, sin cuantificar
        r"(?:GET|POST|PUT)",          # alternancia sin repetir
        r"(foo|bar)+",                # alternativas que no se solapan
        r"(\d{1,3}){1,4}",            # cuantificadores acotados
        r"(a{2}){3}",                 # acotado por dentro y por fuera
        r"\[[0-9]{1,3}\]",            # corchetes que no son grupo
        r"\\\(",                     # parentesis escapado
        r"a\|b",                     # pipe escapado
        r"(?:x|y)?z",                 # opcional
    ],
)
def test_los_patrones_normales_no_se_rechazan(patron: str):
    """Falsos positivos de la validacion serian peores que el problema."""
    analisis = analizar_redos(patron)
    assert analisis is None or analisis[0] != NIVEL_EXPONENCIAL, f"{patron!r} -> {analisis}"
    Config(custom_rules={"normal": patron})  # no revienta


def test_un_patron_valido_se_compila_y_funciona():
    cfg = Config(custom_rules={"tk": r"\btk_[a-z0-9]{24}\b"})
    assert cfg.compiled_custom["tk"]
    assert cfg.compiled_custom["tk"][0].search("usa tk_abcdefghijklmnopqrstuvwx")


# ---------------------------------------- el riesgo cuadratico: aviso, no veto


def test_el_patron_de_dominio_no_se_rechaza_pero_se_avisa(caplog):
    r"""`(?:\w+\.)+\w+` es legitimo y se degrada con el tamaño: se avisa.

    Medido: 0,29 s con 10.000 caracteres y 7,4 s con 50.000 (es O(n^2)).
    Rechazarlo seria que el validador dictara la semantica: muchas reglas
    legitimas tienen esa forma.
    """
    patron = r"(?:\w+\.)+\w+"
    analisis = analizar_redos(patron)
    assert analisis is not None, "el patron de dominio deberia verse como riesgo"
    assert analisis[0] == NIVEL_CUADRATICO, analisis

    with caplog.at_level("WARNING", logger="gatekeeper"):
        Config(custom_rules={"dominio": patron})
    assert any("cuadr" in r.getMessage() for r in caplog.records), [
        r.getMessage() for r in caplog.records
    ]


# ------------------------------------------------------------ la salida


def test_hay_una_salida_explicita_para_quien_sabe_lo_que_hace():
    """Con `allow_unsafe_custom_rules=True` se acepta, pero se avisa."""
    cfg = Config(custom_rules={"peligrosa": r"(a+)+$"},
                 allow_unsafe_custom_rules=True)
    assert cfg.compiled_custom["peligrosa"]


def test_la_salida_avisa(caplog):
    with caplog.at_level("WARNING", logger="gatekeeper"):
        Config(custom_rules={"peligrosa": r"(a+)+$"}, allow_unsafe_custom_rules=True)
    assert any("ReDoS" in r.getMessage() for r in caplog.records), [
        r.getMessage() for r in caplog.records
    ]


def test_hay_un_tope_de_numero_de_reglas():
    from gatekeeper.redos import MAX_CUSTOM_RULES

    reglas = {f"r{i}": "x" for i in range(MAX_CUSTOM_RULES + 1)}
    with pytest.raises(ValueError):
        Config(custom_rules=reglas)


def test_hay_un_tope_de_longitud_de_patron():
    from gatekeeper.redos import MAX_PATTERN_LENGTH

    with pytest.raises(ValueError):
        Config(custom_rules={"larga": "x" * (MAX_PATTERN_LENGTH + 1)})


# ---------------------------------------------- el fallo que se corrige


def test_el_patron_catastrofico_no_llega_a_compilarse():
    """La comprobacion es ANTES de compilar: el regex ni se llega a ejecutar."""
    with pytest.raises(ValueError) as exc:
        Config(custom_rules={"peligrosa": r"(a+)+$"})
    # Y el patrón ni siquiera se ha compilado (el error no es de `re`).
    assert "patrón inválido" not in str(exc.value)


def test_la_comprobacion_no_ejecuta_el_regex():
    """Detectar el riesgo no puede ser lento: es un analisis del texto.

    Si la comprobacion ejecutara el patron para medirlo, ella misma seria el
    DoS que quiere evitar.
    """
    patron = r"(a+)+$"
    inicio = time.perf_counter()
    analizar_redos(patron)
    elapsed = time.perf_counter() - inicio
    assert elapsed < 0.1, f"la deteccion tardo {elapsed:.3f} s"


def test_un_regex_invalido_sigue_dando_error_de_compilacion():
    with pytest.raises(ValueError) as exc:
        Config(custom_rules={"rota": "(unbalanced"})
    assert "patrón inválido" in str(exc.value)


def test_re_compila_el_patron_aceptado():
    """Lo que se acepta tiene que compilar de verdad."""
    cfg = Config(custom_rules={"ok": r"(a|b)+"})
    assert isinstance(cfg.compiled_custom["ok"][0], re.Pattern)
