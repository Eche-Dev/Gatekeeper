"""Deteccion: el corpus de falsos positivos en espanol e ingles (Fase 3.5).

Este archivo fija el contrato de los 100 casos nuevos del corpus de FP
(50 de desarrollo + 50 retenidos). Se escribio ANTES de tocar las reglas:
al principio fallaba, y las reglas se ajustaron despues.

Metodo (el mismo del resto del proyecto: medir, no creer):

1. Se escribieron 50 casos benignos NUEVOS en `corpus/benign.json` (lote de
   desarrollo, ajustable) y 50 en `corpus/heldout_benign.json` (lote
   retenido, se mide una vez y no se ajusta).
2. Se paso el escaner por los dos lotes y se vio que saltan 13: 10 del lote de
   desarrollo y 3 del retenido.
3. Para cada firma sospechosa se midio cuantos ataques dependen EXCLUSIVAMENTE
   de ella (`.audit/f3_ajustes.py`). Solo se endurecen las que se pueden
   endurecer sin perder detecciones; las demas se DOCUMENTAN como limite
   conocido, que es lo que hace el corpus con el campo `known_fp`.

Firmas endurecidas (y por que):

| Firma | Por que saltaba | Endurecimiento | Ataques que dependen solo de ella |
|---|---|---|---|
| `union all` | «union all» en un tutorial de SQL | exige contexto de consulta detras | 1 de CRS (se recupera con `/`) |
| `waitfor delay` | «waitfor delay» en prosa | exige literal de tiempo detras | 1 propio + 10 de CRS (todos con comilla o digito) |
| `like null` | «like null» en prosa | exige el cierre del payload detras | 1 propio + 2 de CRS (todos al final o entrecomillados) |
| `$ne`, `$or`, `$exists` | operadores NoSQL documentados | exige objeto JSON o parametro | 11 + 4 + 1 (todos con `[`, `"` o `=`) |

Firmas que NO se tocan (limites documentados, con su test):

- `{{config}}`: el ataque de Jinja2 es real y la prosa que lo nombra es rara.
- `${env:...}` y `${jndi}`: familia critica (Log4Shell); la prosa que lo
  documenta es un caso de uso concreto.
- CRLF: un cuerpo con un salto de linea y una cabecera citada.
- La IP de metadata citada en una explicacion (`169.254.169.254`).
"""
from __future__ import annotations

import pytest

from gatekeeper.rules import scan


# ------------------------------------- FP que se quitan (firmas endurecidas)


@pytest.mark.parametrize(
    "payload",
    [
        # «union all» en un tutorial de SQL: la firma de ruta pedia que
        # detras hubiera contexto de consulta («union all select»).
        "/search?q=union+all+en+sql+como+se+usa",
        "/search?q=how+to+use+union+all+in+sqlite",
        # «waitfor delay» explicado: la forma real lleva el tiempo detras
        # («WAITFOR DELAY '0:0:5'»).
        "/search?q=waitfor+delay+en+sql+server",
        # «like null» explicado: la forma real cierra el payload.
        "/search?q=like+null+en+sql+que+significa",
        # Operadores NoSQL documentados: el ataque va dentro de un objeto
        # JSON o de un parametro («user[$ne]=x»).
        "/search?q=que+es+el+operador+$ne+de+mongodb",
        "/search?q=how+to+use+mongodb+$exists+operator",
    ],
)
def test_los_fp_nuevos_no_se_detectan(payload: str):
    hit = scan(payload)
    assert hit is None, f"falso positivo: {payload!r} -> {hit}"


# --------------------------------- referencias: lo que NO puede perderse
#
# Son los ataques reales de los que dependia cada firma endurecida. Si uno
# vuelve a "no detectado", el arreglo ha roto la deteccion y el test lo dice.


@pytest.mark.parametrize(
    "payload",
    [
        # `union all` con contexto de consulta
        "' union all select 1,2,3 from aa",
        "/post/foo/24'union+all+select+1,2,3+from+aa/bar",
        # `union all` pegado a una ruta (CRS 942101 t9/t10)
        "/post/%2A/%2A/2+union+all/bar",
        "/post/foo/9'union+all/bar",
        # `union all` como valor entero (fijado por la Fase 2)
        "/union all",
        # `waitfor delay` con el literal de tiempo
        "WAITFOR DELAY '0:0:5'",
        "waitfor delay'5:0:20'--",
        # `like null` cerrando el payload
        "?id=1 LIKE NULL",
        "/get?var=blahblah&var2=LIKE%20NULL",
        '<?xml version="1.0"?><root><a probe="LIKE NULL"></a></root>',
    ],
)
def test_el_sqli_real_no_se_pierde(payload: str):
    assert scan(payload) == "sqli", payload


@pytest.mark.parametrize(
    "payload",
    [
        "username[$ne]=x",
        '{"user": {"$ne": ""}}',
        "user[%24ne]=x",
        "$where=this.password.match(/^a/)",
        '{"$where": "this.a == this.b"}',
        '{"$regex": ".*", "$options": "i"}',
        '{"$or": [{"a": 1}, {"b": 2}]}',
        '{"$exists": true}',
        "password[$nin][]=root",
        "name[$regex]=^adm",
    ],
)
def test_el_nosql_real_no_se_pierde(payload: str):
    assert scan(payload) == "nosql", payload


# ------------------------------- limites documentados (NO se corrigen)
#
# Estos cuatro si siguen saltando: son limites conocidos, aceptados y
# publicados. El test existe para que nadie los "arregle" sin dar cuenta.


@pytest.mark.parametrize(
    "payload,regla",
    [
        # `{{config}}` es un vector de Jinja2 real; la prosa que lo nombra es
        # rara, pero romper el vector para tapar un FP no sale a cuenta.
        ("plantilla de jinja con {{config}} y variables", "ssti"),
        # La familia Log4Shell es critica: `${env:...}` en un valor es
        # exfiltracion de variables aunque alguien lo cite en un tutorial.
        ("log4j como usar ${env:PATH} en un fichero", "log4shell"),
        ("que significa ${jndi} en log4j", "log4shell"),
        # Un cuerpo con salto de linea y una cabecera citada: el patron CRLF
        # no puede distinguirlo de un intento de response splitting.
        ('{"body": "Hola\\nLocation: Madrid"}', "crlf"),
    ],
)
def test_los_limites_documentados_siguen_saltando(payload: str, regla: str):
    assert scan(payload) == regla, payload


def test_el_fp_de_la_ip_de_metadata_citada_es_ssrf():
    """La IP de metadata en una explicacion sigue saltando (limite conocido)."""
    assert scan("/faq?q=que+es+el+metadata+de+aws+169.254.169.254") == "ssrf"


# ------------------------------------- el pre filtro no debe perder nada
#
# El endurecimiento no puede depender de que el pre filtro deje pasar la
# familia: se comprueba el mismo texto con y sin pre filtro.


@pytest.mark.parametrize(
    "payload,regla",
    [
        ("/post/foo/9'union+all/bar", "sqli"),
        ("WAITFOR DELAY '0:0:5'", "sqli"),
        ("?id=1 LIKE NULL", "sqli"),
        ('{"$exists": true}', "nosql"),
        ("username[$ne]=x", "nosql"),
    ],
)
def test_el_pre_filtro_no_cambia_el_resultado(payload: str, regla: str):
    from gatekeeper.rules import scan_detailed

    con = scan_detailed(payload, use_prefilter=True)
    sin = scan_detailed(payload, use_prefilter=False)
    assert con is not None and con[0] == regla, (payload, con)
    assert sin is not None and sin[0] == regla, (payload, sin)
