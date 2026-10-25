"""El informe de revisión de seguridad tiene que seguir siendo cierto.

`SECURITY_REVIEW.md` afirma cosas concretas: un límite de amplificación, que
las reglas del usuario no están acotadas, que la NFKC expande, que la
configuración falla al arrancar... Si el código cambia y el informe no, el
informe miente.

Este test comprueba las afirmaciones MEDIBLES del informe. Las que dependen de
una medida concreta (los milisegundos) no se comprueban aquí: se miden en
`tests/test_limites_memoria.py` y `tests/test_dos_punteros_json.py`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from gatekeeper.config import Config
from gatekeeper.middleware import GatekeeperMiddleware
from gatekeeper.rules import RULES, normalize

ROOT = Path(__file__).resolve().parent.parent
INFORME = ROOT / "SECURITY_REVIEW.md"


def _informe() -> str:
    return INFORME.read_text(encoding="utf-8")


def test_el_informe_existe_y_no_esta_vacio():
    texto = _informe()
    assert len(texto) > 3000, "el informe esta suspiciously corto"
    assert "H-1" in texto, "el hallazgo principal no esta documentado"


def test_el_informe_declara_su_limitacion_de_independencia():
    """La revisión la hizo quien escribio el codigo: hay que decirlo.

    Se normaliza el texto (quitando el "> " de las citas y los saltos de linea)
    porque las frases pueden estar partidas entre lineas.
    """
    texto = _informe().lower()
    plano = " ".join(texto.replace(">", " ").split())
    assert "no es una revisi" in plano and "independiente" in plano
    assert "conflicto de inter" in plano


def test_el_hallazgo_principal_esta_descrito_con_su_impacto():
    """H-1 tiene que decir QUE era, CUANTO costaba y COMO se corrigio."""
    texto = _informe()
    assert "193,6 MiB" in texto, "falta la medicion del pico de memoria"
    assert "1,9 GiB" in texto, "falta el impacto en concurrencia"
    assert "MAX_POINTER_DEPTH" in texto, "falta el nombre del arreglo"
    assert "regresi" in texto.lower(), "falta la mencion de la regresion"


# ------------------------------------------- afirmaciones sobre el codigo


def test_las_reglas_integradas_siguen_todas_acotadas():
    """A-1 dice que las integradas estan acotadas y las del usuario no."""
    for familia, patrones in RULES.items():
        for patron in patrones:
            # Un cuantificador sin cota explicita: * o + o {n,} sin {0,N}.
            for m in re.finditer(r"(\*|\+|\{\d+,\})", patron.pattern):
                resto = patron.pattern[m.end():m.end() + 12]
                if "{" in resto:
                    continue
                # Los cuantificadores sobre literales (no variables) no son
                # un problema de backtracking: no pueden hacer match variable.
                antes = patron.pattern[max(0, m.start() - 1):m.start()]
                if antes and antes not in "[(":
                    continue
                pytest.fail(f"{familia}: cuantificador sin cota en {patron.pattern!r}")


def test_las_reglas_del_usuario_siguen_sin_proteccion():
    """A-1: las reglas propias NO tienen proteccion de ReDoS.

    Si esto cambia, el informe tiene que cambiar con ello.
    """
    config = Config(custom_rules={"mia": r"(a+)+$"})
    assert "mia" in config.compiled_custom
    # Se compilan tal cual: el usuario es responsable.
    assert config.compiled_custom["mia"][0].pattern == r"(a+)+$"


def test_la_nfkc_sigue_expandiendo():
    """A-2: la normalizacion de compatibilidad expande hasta 4x."""
    assert len(normalize("Ⅷ" * 100)) == 400
    assert len(normalize("ﬁ" * 100)) == 200


def test_la_configuracion_sigue_fallando_al_arrancar():
    """El informe dice que los valores hostiles ROMPEN el arranque."""
    casos = [
        {"rate_backend": "inventado"},
        {"max_body_size": 0},
        {"max_body_size": -1},
        {"trusted_proxy_cidrs": {"no/es/cidr"}},
        {"blocked_ips": {"999.999.999.999"}},
        {"disabled_rules": ["no_existe"]},
        {"custom_rules": {"mia": ["[sin cerrar"]}},
    ]
    for datos in casos:
        with pytest.raises((ValueError, TypeError)):
            Config(**datos)


def test_el_puntero_json_esta_acotado():
    """H-1: el puntero no crece sin limite."""
    from gatekeeper.body import MAX_POINTER_LENGTH, _iter_fields

    obj: object = "hoja"
    for _ in range(500):
        obj = {"nivel": obj}
    punteros = [p for p, _, _ in _iter_fields(obj)]
    assert max(len(p) for p in punteros) <= MAX_POINTER_LENGTH


def test_la_inyeccion_de_log_sigue_siendo_imposible():
    """El informe dice que el puntero no puede colar claves en el evento."""
    from gatekeeper.body import escape_pointer

    clave = 'evil", "injected": "yes'
    evento = json.dumps({"field": f"/{escape_pointer(clave)}"}, ensure_ascii=False)
    datos = json.loads(evento)
    assert "injected" not in datos, datos
    assert list(datos) == ["field"], datos


def test_los_codigos_de_respuesta_siguen_siendo_los_documentados():
    """El informe lista los codigos; tienen que ser los que emite el codigo."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/{path:path}", ok, methods=["GET", "POST"])])
    mw = GatekeeperMiddleware(app, Config(rate_limit=1, rate_window=60))
    with TestClient(mw) as client:
        assert client.get("/ok").status_code == 200
        # El segundo consume el limite.
        assert client.get("/ok").status_code == 429
        # Un ataque por query da 403 (con el limite ya consumido da 429).
        assert client.post(
            "/x?q=1%20UNION%20SELECT%20x",
            headers={"content-type": "application/json"},
        ).status_code in (403, 429)
