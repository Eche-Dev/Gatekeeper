"""El pre filtro de familias no puede cambiar QUÉ se detecta.

Medido: el escaneo cuesta ~57 µs y casi todo son regex de Python corriendo
sobre texto inocuo. El pre filtro descarta antes las familias cuyo literal
obligatorio no aparece, lo que ahorra la mayor parte.

El riesgo evidente de esa optimización es perder una detección por un literal
mal escrito. Estos tests lo cierran comparando pre filtro contra NO-prefiltro
sobre TODO el corpus (propio + los 1379 tests de OWASP CRS), que es la única
forma seria de garantizarlo.
"""
import json
from pathlib import Path

import pytest

from gatekeeper.rules import (
    PREFILTER_LITERALS,
    RULES,
    scan_detailed,
)

CORPUS = Path(__file__).resolve().parents[1] / "corpus"


def _textos() -> list[str]:
    """Todos los valores de los dos corpus.

    OJO: los items del corpus de CRS no tienen un campo `payload`; llevan `uri`,
    `data` y `headers`. Hay que mirar los tres o el test se queda sin comprobar
    1379 casos sin avisar.
    """
    textos: list[str] = []
    ataques = json.loads((CORPUS / "attacks.json").read_text(encoding="utf-8"))
    benignos = json.loads((CORPUS / "benign.json").read_text(encoding="utf-8"))
    textos += [a["payload"] for a in ataques["payloads"]]
    textos += [b["payload"] for b in benignos["payloads"]]
    # El corpus RETENIDO tambien entra: sus payloads son los que mensuran si
    # las reglas generalizan, asi que el pre filtro tiene que cubrirlos igual.
    retenido_a = json.loads((CORPUS / "heldout_attacks.json").read_text(encoding="utf-8"))
    retenido_b = json.loads((CORPUS / "heldout_benign.json").read_text(encoding="utf-8"))
    textos += [a["payload"] for a in retenido_a["payloads"]]
    textos += [b["payload"] for b in retenido_b["payloads"]]
    crs = json.loads((CORPUS / "crs_payloads.json").read_text(encoding="utf-8"))
    for item in crs["payloads"]:
        uri = item.get("uri") or ""
        data = item.get("data") or ""
        cabeceras = item.get("headers") or {}
        completo = uri + ("?" + data if data else "")
        textos.append(completo)
        textos.extend(f"{k}: {v}" for k, v in cabeceras.items())
    return [t for t in textos if t]


TEXTOS = _textos()


def test_corpus_no_esta_vacio():
    # 160 ataques + 132 benignos + 109 retenidos + 140 retenidos benignos
    # + 1379 solicitudes CRS y sus cabeceras.
    assert len(TEXTOS) == 2088, f"el corpus se ha cargado mal: {len(TEXTOS)}"


@pytest.mark.parametrize("texto", TEXTOS)
def test_prefilter_no_cambia_el_resultado(texto):
    """Si una familia dispara sin pre filtro, tiene que disparar con él (corto y >=128 chars)."""
    sin = scan_detailed(texto, use_prefilter=False)
    con = scan_detailed(texto, use_prefilter=True)
    assert con == sin, f"el pre filtro cambió el resultado de {texto[:60]!r}"

    largo = ("a" * 150) + " " + texto
    sin_largo = scan_detailed(largo, use_prefilter=False)
    con_largo = scan_detailed(largo, use_prefilter=True)
    assert con_largo == sin_largo, (
        f"el pre filtro cambió el resultado con relleno >=128 de {texto[:60]!r}: "
        f"con={con_largo}, sin={sin_largo}"
    )


def test_toda_familia_o_tiene_prefiltro_o_no_esta_en_la_tabla():
    """Si una familia nueva no está en la tabla, no se pre filtra (se ejecuta
    siempre): es seguro pero lento. El test lo hace visible para que nadie
    añada una familia y olvide decidir."""
    sin_prefijo = set(RULES) - {f for f, lits in PREFILTER_LITERALS.items() if lits}
    assert sin_prefijo == set(), (
        f"familias sin pre filtro (se ejecutan siempre): {sorted(sin_prefijo)}"
    )


def test_los_prefiltros_no_contienen_lit_vacios():
    for familia, literales in PREFILTER_LITERALS.items():
        assert literales, f"{familia} tiene una lista de literales vacía"
        for literal in literales:
            assert literal == literal.lower(), f"{familia}: {literal!r} no está en minúsculas"
            # Un literal que sea solo un espacio en blanco no filtra nada. La
            # excepcion son los SEPARADORES: en shell, el salto de linea es un
            # separador de comandos igual que el `;`, asi que "\n" es un
            # literal util (descarta la familia en texto de una sola linea).
            separador = literal in ("\n", "\r")
            assert separador or literal.strip(), (
                f"{familia}: el literal {literal!r} es solo espacio"
            )
            # Un literal de 1 carácter solo tiene sentido si es un separador
            # (el backtick de cmdi), no una letra suelta que colaría en cualquier
            # texto.
            assert len(literal) >= 2 or not literal.isalnum(), (
                f"{familia}: el literal {literal!r} es una suelta demasiado común"
            )


def test_prefilter_realmente_descarta_en_texto_inocuo():
    """Si no descartara nada, la optimización no valdría el riesgo."""
    from gatekeeper.rules import _posibles_familias

    inocuo = "/api/v1/users?page=2&limit=50&sort=name"
    posibles = _posibles_familias(inocuo)
    assert len(posibles) < len(RULES), (
        f"el pre filtro solo descartó {len(RULES) - len(posibles)} familias: "
        "los literales son demasiado comunes"
    )
    assert scan_detailed(inocuo) is None


def test_los_prefiltros_se_pueden_desactivar():
    """Si algo inexplicable pasa en producción, se desactiva y se diagnostica."""
    texto = "1' OR '1'='1"
    assert scan_detailed(texto, use_prefilter=False)[0] == "sqli"
    assert scan_detailed(texto, use_prefilter=True)[0] == "sqli"


@pytest.mark.parametrize(
    "payload,regla",
    [
        ("1 GROUP BY 3-- -", "sqli"),
        ("1 HAVING 1=1-- -", "sqli"),
        ("1 INTO OUTFILE '/tmp/x'", "sqli"),
        ("1 AND IF(1=1,1,0)", "sqli"),
        ("1 PROCEDURE ANALYSE()", "sqli"),
        ("/var/log/nginx/access.log", "sensitive_files"),
        ("/var/run/docker.sock", "sensitive_files"),
        ("/var/lib/postgresql/data/pg_hba.conf", "sensitive_files"),
        ("/cgi-bin/.htpasswd", "sensitive_files"),
        ('{"$or": [{"a": 1}]}', "nosql"),
        ('{"$exists": true}', "nosql"),
        ("${T(java.lang.Runtime).getRuntime().exec('id')}", "ssti"),
        ('{"constructor": {"prototype": {"admin": true}}}', "proto_pollution"),
    ],
)
def test_el_prefiltro_no_pierde_detecciones_en_textos_largos(payload, regla):
    """REGRESION: el pre filtro solo se aplica a partir de 128 caracteres.

    Una firma nueva sin su literal en `PREFILTER_LITERALS` funciona en los
    corpus cortos y desaparece en los largos: el pre filtro descarta la familia
    antes de que la regla llegue a evaluarse. Los corpus no lo detectan porque
    casi todos sus payloads son cortos.

    Este test mete el payload detras de 200 caracteres de relleno, que es lo
    que hace un atacante (o un bot) cuando quiere colarse.
    """
    relleno = "A" * 200
    largo = relleno + payload

    sin = scan_detailed(largo, use_prefilter=False)
    con = scan_detailed(largo, use_prefilter=True)

    assert sin is not None, f"el payload {payload!r} no se detecta ni sin pre filtro"
    assert sin[0] == regla, f"{payload!r} deberia dar {regla}, dio {sin[0]}"
    assert con == sin, (
        f"el pre filtro perdio la deteccion de {payload!r} en texto largo: "
        f"con pre filtro {con}, sin pre filtro {sin}. "
        "Falta el literal de la familia en PREFILTER_LITERALS."
    )
