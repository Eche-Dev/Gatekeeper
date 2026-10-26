#!/usr/bin/env python3
"""F3.5 - Cuantifica el coste de endurecer las firmas que dan falso positivo.

Para cada firma candidata responde a tres preguntas con MEDIDAS, no con
opiniones:

1. ¿Cuantos payloads de ataque (propio, retenido y CRS) dependen EXCLUSIVAMENTE
   de esa firma? Si son cero, endurecerla no puede perder detecciones.
2. ¿Cuantos falsos positivos elimina la version endurecida?
3. ¿Cuantas detecciones pierde en total (no solo las exclusivas)?

Uso:
    python .audit/f3_ajustes.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "gatekeeper-v0.3" / "gatekeeper"
sys.path.insert(0, str(PKG / "src"))

from gatekeeper.config import DEFAULT_INSPECT_HEADERS  # noqa: E402
from gatekeeper.body import content_type_of, extract_strings, is_inspectable  # noqa: E402
from gatekeeper.rules import RULES, normalize, scan  # noqa: E402

sys.path.insert(0, str(PKG / "tools"))
from evaluate import _crs_carriers  # noqa: E402

CORPUS = PKG / "corpus"

# --- Firmas candidatas: (familia, patron actual, propuesta, descripcion) ------
# La propuesta se evalua SOLO para este patron: el resto de la familia sigue
# igual, asi que se mide el cambio real. El indice se localiza por el patron.
PROPUESTAS: list[tuple[str, str, str, str]] = [
    (
        "sqli", r"union\s{1,32}all",
        r"union\s{1,32}all\s{0,32}(?:select|from|null|values|table|\()",
        "«union all» seguido de contexto de consulta (select/from/null/values/table/()",
    ),
    (
        "sqli", r"\bwaitfor\b\s{1,16}delay\b",
        r"\bwaitfor\b\s{1,16}delay\s{0,8}(?:['\"]|\d)",
        "«waitfor delay» seguido de literal de tiempo (comilla o digito)",
    ),
    (
        "sqli", r"\blike\s{0,8}null\b",
        r"\blike\s{0,8}null\b(?=[\s\w]{0,8}(?:--|#|\)|;|$))",
        "«like null» seguido del final del payload o de un cierre de comentario",
    ),
    (
        "nosql", r"\$\s{0,4}(?:ne|where|regex|nin)\b",
        r"(?:\[\s*|[\"'])\$\s{0,4}(?:ne|where|regex|nin)\b",
        "operador NoSQL dentro de un objeto JSON o de un parametro entre corchetes",
    ),
    (
        "nosql", r"\$\s{0,4}or\b",
        r"(?:\[\s*|[\"'])\$\s{0,4}or\b",
        "«$or» dentro de un objeto JSON o de un parametro entre corchetes",
    ),
    (
        "nosql", r"\$\s{0,4}exists\b",
        r"(?:\[\s*|[\"'])\$\s{0,4}exists\b",
        "«$exists» dentro de un objeto JSON o de un parametro entre corchetes",
    ),
    (
        "ssti",
        r"\{\{[-\w\.\[\]'\",() ]{0,40}(?:config|request|session|application|self|lipsum"
        r"|cycler|namespace|globals|builtins|__class__|__mro__|__subclasses__)"
        r"[-\w\.\[\]'\",() ]{0,40}\}\}",
        r"\{\{[-\w\.\[\]'\",() ]{0,40}(?:config|request|session|application|self|lipsum"
        r"|cycler|namespace|globals|builtins|__class__|__mro__|__subclasses__)"
        r"[-\w\.\[\]'\",() ]{0,40}[.(\[](?:[^\s.(\[]]{0,40})?\}\}",
        "objeto peligroso de plantilla seguido de acceso (. o [), no la variable sola",
    ),
]


def _carga(nombre: str) -> list[dict]:
    return json.loads((CORPUS / nombre).read_text(encoding="utf-8"))["payloads"]


def _ataques_propio() -> list[tuple[str, str]]:
    return [(i["id"], i["payload"]) for i in _carga("attacks.json")]


def _ataques_retenido() -> list[tuple[str, str]]:
    return [(i["id"], i["payload"]) for i in _carga("heldout_attacks.json")]


def _crs() -> list[tuple[str, list[str]]]:
    data = json.loads((CORPUS / "crs_payloads.json").read_text(encoding="utf-8"))
    salida = []
    for item in data["payloads"]:
        carriers, _ = _crs_carriers(item)
        if item.get("expect") == "attack":
            salida.append((item["id"], carriers))
    return salida


def _familias_que_casan(texto: str, saltando: tuple[str, int] | None = None) -> set[str]:
    """Familias que casan con el texto normalizado, saltando un patron."""
    activas = set()
    for nombre, patrones in RULES.items():
        for indice, patron in enumerate(patrones):
            if saltando == (nombre, indice):
                continue
            if patron.search(texto):
                activas.add(nombre)
                break
    return activas


def _dispara_solo(texto: str, familia: str, indice: int) -> bool:
    """¿Esta firma es la UNICA que casa en el texto (familia y patron exactos)?"""
    patron = RULES[familia][indice]
    if not patron.search(texto):
        return False
    for nombre, patrones in RULES.items():
        for i, p in enumerate(patrones):
            if (nombre, i) == (familia, indice):
                continue
            if p.search(texto):
                return False
    return True


def main() -> int:
    propio = _ataques_propio()
    retenido = _ataques_retenido()
    crs = _crs()

    print(f"corpus: propio={len(propio)} retenido={len(retenido)} crs_ataques={len(crs)}\n")

    for familia, actual, nuevo, descripcion in PROPUESTAS:
        # el indice se localiza por el patron: si cambia el orden de RULES,
        # este script sigue diciendo la verdad
        indices = [i for i, p in enumerate(RULES[familia]) if p.pattern == actual]
        if not indices:
            print(f"### {familia}: NO ENCONTRADO {actual!r}")
            continue
        indice = indices[0]
        pat_nuevo = re.compile(nuevo)

        # 1. ataques que dependen SOLO de esta firma
        solo_propio = [i for i, p in propio if _dispara_solo(normalize(p), familia, indice)]
        solo_ret = [i for i, p in retenido if _dispara_solo(normalize(p), familia, indice)]
        solo_crs = [
            i for i, carriers in crs
            if any(_dispara_solo(normalize(c), familia, indice) for c in carriers)
        ]

        # 2. y 3. efecto de la propuesta
        perdidos = []
        for etiqueta, conjunto in (("propio", propio), ("retenido", retenido)):
            for id_, payload in conjunto:
                texto = normalize(payload)
                antes = _familias_que_casan(texto)
                despues = _familias_que_casan(texto, saltando=(familia, indice))
                if (antes - despues):
                    perdidos.append((etiqueta, id_, sorted(antes - despues)))
        perdidos_crs = []
        for id_, carriers in crs:
            antes = set()
            despues = set()
            for c in carriers:
                texto = normalize(c)
                antes |= _familias_que_casan(texto)
                despues |= _familias_que_casan(texto, saltando=(familia, indice))
            if antes - despues:
                perdidos_crs.append((id_, sorted(antes - despues)))

        print(f"### {familia}[{indice}]: {descripcion}")
        print(f"    patron actual : {actual}")
        print(f"    propuesta      : {nuevo}")
        print(f"    dependen SOLO de esta firma: propio={len(solo_propio)} "
              f"{solo_propio or ''} retenido={len(solo_ret)} {solo_ret or ''} "
              f"crs={len(solo_crs)} {solo_crs[:8] or ''}")
        print(f"    detecciones perdidas con la propuesta: propio/retenido={len(perdidos)} "
              f"{perdidos[:6] or ''} crs={len(perdidos_crs)} {perdidos_crs[:6] or ''}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
