"""Reglas de detección por patrones.

LIMITACIÓN CONOCIDA: la detección por regex tiene falsos positivos y falsos
negativos. Gatekeeper es una capa adicional, no sustituye a un WAF ni a
consultas parametrizadas.

Todos los patrones se evalúan sobre texto decodificado y en minúsculas, y los
integrados usan cuantificadores acotados para evitar ReDoS con entradas grandes.
"""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from urllib.parse import unquote_plus

RULES: dict[str, list[re.Pattern[str]]] = {
    # Anti-ReDoS: TODOS los cuantificadores de blancos van acotados (`\s{0,16}`).
    # Dos `\s*` adyacentes sobre la misma racha de espaces son O(n²): medido,
    # `or` + 80.000 espacios tardaba 118 s; con el límite, <1 ms. Si toques una
    # regla, no reintroduzcas `\s*` sin límite (tests/test_fuzz.py lo vigila).
    "sqli": [
        re.compile(r"\bunion\b\s{1,32}(all\s{1,32})?\bselect\b"),
        # tautología booleana: `or 1=1`, `or '1'='1`, `) or (1=1`...
        re.compile(r"\b(or|and)\b\s{0,16}[(']?\s{0,16}['\"]?\d+['\")\]]?\s{0,16}=\s{0,16}['\"]?\d+"),
        # tautología con literales de texto: `or 'a'='a'` (payload `%u2019 or %u2019a%u2019=%u2019a`)
        re.compile(r"\b(or|and)\b\s{0,16}[(']?\s{0,16}['\"][\w-]+['\"]\s{0,16}=\s{0,16}['\"][\w-]+['\"]"),
        # tautología canónica en contexto de parámetro: `?a=1=1`, no prosa con `1=1`
        re.compile(r"(?:^|[?&=,])1\s{0,16}=\s{0,16}1(?:[\s&;]|$)"),
        # consultas apiladas: `; DROP`, `; SELECT`, `; EXEC`...
        re.compile(r";\s{0,16}(select|insert|update|drop|delete|alter|truncate|exec(?:ute)?)\b"),
        re.compile(r"'\s{0,16}(--|#)"),
        # sondeo de columnas: `ORDER BY 10`
        re.compile(r"\border\s{1,16}by\s{1,16}['\"]?\d+"),
        # subconsulta sin filtrar: `EXISTS(SELECT ...)`, `OR (SELECT ...)`
        re.compile(r"\bexists\s{0,16}\(\s{0,16}select\b"),
        # time-based: SLEEP / PG_SLEEP / BENCHMARK / DBMS_PIPE
        re.compile(r"\b(?:pg_|dbms_)?sleep\s{0,16}\(\s{0,16}\d+"),
        re.compile(r"\bbenchmark\s{0,16}\(\s{0,16}\d+"),
        re.compile(r"\bwaitfor\b\s{1,16}delay\b"),
        # error-based: EXTRACTVALUE / UPDATEXML / CONVERT devuelven el error en la respuesta
        re.compile(r"\b(?:extractvalue|updatexml)\s{0,16}\(\s{0,16}\d+\s{0,16},"),
        re.compile(r"\bconvert\s{0,16}\(\s{0,16}int\b"),
        re.compile(r"\bxp_cmdshell\b"),
    ],
    "xss": [
        re.compile(r"<\s{0,16}script"),
        re.compile(r"javascript\s{0,16}:"),
        re.compile(r"<[^<>]{0,200}\bon\w{1,40}\s{0,16}="),
        # evento sin etiqueta delante: `"onmouseover=`, ` onload=` (probe 941101/941120)
        re.compile(
            r"(?:^|[\s'\"`(<])on(?:mouseover|load|error|click|change|submit|focus|blur|toggle)"
            r"\s{0,16}="
        ),
        re.compile(r"<\s{0,16}iframe"),
        re.compile(r"data:text/html"),
    ],
    # `..` solo cuenta como traversal en frontera de segmento: `foo../bar` es un
    # nombre de fichero, no un salto (falso positivo medido contra CRS).
    "path_traversal": [
        re.compile(r"(?<![.\w])\.\./"),
        re.compile(r"(?<![.\w])\.\.\\"),
        re.compile(r"(?<![.\w])\.\.;"),  # `..;/` para saltarse normalizadores
        re.compile(r"/etc/passwd"),
    ],
    # Ficheros que ningún request legítimo debería pedir (LFI / enumeración).
    # Exigen un separador de ruta o de query delante: `?q=me.env` pasa,
    # `?file=/app/.env` y `?path_comp=.ssh/id_rsa` no.
    "sensitive_files": [
        re.compile(r"/etc/(?:passwd|shadow|group|subuid|subgid)\b"),
        re.compile(r"/proc/self/(?:environ|cmdline)\b"),
        re.compile(r"(?:^|[\\/])win\.ini\b"),
        re.compile(r"(?:^|[\\/?=&])\.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys)\b"),
        re.compile(r"(?:^|[\\/?=&])\.aws/credentials\b"),
        re.compile(r"(?:^|[\\/?=&])\.docker/secrets\b"),
        re.compile(r"(?:^|[\\/?=&])\.git/config\b"),
        # `.env` exige separador de ruta: `?q=.env` (búsqueda) pasa, `?file=/app/.env` no
        re.compile(r"(?:^|[\\/])\.env\b"),
    ],
}


_UNICODE_ESCAPE = re.compile(r"%u([0-9a-fA-F]{4})", re.IGNORECASE)


def decode(value: str, max_rounds: int = 3) -> str:
    """Decodifica URL-encoding repetido y escapes `%uXXXX` (IIS/ASP).

    El `%uXXXX` es la codificación Unicode de IIS: `or %U20191%U2019` es
    `or ’1’`. Sin este paso, esa evasión pasa intacta (mayúsculas incluidas).
    """
    for _ in range(max_rounds):
        value = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), value)
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def normalize(value: str, max_rounds: int = 3) -> str:
    """Decodifica, normaliza Unicode, quita comentarios SQL y pasa a minúsculas.

    - `/**/` se trata como espacio en blanco (así lo interpreta MySQL), lo que
      desactiva el ofuscador `uni/**/on/**/select`.
    - NFKC pliega los caracteres de ancho completo: `＜script` (U+FF1C) es
      `<script` para cualquier inspección que no normalice; Gatekeeper sí lo hace.
    - Tras NFKC se decodifica otra vez (pase acotado): la normalización puede
      desvelar escapes escritos en ancho completo (`％Ｕ００２７` → `%U0027` → `'`).
    - Se aplica también a las reglas personalizadas: documentado en el README.
    """
    text = unicodedata.normalize("NFKC", decode(value, max_rounds))
    text = unicodedata.normalize("NFKC", decode(text, max_rounds))
    return text.replace("/**/", " ").lower()


def scan(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
) -> str | None:
    """Devuelve el nombre de la regla que coincide (integrada o personalizada), o None."""
    disabled = disabled or set()
    text = normalize(value)
    groups = list(RULES.items()) + list((extra or {}).items())
    for name, patterns in groups:
        if name in disabled:
            continue
        if any(p.search(text) for p in patterns):
            return name
    return None


def scan_all(
    values: Iterable[str],
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
) -> str | None:
    for value in values:
        rule = scan(value, disabled, extra)
        if rule:
            return rule
    return None
