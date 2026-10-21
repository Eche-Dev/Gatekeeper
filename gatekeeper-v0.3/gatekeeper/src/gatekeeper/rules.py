"""Reglas de detección por patrones.

LIMITACIÓN CONOCIDA: la detección por regex tiene falsos positivos y falsos
negativos. Gatekeeper es una capa adicional, no sustituye a un WAF ni a
consultas parametrizadas.

Todos los patrones se evalúan sobre texto decodificado y en minúsculas, y los
integrados usan cuantificadores acotados para evitar ReDoS con entradas grandes.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import unquote_plus

RULES: dict[str, list[re.Pattern[str]]] = {
    "sqli": [
        re.compile(r"\bunion\b\s+(all\s+)?\bselect\b"),
        # tautología booleana: `or 1=1`, `or '1'='1`, `) or (1=1`...
        re.compile(r"\b(or|and)\b\s*[(']?\s*['\"]?\d+['\")\]]?\s*=\s*['\"]?\d+"),
        # consultas apiladas: `; DROP`, `; SELECT`, `; EXEC`...
        re.compile(r";\s*(select|insert|update|drop|delete|alter|truncate|exec(?:ute)?)\b"),
        re.compile(r"'\s*(--|#)"),
        # sondeo de columnas: `ORDER BY 10`
        re.compile(r"\border\s+by\s+['\"]?\d+"),
        # subconsulta sin filtrar: `EXISTS(SELECT ...)`, `OR (SELECT ...)`
        re.compile(r"\bexists\s*\(\s*select\b"),
        # time-based: SLEEP / PG_SLEEP / BENCHMARK / DBMS_PIPE
        re.compile(r"\b(?:pg_|dbms_)?sleep\s*\(\s*\d+"),
        re.compile(r"\bbenchmark\s*\(\s*\d+"),
        re.compile(r"\bwaitfor\b\s+delay\b"),
        # error-based: EXTRACTVALUE / UPDATEXML / CONVERT devuelven el error en la respuesta
        re.compile(r"\b(?:extractvalue|updatexml)\s*\(\s*\d+\s*,"),
        re.compile(r"\bconvert\s*\(\s*int\b"),
        re.compile(r"\bxp_cmdshell\b"),
    ],
    "xss": [
        re.compile(r"<\s*script"),
        re.compile(r"javascript\s*:"),
        re.compile(r"<[^<>]{0,200}\bon\w{1,40}\s*="),
        re.compile(r"<\s*iframe"),
        re.compile(r"data:text/html"),
    ],
    "path_traversal": [
        re.compile(r"\.\./"),
        re.compile(r"\.\.\\"),
        re.compile(r"\.\.;"),  # `..;/` para saltarse normalizadores
        re.compile(r"/etc/passwd"),
    ],
    # Ficheros que ningún request legítimo debería pedir (LFI / enumeración).
    # Exigen un separador de ruta delante: `?q=.env` pasa, `?file=/app/.env` no.
    "sensitive_files": [
        re.compile(r"/etc/(?:passwd|shadow|group)\b"),
        re.compile(r"/proc/self/(?:environ|cmdline)\b"),
        re.compile(r"(?:^|[\\/])win\.ini\b"),
        re.compile(r"(?:^|[\\/])\.ssh/id_rsa"),
        re.compile(r"(?:^|[\\/])\.env\b"),
    ],
}


def decode(value: str, max_rounds: int = 3) -> str:
    """Decodifica URL-encoding repetido (anti doble codificación)."""
    for _ in range(max_rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def normalize(value: str, max_rounds: int = 3) -> str:
    """Decodifica, quita comentarios SQL de ofuscación y pasa a minúsculas.

    `/**/` se trata como espacio en blanco (así lo interpreta MySQL), lo que
    desactiva el ofuscador `uni/**/on/**/select`. Se aplica también a las
    reglas personalizadas: documentado en el README.
    """
    return decode(value, max_rounds).replace("/**/", " ").lower()


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
