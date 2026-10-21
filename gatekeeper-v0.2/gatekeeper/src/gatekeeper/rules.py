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
        re.compile(r"\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"),
        re.compile(r";\s*(drop|alter|truncate|delete)\s"),
        re.compile(r"'\s*(--|#)"),
        re.compile(r"\b(sleep|benchmark)\s*\(\s*\d+"),
    ],
    "xss": [
        re.compile(r"<\s*script"),
        re.compile(r"javascript\s*:"),
        re.compile(r"<[^<>]{0,200}\bon\w{1,40}\s*="),
        re.compile(r"<\s*iframe"),
    ],
    "path_traversal": [
        re.compile(r"\.\./"),
        re.compile(r"\.\.\\"),
        re.compile(r"/etc/passwd"),
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
    """Decodifica y pasa a minúsculas."""
    return decode(value, max_rounds).lower()


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
