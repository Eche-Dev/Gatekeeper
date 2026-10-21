"""Reglas de detección por patrones.

LIMITACIÓN CONOCIDA: la detección por regex tiene falsos positivos y falsos
negativos. Gatekeeper es una capa adicional, no sustituye a un WAF ni a
consultas parametrizadas.
"""
from __future__ import annotations

import re
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
        re.compile(r"<[^>]*\bon\w+\s*="),
        re.compile(r"<\s*iframe"),
    ],
    "path_traversal": [
        re.compile(r"\.\./"),
        re.compile(r"\.\.\\"),
        re.compile(r"/etc/passwd"),
    ],
}


def normalize(value: str, max_rounds: int = 3) -> str:
    """Decodifica URL-encoding repetido (anti doble codificación) y pasa a minúsculas."""
    for _ in range(max_rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value.lower()


def scan(value: str, disabled: set[str] | None = None) -> str | None:
    """Devuelve el nombre de la regla que coincide, o None."""
    disabled = disabled or set()
    text = normalize(value)
    for name, patterns in RULES.items():
        if name in disabled:
            continue
        if any(p.search(text) for p in patterns):
            return name
    return None
