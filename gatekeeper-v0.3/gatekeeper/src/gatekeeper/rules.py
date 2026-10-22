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
        # blind boolean carácter a carácter: `ASCII(SUBSTRING(p,1,1))>64` — la
        # combinatoria ascii/ord/length sobre substring/mid no aparece en
        # tráfico legítimo y es la firma canónica de la exfiltración ciega
        re.compile(
            r"\b(?:ascii|ord|length|char_length)\s{0,16}\(\s{0,16}"
            r"(?:substring|substr|mid)\s{0,16}\("
        ),
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
        # Java: `/WEB-INF/` es innaccesible por especificación Java EE; pedirlo
        # desde un navegador es exploración, nunca tráfico legítimo
        re.compile(r"(?:^|[\\/?=&])web-inf[/\\]"),
    ],
}


_UNICODE_ESCAPE = re.compile(r"%u([0-9a-fA-F]{4})", re.IGNORECASE)
# Entidades HTML numéricas: `&#60;` es `<` y `&#106;avascript:` es `javascript:`.
# Sin este paso, `&#60;script&#62;alert(1)` pasa intacto por cualquier inspección.
_HTML_ENTITY = re.compile(r"&#(?:x([0-9a-fA-F]{1,6})|(\d{1,7}));", re.IGNORECASE)
# UTF-8 sobre-long: `%c0%af` es una `/` con bytes de más. `unquote` deja los
# bytes inválidos como U+FFFD, así que la forma porcentual se sustituye ANTES
# de decodificar; la forma ya convertida a caracteres (`%u00c0%u00af`) se
# normaliza después. Cualquier servidor que valide el encoding hace lo mismo.
_OVERLONG_MAP = {"%c0%af": "/", "%c0%ae": ".", "%e0%80%af": "/", "%e0%80%ae": "."}
_OVERLONG_PERCENT = re.compile("|".join(map(re.escape, _OVERLONG_MAP)), re.IGNORECASE)
_OVERLONG_CHARS = (
    ("\u00c0\u00af", "/"),
    ("\u00c0\u00ae", "."),
    ("\u00e0\u0080\u00af", "/"),
    ("\u00e0\u0080\u00ae", "."),
)


def _overlong_to_char(match: re.Match[str]) -> str:
    return _OVERLONG_MAP[match.group(0).lower()]


def _entity_to_char(match: re.Match[str]) -> str:
    hexa, decimal = match.group(1), match.group(2)
    code = int(hexa, 16) if hexa else int(decimal, 10)
    # `chr()` lanza con > 0x10FFFF: la entidad se deja tal cual. El fuzzer
    # genera `&#99999999;` y debe seguir pasando sin excepción.
    return match.group(0) if code > 0x10FFFF else chr(code)


def decode(value: str, max_rounds: int = 3) -> str:
    """Decodifica URL-encoding repetido, escapes `%uXXXX` y entidades HTML.

    - `%uXXXX` es la codificación Unicode de IIS: `or %U20191%U2019` es
      `or ’1’`. Sin este paso, esa evasión pasa intacta (mayúsculas incluidas).
    - Entidades numéricas: `&#60;script&#62;` es `<script>`; los rangos se
      acotan para que `&#99999999;` no reviente (`_entity_to_char`).
    - Sobre-long: `%c0%af` → `/` antes de decodificar (`_OVERLONG_PERCENT`)
      y en forma de caracteres después (`_OVERLONG_CHARS`).
    Todo por rondas: cada forma puede revelar la siguiente (`&#38;#60;` →
    `&#60;` → `<`), de ahí que convivan en el mismo ciclo.
    """
    for _ in range(max_rounds):
        antes = value
        value = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), value)
        value = _HTML_ENTITY.sub(_entity_to_char, value)
        value = _OVERLONG_PERCENT.sub(_overlong_to_char, value)
        decoded = unquote_plus(value)
        for overlong, directo in _OVERLONG_CHARS:
            decoded = decoded.replace(overlong, directo)
        # se compara con el INICIO de la ronda: una transformación puede revelar
        # otra sin que el final del pipeline cambie (`&#38;#60;` → `&#60;` → `<`)
        if decoded == antes:
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


def scan_detailed(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
) -> tuple[str, str] | None:
    """Como `scan()`, pero devuelve `(regla, patrón)` — el patrón es el "motivo"
    que se registra en los eventos de auditoría para poder tunear sin adivinar."""
    disabled = disabled or set()
    text = normalize(value)
    groups = list(RULES.items()) + list((extra or {}).items())
    for name, patterns in groups:
        if name in disabled:
            continue
        for pattern in patterns:
            if pattern.search(text):
                return name, pattern.pattern
    return None


def scan(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
) -> str | None:
    """Devuelve el nombre de la regla que coincide (integrada o personalizada), o None."""
    hit = scan_detailed(value, disabled, extra)
    return hit[0] if hit else None


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
