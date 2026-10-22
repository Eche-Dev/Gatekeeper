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
        # Esquema con separadores que el navegador descarta (WHATWG URL: tab, NL
        # o CR en cualquier punto): `java\tscript:` y `java&#9;script:` siguen
        # siendo ejecutables. SOLO contenedores, no espacios: "java script:"
        # en prosa no es un esquema explotable y no debe saltar.
        re.compile(
            r"j(?:[\t\r\n\x00]{0,4})a(?:[\t\r\n\x00]{0,4})v(?:[\t\r\n\x00]{0,4})"
            r"a(?:[\t\r\n\x00]{0,4})s(?:[\t\r\n\x00]{0,4})c(?:[\t\r\n\x00]{0,4})"
            r"r(?:[\t\r\n\x00]{0,4})i(?:[\t\r\n\x00]{0,4})p(?:[\t\r\n\x00]{0,4})"
            r"t\s{0,16}:"
        ),
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
    # Operadores de inyección NoSQL (Mongo): bypass de login (`user[$ne]=x`),
    # ejecución de JS (`$where`) y exfiltración por regex. `$gt`/`$lt`/`$in`
    # quedan FUERA a propósito: los filtros legítimos pasados por HTTP los usan
    # (`{"price":{"$gt":10}}`, benign-017) y el coste de bloquearlos no compensa.
    # Frontera documentada en docs/amenazas.md.
    "nosql": [
        re.compile(r"\$\s{0,4}(?:ne|where|regex|nin)\b"),
    ],
    # Inyección de comandos: separador shell + binario (los unicos binarios sin
    # separador aceptables son los .exe de Windows, imposibles en prosa).
    "cmdi": [
        re.compile(
            r"(?:;|&&|\|\s{0,4}|\$\(|`)\s{0,8}"
            r"(?:ls|cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|zsh|python\d{0,2}"
            r"|perl|ruby|powershell|cmd|dir|type|chmod|chown"
            r"|rm|cp|mv|kill|ps|env|printenv|hostname|ifconfig|ipconfig|nslookup"
            r"|dig|ping|socat|tar|dd|base64|net|mkdir|rmdir|ln)\b"
            # `;type=json`, `;env=prod` son params con `;` como separador, no
            # comandos: el binario no puede ir seguido de `=`.
            r"(?!\s{0,4}=)"
        ),
        # LOLBins de Windows: con `.exe` no hay prosa que los justifique
        re.compile(
            r"\b(?:cmd|powershell|wscript|cscript|mshta|certutil|rundll32"
            r"|regsvr32|bitsadmin|wmic|ncat)\.exe\b"
        ),
        # PHP con separador (`;system('id')`) y funciones raras sin él
        # (`shell_exec(`): system/exec/assert SOLO con argumento entrecomillado
        # para no bloquear búsquedas como `eval(2+2)`.
        re.compile(
            r"(?:;|&&|\|\s{0,4}|\$\(|`)\s{0,8}"
            r"(?:system|exec|eval|shell_exec|passthru|popen|proc_open"
            r"|pcntl_exec|assert)\s{0,4}\(\s{0,4}['\"]?"
        ),
        re.compile(r"\b(?:shell_exec|passthru|proc_open|pcntl_exec)\s{0,4}\("),
        # reverse shell clásica de bash
        re.compile(r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d{1,5}"),
    ],
    # SSRF: el destino vive en el valor. `localhost`/`127.0.0.1` NO se bloquean
    # (OAuth de desarrollo, webhooks locales: legítimos y muy comunes); sí las
    # IPs de metadata cloud y los esquemas de lectura local.
    "ssrf": [
        re.compile(r"\b169\.254\.169\.254\b"),  # AWS/GCP/Azure/OpenStack IMDS
        re.compile(r"\b169\.254\.170\.2\b"),  # AWS ECS task metadata
        re.compile(r"\b100\.100\.100\.200\b"),  # Alibaba metadata
        re.compile(r"\bmetadata\.google\.internal\b"),
        re.compile(r"\b(?:file|gopher|dict|jar|netdoc|tftp)://"),
    ],
    # SSTI: primero aritmética (`{{7*7}}`, la prueba de canonicidad de todas
    # las plantillas), luego acceso a objetos peligrosos. `{{user.name}}` o
    # `${HOME}` (variables de entorno en prosa) no saltan.
    "ssti": [
        re.compile(r"\{\{\s{0,8}\d{1,6}\s{0,4}[-+*/%]{1,2}\s{0,4}\d{1,6}\s{0,8}\}\}"),
        re.compile(r"\$\{\s{0,8}\d{1,6}\s{0,4}[-+*/%]{1,2}\s{0,4}\d{1,6}\s{0,8}\}"),
        re.compile(r"<%=\s{0,8}\d{1,6}\s{0,4}[-+*/%]{1,2}\s{0,4}\d{1,6}"),
        re.compile(r"\#\{\s{0,8}\d{1,6}\s{0,4}[-+*/%]{1,2}\s{0,4}\d{1,6}"),
        # El interior se limita a lo que aparece DENTRO de una plantilla real
        # (identificadores, puntos, comillas, corchetes, espacios): una llave
        # no puede aparecer ahí, así que una racha de `{` falla en un paso en
        # vez de recorrer 40 posiciones por cada `{` (ReDoS por entrada patológica).
        re.compile(
            r"\{\{[-\w\.\[\]'\",() ]{0,40}"
            r"(?:config|request|session|application|self|lipsum"
            r"|cycler|namespace|globals|builtins|__class__|__mro__|__subclasses__)"
            r"[-\w\.\[\]'\",() ]{0,40}\}\}"
        ),
    ],
    # CRLF / response splitting: el salto de línea DEBE ir seguido de una
    # cabecera, si no toda conversación multilínea sería un falso positivo.
    # Cubre CR/LF reales (decodificados de %0d%0a) y literales `\\r\\n`.
    "crlf": [
        re.compile(
            r"(?:[\r\n]|\\[rn]){1,3}\s{0,8}"
            r"(?:set-cookie|location|content-type|content-length"
            r"|www-authenticate|refresh|strict-transport-security"
            r"|transfer-encoding)\s{0,16}:"
        ),
        re.compile(r"(?:[\r\n]|\\[rn]){1,3}\s{0,8}x-[a-z0-9-]{1,32}\s{0,16}:"),
    ],
    # Log4Shell: cualquier `${jndi` en un valor de request es ataque, no hay
    # uso legítimo; se cubren las ofuscaciones con decoys (`${${::-j}ndi:`)
    # y la cadena de lookups que exfiltra (`${env:AWS_SECRET…}`).
    "log4shell": [
        re.compile(r"\$\{[\s\S]{0,32}jndi"),
        re.compile(r"\$\{::-[a-z]\}ndi|\$\{(?:lower|upper):[a-z]\}ndi"),
        re.compile(r"\$\{(?:\$\{::-[a-z]\}){2,6}"),  # `${${::-j}${::-n}…`
        re.compile(
            r"\bjndi\s{0,4}:\s{0,4}(?:ldaps?|rmi|dns|iiop|corba|nis|nds)\s{0,4}://"
        ),
        re.compile(
            r"\$\{\s{0,4}(?:env|sys|date|java|main|marker|web|ctx|lower|upper"
            r"|spring|k8s):"
        ),
    ],
    # Proto-pollution de JavaScript: `__proto__` en un valor es o ataque o una
    # búsqueda de documentación (FP documentado como benign-0xx, misma familia
    # que `<script>` en búsquedas).
    "proto_pollution": [
        re.compile(r"__proto__"),
        re.compile(r"constructor\s{0,4}[\[.]\s{0,4}prototype"),
    ],
}


_UNICODE_ESCAPE = re.compile(r"%u([0-9a-fA-F]{4})", re.IGNORECASE)
# Entidades HTML numéricas: `&#60;` es `<` y `&#106;avascript:` es `javascript:`.
# Sin este paso, `&#60;script&#62;alert(1)` pasa intacto por cualquier inspección.
_HTML_ENTITY = re.compile(r"&#(?:x([0-9a-fA-F]{1,6})|(\d{1,7}));", re.IGNORECASE)
# Entidades HTML NOMBRADAS (lista acotada, no la tabla HTML5 entera): `&lt;script`
# y `javascript&colon;` son el mismo vector que sus formas numéricas. `&amp;` va
# la última para que `&#38;#60;` y `&amp;lt;` se resuelvan por rondas.
_NAMED_ENTITIES = {
    "lt": "<", "gt": ">", "quot": '"', "apos": "'", "colon": ":", "sol": "/",
    "tab": "\t", "newline": "\n", "bsol": "\\", "period": ".", "comma": ",",
    "num": "#", "amp": "&",
}
_NAMED_ENTITY = re.compile(
    r"&(" + "|".join(sorted(_NAMED_ENTITIES, key=len, reverse=True)) + r");",
    re.IGNORECASE,
)
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


# Comentario versionado de MySQL: el contenido SE EJECUTA si la versión cumple,
# así que se desenvuelve en lugar de borrarlo (un `/*!50000union*/` borrado es
# un payload invisible). Contenido acotado: sin `*/` de cierre no hay carrera.
_VERSIONED_COMMENT = re.compile(r"/\*!\d{0,6}(.{0,200}?)\*/")


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
        value = _NAMED_ENTITY.sub(lambda m: _NAMED_ENTITIES[m.group(1).lower()], value)
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
    - Los comentarios VERSIONADOS `/*!50000union*/` se desenvuelven a su
      contenido (`union`): MySQL los ejecuta, borrarlos ocultaría el payload.
      Contenido acotado a 200 caracteres por si el comentario nunca cierra.
    - NFKC pliega los caracteres de ancho completo: `＜script` (U+FF1C) es
      `<script` para cualquier inspección que no normalice; Gatekeeper sí lo hace.
    - Tras NFKC se decodifica otra vez (pase acotado): la normalización puede
      desvelar escapes escritos en ancho completo (`％Ｕ００２７` → `%U0027` → `'`).
    - Se aplica también a las reglas personalizadas: documentado en el README.
    """
    text = unicodedata.normalize("NFKC", decode(value, max_rounds))
    text = unicodedata.normalize("NFKC", decode(text, max_rounds))
    text = _VERSIONED_COMMENT.sub(r" \1 ", text)
    return text.replace("/**/", " ").lower()


def _family_names() -> tuple[str, ...]:
    return tuple(RULES)


# Packs de reglas: la misma detección, agrupada por lo que una aplicación
# EXIGE de verdad. No cambian ni una línea de los patrones; solo el subconjunto
# de familias que se evalúa, para que un backend sin plantillas no pague (ni
# sufra falsos positivos) por firmas que su superficie no expone.
#
# Todos son OPT-IN: sin `rule_packs` se evalúan las once familias (el defecto
# no cambia respecto a 0.3.1). Configúralo solo si sabes qué expone tu app.
#
# - `minimal`: lo que no depende de la superficie (SQLi y traversal).
# - `api`: APIs JSON/GraphQL sin HTML servido: fuera `xss`, `ssti` y
#   `proto_pollution`; dentro SQLi, NoSQL, traversal, ficheros sensibles y las
#   cuatro de infraestructura (SSRF, Log4Shell, CRLF, comandos).
# - `web`: web pública con HTML: lo de `api` más `xss`. Es el pack que casi
#   todo el mundo quiere; no excluye `ssti` porque un CMS renderiza plantillas.
# - `infrastructure`: solo ataques que llegan por valores que el usuario nunca
#   ve (destinos, cabeceras, logs) — útil como segunda capa tras otra.
# - `strict`: las once familias, sin excluir nada (equivale al defecto).
RULE_PACKS: dict[str, frozenset[str]] = {
    "minimal": frozenset({"sqli", "path_traversal"}),
    "api": frozenset({"sqli", "nosql", "path_traversal", "sensitive_files"}),
    "web": frozenset({"sqli", "xss", "path_traversal", "sensitive_files"}),
    "infrastructure": frozenset({"ssrf", "log4shell", "crlf", "cmdi"}),
}
# `web` y `api` heredan las familias de infraestructura: una web también recibe
# SSRF y Log4Shell por sus formularios, aunque no renderice plantillas.
RULE_PACKS["web"] = frozenset(RULE_PACKS["web"] | RULE_PACKS["infrastructure"])
RULE_PACKS["api"] = frozenset(RULE_PACKS["api"] | RULE_PACKS["infrastructure"])
RULE_PACKS["strict"] = frozenset(_family_names())

PACK_NAMES: tuple[str, ...] = ("minimal", "api", "web", "infrastructure", "strict")


def resolve_rules(packs: Iterable[str] | None = None) -> set[str]:
    """Familias activas según los packs pedidos.

    `None` o lista vacía = **todas** las familias (el defecto histórico: los
    packs son opt-in). Cada nombre debe existir en `RULE_PACKS`; un nombre
    desconocido es `ValueError` al arrancar, no una configuración que en
    silencio deja la app sin protección.
    """
    selected = [str(p).strip() for p in (packs or ()) if str(p).strip()]
    if not selected:
        return set(_family_names())
    familias: set[str] = set()
    for name in selected:
        pack = RULE_PACKS.get(name.lower())
        if pack is None:
            raise ValueError(
                f"Pack de reglas desconocido: '{name}'. Disponibles: {', '.join(PACK_NAMES)}"
            )
        familias |= pack
    return familias


def scan_detailed(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
    only: frozenset[str] | set[str] | None = None,
) -> tuple[str, str] | None:
    """Como `scan()`, pero devuelve `(regla, patrón)` — el patrón es el "motivo"
    que se registra en los eventos de auditoría para poder tunear sin adivinar.

    `only` limita la evaluación a un subconjunto de familias (los packs de
    `Config.active_rules`); las reglas personalizadas de `extra` se evaluan
    siempre, porque son tuyas y las pediste explícitamente.
    """
    disabled = disabled or set()
    text = normalize(value)
    groups = list(RULES.items()) + list((extra or {}).items())
    for name, patterns in groups:
        if name in disabled:
            continue
        if only is not None and name in RULES and name not in only:
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
