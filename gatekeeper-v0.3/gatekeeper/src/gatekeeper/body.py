from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qsl

from starlette.types import Message, Receive


def content_type_of(raw: str | None) -> str:
    return (raw or "").split(";")[0].strip().lower()


# Content-types BINARIOS: su contenido no son cadenas que inspeccionar. Todo lo
# demás —incluido el ausente— SÍ se inspecciona: un `text/plain` o un POST sin
# content-type lo parsea `await request.json()` igual, y con la allowlist
# anterior el payload pasaba sin verlo. multipart queda fuera hasta su parser
# propio (v0.4).
_BINARY_CONTENT_TYPES = frozenset({
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/wasm",
    "application/java-archive",
    "application/x-bzip2",
})
_BINARY_PREFIXES = ("image/", "video/", "audio/", "font/")


def is_inspectable(content_type: str) -> bool:
    """True salvo que el body sea binario conocido o multipart (ver arriba)."""
    if not content_type:
        return True
    if content_type == "multipart/form-data":
        return False
    if content_type.startswith(_BINARY_PREFIXES):
        return False
    return content_type not in _BINARY_CONTENT_TYPES


async def read_body(receive: Receive, max_size: int) -> tuple[list[Message], bytes | None]:
    """Lee el body completo. Devuelve (mensajes originales, body) o (mensajes, None) si excede.

    Los bytes se guardan **una sola vez**: los mensajes de ASGI ya llevan el
    `body` de cada fragmento, así que no hace falta una lista de chunks aparte.
    Con la duplicación, un body de 8 MiB ocupaba 16 MiB de memoria (el doble de
    lo que ocupa el body), y el pico de memoria de un proceso era el doble de
    lo que el limite `max_body_size` sugiere.

    El body se devuelve unido (`b"".join`) porque es lo que se inspecciona; los
    mensajes se conservan sueltos para poder reproducirlos tal cual llegaron
    (`replay`), que es lo que espera la app.
    """
    messages: list[Message] = []
    size = 0
    while True:
        message = await receive()
        messages.append(message)
        if message["type"] != "http.request":
            break  # http.disconnect
        size += len(message.get("body", b""))
        if size > max_size:
            return messages, None
        if not message.get("more_body", False):
            break
    return messages, b"".join(m.get("body", b"") for m in messages)


def replay(messages: list[Message], receive: Receive) -> Receive:
    """Reproduce los mensajes ya leídos y después delega en el `receive` original."""
    it = iter(messages)

    async def wrapped() -> Message:
        try:
            return next(it)
        except StopIteration:
            return await receive()

    return wrapped


def _escape_pointer(token: str) -> str:
    """Escapado RFC 6901 para los punteros de campo de los eventos de auditoría."""
    return token.replace("~", "~0").replace("/", "~1")


# Profundidad máxima del puntero JSON que se construye.
#
# El puntero identifica el campo en la auditoría y es lo que se compara con
# `exclude_fields`. Su longitud crece UN NIVEL POR NIVEL: a profundidad N, cada
# puntero mide O(N) caracteres. Con N campos, el total es O(N^2).
#
# Medido: un body de 60 KiB con 10.000 niveles de anidamiento producía 100 MB
# de punteros (193 MB con las tuplas), y 10 peticiones simultáneas llegaban a
# 1,9 GB. Es un DoS con cuerpos pequeños: el `max_body_size` no lo acota,
# porque 60 KiB están muy por debajo de 1 MiB.
#
# El límite corta la cadena por arriba. NO se pierde nada de lo que importa:
#   - `exclude_fields` compara por el ÚLTIMO segmento (`bio`) y por el puntero
#     completo; el último segmento se conserva intacto;
#   - la atribución por campo sigue diciendo QUÉ campo saltó;
#   - lo que se pierde es la RUTA COMPLETA a ese campo, que en un JSON de
#     100 niveles es información de relleno.
#
# 64 niveles cubren de sobra cualquier JSON real (los que usan las APIs
# habituales van de 3 a 10), y dejan el consumo lineal en el tamaño del body.
MAX_POINTER_DEPTH = 64

# Longitud maxima del puntero, en caracteres. El limite de PROFUNDIDAD no
# basta: una sola clave puede tener miles de caracteres, asi que el puntero
# tambien tiene que estar acotado en longitud.
MAX_POINTER_LENGTH = 256

# Longitud maxima de un segmento suelto (una clave). Sin este limite, una
# clave de 10.000 caracteres haria que el puntero fuera enorme aunque el
# numero de segmentos fuera pequeno.
MAX_SEGMENT_LENGTH = 64


def _render_pointer(segmentos: list[str]) -> str:
    """Convierte la lista de segmentos en el puntero final, acotando la longitud.

    La lista esta acotada en NUMERO de segmentos, pero cada segmento puede
    tener varios caracteres (una clave larga), asi que el limite real tiene que
    estar en la LONGITUD de la cadena.

    Cuando hay que recortar, se conservan los dos extremos:
    - el primero (la clave exterior, la que nombra el usuario en
      `exclude_fields`);
    - el ultimo (el campo concreto que salto);
    y se marca el corte con `…`.
    """
    if len(segmentos) <= MAX_POINTER_DEPTH:
        puntero = "/" + "/".join(segmentos)
        if len(puntero) <= MAX_POINTER_LENGTH:
            return puntero

    # Hay que recortar por longitud. Los extremos se recortan ellos mismos si
    # son exageradamente largos: una clave de 10.000 caracteres no puede caber
    # en un puntero de 256.
    primero = _clip_segment(segmentos[0])
    ultimo = _clip_segment(segmentos[-1])
    intermedios = [_clip_segment(s) for s in segmentos[1:-1]]

    # Cuantos intermedios caben, por CARACTERES (no por segmentos): cada uno
    # consume su longitud mas la barra.
    presupuesto = MAX_POINTER_LENGTH - len(primero) - len(ultimo) - len("/…/")
    if presupuesto <= 0:
        # Los dos extremos ya llenan el presupuesto: se quedan ellos y el
        # corte, y nada mas.
        return (f"/{primero}/…/{ultimo}")[:MAX_POINTER_LENGTH]

    mitad_presupuesto = presupuesto // 2

    izquierda = []
    gastado = 0
    for segmento in intermedios:
        coste = len(segmento) + 1
        if gastado + coste > mitad_presupuesto:
            break
        gastado += coste
        izquierda.append(segmento)

    derecha = []
    gastado = 0
    for segmento in reversed(intermedios[len(izquierda):]):
        coste = len(segmento) + 1
        if gastado + coste > mitad_presupuesto:
            break
        gastado += coste
        derecha.append(segmento)
    derecha.reverse()

    if not izquierda and not derecha:
        return f"/{primero}/…/{ultimo}"
    return "/" + "/".join([primero, *izquierda, "…", *derecha, ultimo])


def _clip_segment(segment: str) -> str:
    """Recorta un segmento individual que es demasiado largo.

    Una clave de 10.000 caracteres tiene que caber en el puntero: si no, el
    puntero seguiría siendo enorme y el problema volvería.
    """
    if len(segment) <= MAX_SEGMENT_LENGTH:
        return segment
    return segment[: MAX_SEGMENT_LENGTH - 1] + "…"


def _child_pointer(segmentos: list[str], segment: str) -> list[str]:
    """Añade un segmento a la ruta, manteniendo la lista acotada.

    La lista nunca crece más de `MAX_POINTER_DEPTH + 2` elementos: el primero
    (la clave exterior, que es la que nombra el usuario en `exclude_fields`), un
    `…` en el sitio del corte, y el último (el campo concreto que saltó).
    """
    if len(segmentos) < MAX_POINTER_DEPTH:
        segmentos.append(segment)
        return segmentos
    # Al límite: se descarta el segmento intermedio más antiguo (el segundo,
    # que no es el primero ni el último) y se marca el corte.
    if len(segmentos) > 1 and segmentos[1] != "…":
        segmentos[1] = "…"
    else:
        # Ya marcado: se hace sitio para el nuevo segmento.
        segmentos.insert(-1, segment)
        segmentos.pop(-2)
    return segmentos


def _iter_fields(
    obj: Any, pointer: str = "", include_keys: bool = True
) -> Iterator[tuple[str, str, bool]]:
    """`(puntero, texto, es_clave)` de los campos de texto.

    La ruta se lleva como una LISTA de segmentos acotada (ver
    `MAX_POINTER_DEPTH`): concatenarla como cadena hacia que un JSON
    profundamente anidado consumiese memoria cuadrática.
    """
    inicial = [s for s in pointer.split("/") if s]
    stack: list[tuple[list[str], Any, bool]] = [(inicial, obj, False)]
    while stack:
        segmentos, cur, is_key = stack.pop()
        if is_key:
            yield _render_pointer(segmentos), str(cur), True
        elif isinstance(cur, str):
            yield _render_pointer(segmentos), cur, False
        elif isinstance(cur, dict):
            for key, value in cur.items():
                hijo = _child_pointer(list(segmentos), _escape_pointer(str(key)))
                stack.append((hijo, value, False))
                if include_keys:
                    stack.append((list(hijo), str(key), True))
        elif isinstance(cur, list):
            for pos, value in enumerate(cur):
                stack.append((_child_pointer(list(segmentos), str(pos)), value, False))


def _iter_body_fields(
    content_type: str, body: bytes
) -> Iterator[tuple[str, str, bool]]:
    text = body.decode("utf-8", errors="replace")
    if content_type == "application/x-www-form-urlencoded":
        for key, value in parse_qsl(text, keep_blank_values=True):
            pointer = f"/{_escape_pointer(key)}"
            yield pointer, key, True
            yield pointer, value, False
        return
    try:
        obj = json.loads(body)
    except (ValueError, RecursionError):
        yield "", text, False
        return
    yield from _iter_fields(obj)


def extract_strings(
    content_type: str, body: bytes, include_keys: bool = True
) -> list[tuple[str, str]]:
    """Extrae `(puntero, texto)` a inspeccionar.

    El puntero identifica el campo en los eventos de auditoría: JSON pointer
    (`/users/0/name`) en JSON, `/campo` en formularios y cadena vacía cuando se
    inspecciona el cuerpo en bruto. `include_keys=False` devuelve solo valores
    textuales estructurados.
    """
    return [
        (pointer, value)
        for pointer, value, is_key in _iter_body_fields(content_type, body)
        if include_keys or not is_key
    ]


def extract_strings_and_values(
    content_type: str, body: bytes
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Extrae una vez todos los textos y separa valores de claves."""
    fields: list[tuple[str, str]] = []
    values: list[tuple[str, str]] = []
    for pointer, text, is_key in _iter_body_fields(content_type, body):
        fields.append((pointer, text))
        if not is_key:
            values.append((pointer, text))
    return fields, values
