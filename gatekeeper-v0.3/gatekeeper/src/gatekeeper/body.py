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
    """Lee el body completo. Devuelve (mensajes originales, body) o (mensajes, None) si excede."""
    messages: list[Message] = []
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        messages.append(message)
        if message["type"] != "http.request":
            break  # http.disconnect
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > max_size:
            return messages, None
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return messages, b"".join(chunks)


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


def _iter_fields(obj: Any, pointer: str = "") -> Iterator[tuple[str, str]]:
    """`(puntero, texto)` de todos los textos, claves incluidas (iterativo)."""
    stack: list[tuple[str, Any]] = [(pointer, obj)]
    while stack:
        ptr, cur = stack.pop()
        if isinstance(cur, str):
            yield ptr, cur
        elif isinstance(cur, dict):
            for key, value in cur.items():
                child = f"{ptr}/{_escape_pointer(str(key))}"
                stack.append((child, value))
                stack.append((child, str(key)))
        elif isinstance(cur, list):
            for pos, value in enumerate(cur):
                stack.append((f"{ptr}/{pos}", value))


def extract_strings(content_type: str, body: bytes) -> list[tuple[str, str]]:
    """Extrae `(puntero, texto)` a inspeccionar.

    El puntero identifica el campo en los eventos de auditoría: JSON pointer
    (`/users/0/name`) en JSON, `/campo` en formularios y cadena vacía cuando se
    inspecciona el cuerpo en bruto.
    """
    text = body.decode("utf-8", errors="replace")
    if content_type == "application/x-www-form-urlencoded":
        out: list[tuple[str, str]] = []
        for key, value in parse_qsl(text, keep_blank_values=True):
            ptr = f"/{_escape_pointer(key)}"
            out.append((ptr, key))
            out.append((ptr, value))
        return out
    try:
        obj = json.loads(body)
    except (ValueError, RecursionError):
        return [("", text)]  # JSON inválido o demasiado anidado: se escanea en bruto
    return list(_iter_fields(obj))
