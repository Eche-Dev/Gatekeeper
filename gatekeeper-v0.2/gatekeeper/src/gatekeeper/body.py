from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qsl

from starlette.types import Message, Receive


def content_type_of(raw: str | None) -> str:
    return (raw or "").split(";")[0].strip().lower()


def is_inspectable(content_type: str) -> bool:
    return (
        content_type == "application/x-www-form-urlencoded"
        or content_type == "application/json"
        or content_type.endswith("+json")
    )


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


def _iter_strings(obj: Any) -> Iterator[str]:
    stack = [obj]  # iterativo: sin recursión por anidamiento
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            yield cur
        elif isinstance(cur, dict):
            stack.extend(cur.keys())
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)


def extract_strings(content_type: str, body: bytes) -> list[str]:
    """Extrae los textos a inspeccionar (claves y valores)."""
    text = body.decode("utf-8", errors="replace")
    if content_type == "application/x-www-form-urlencoded":
        out: list[str] = []
        for key, value in parse_qsl(text, keep_blank_values=True):
            out.extend((key, value))
        return out
    try:
        obj = json.loads(body)
    except (ValueError, RecursionError):
        return [text]  # JSON inválido o demasiado anidado: se escanea en bruto
    return list(_iter_strings(obj))
