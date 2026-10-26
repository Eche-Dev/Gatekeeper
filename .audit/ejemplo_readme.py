#!/usr/bin/env python3
"""Genera el ejemplo real del README (respuesta 403 y evento de auditoria).

El README no puede inventar lo que el middleware devuelve: esto lo ejecuta y
lo imprime, para que el ejemplo sea el de verdad.
"""
from __future__ import annotations

import io
import logging

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware

stream = io.StringIO()
handler = logging.StreamHandler(stream)
registro = logging.getLogger("gatekeeper")
registro.setLevel(logging.DEBUG)
registro.addHandler(handler)


async def home(request):  # type: ignore[no-untyped-def]
    return JSONResponse({"ok": True})


app = Starlette(routes=[Route("/", home)])
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))

cliente = TestClient(app)

ataque = cliente.get("/?q=1%27%20OR%20%271%27%3D%271")
print("=== ataque ===")
print("status :", ataque.status_code)
print("body   :", ataque.text)
print("headers:", {k: v for k, v in ataque.headers.items() if k.lower() in {
    "content-type", "x-content-type-options", "x-frame-options",
    "strict-transport-security", "referrer-policy", "permissions-policy",
}})
print("log    :", stream.getvalue().strip())

stream.truncate(0)
stream.seek(0)
normal = cliente.get("/?q=caf%C3%A9")
print()
print("=== trafico normal ===")
print("status :", normal.status_code)
print("body   :", normal.text)
print("log    :", repr(stream.getvalue().strip()))
