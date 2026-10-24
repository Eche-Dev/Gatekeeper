"""App minima para los tests de servidores ASGI.

Los servidores reales (uvicorn, hypercorn, daphne) se lanzan como subprocesos
y cargan la app desde un modulo importable, no desde una funcion en linea:
daphne ademas la serializa con pickle al arrancar su proceso.

Esta app es la MISMA que usan los tests: el middleware con la configuracion
por defecto, y dos rutas para comprobar el bloqueo y el paso.
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from gatekeeper import Config, GatekeeperMiddleware


async def buscar(request):
    return JSONResponse({"ok": True, "q": request.query_params.get("q", "")})


async def eco(request):
    cuerpo = await request.body()
    return JSONResponse({"ok": True, "len": len(cuerpo)})


_inner = Starlette(routes=[
    Route("/buscar", buscar, methods=["GET"]),
    Route("/eco", eco, methods=["POST"]),
])

app = GatekeeperMiddleware(_inner, Config(rate_limit=100, rate_window=60))
