"""Prueba de extremo a extremo: una sola peticion HTTP bloquea el servidor?"""
from __future__ import annotations

import sys
import time

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware


async def home(request):
    return PlainTextResponse("ok")


app = Starlette(routes=[Route("/", home, methods=["POST"])])
app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
cliente = TestClient(app)

print("Una sola peticion POST con '/*a' repetido (content-type: text/plain):")
print(f"{'bytes':>10} {'segundos':>10} {'estado':>8}   tiempo de CPU del proceso")
for tam in (8_000, 16_000, 32_000, 64_000):
    cuerpo = ("/*a" * (tam // 3)).encode()
    t0 = time.perf_counter()
    r = cliente.post("/", content=cuerpo, headers={"content-type": "text/plain"})
    dt = time.perf_counter() - t0
    print(f"{len(cuerpo):>10} {dt:>10.3f} {r.status_code:>8}")

print()
print("Referencia (0.4.0 SIN el arreglo): 8 KB 0,142 s | 16 KB 0,336 s |")
print("  32 KB 1,340 s | 64 KB 5,535 s | 128 KB ~23,6 s | 1 MiB ~25 min (x4 por duplicacion).")
print("  Con el arreglo (0.4.1) el tiempo es lineal y 128 KB baja a ~0,016 s.")
