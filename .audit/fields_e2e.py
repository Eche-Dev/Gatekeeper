"""Coste end-to-end por peticion segun el numero de campos del body.
Se mide a traves del middleware real (no en aislamiento)."""
from __future__ import annotations

import json
import sys
import time

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware


def make_client(**cfg):
    async def home(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", home, methods=["POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0, **cfg))
    return TestClient(app)


print("=" * 78)
print("COSTE END-TO-END POR PETICION (a traves del middleware real)")
print("=" * 78)
print(f"{'campos':>8} {'KiB body':>9} {'segundos':>9} {'x campos':>9}   estado")
prev = None
for n in (2_500, 5_000, 10_000, 20_000):
    cuerpo = json.dumps({f"campo_{i}": "valor" for i in range(n)}).encode()
    c = make_client()
    t0 = time.perf_counter()
    r = c.post("/", content=cuerpo, headers={"content-type": "application/json"})
    dt = time.perf_counter() - t0
    x = f"{n/prev[0]:.1f}" if prev else "-"
    print(f"{n:>8} {len(cuerpo)/1024:>9.0f} {dt:>9.3f} {x:>9}   {r.status_code}")
    prev = (n, dt)

print()
print("PEOR CASO con max_body_size = 1 MiB (el valor por defecto):")
for etiqueta, n, valor in (("campos cortos", 55_000, "v"), ("claves largas", 26_000, "x" * 20)):
    cuerpo = json.dumps({f"campo_{i}": valor for i in range(n)}).encode()
    if len(cuerpo) > 1_048_576:
        # ajusta n para no pasarse
        continue
    c = make_client()
    t0 = time.perf_counter()
    r = c.post("/", content=cuerpo, headers={"content-type": "application/json"})
    dt = time.perf_counter() - t0
    print(f"  {etiqueta}: {n} campos, {len(cuerpo)/1024:.0f} KiB -> {dt:.2f} s  (status {r.status_code})")

print()
print("Y con inspect_cross_carrier=True (el modo que concatena query + body):")
cuerpo = json.dumps({f"campo_{i}": "valor" for i in range(20_000)}).encode()
for cross in (False, True):
    c = make_client(inspect_cross_carrier=cross)
    t0 = time.perf_counter()
    r = c.post("/", content=cuerpo, headers={"content-type": "application/json"})
    dt = time.perf_counter() - t0
    print(f"  inspect_cross_carrier={cross!s:<5} -> {dt:.2f} s (status {r.status_code})")
