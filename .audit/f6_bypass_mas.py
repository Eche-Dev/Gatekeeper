#!/usr/bin/env python3
"""F6.4: el `+` de un FORM BODY. ¿El middleware inspecciona lo mismo que la app?

Contexto:
- En la RUTA/QUERY, el texto crudo se decodifica una vez con `unquote_plus`
  (ronda 0) y las siguientes con `unquote`: el `+` (operador de MySQL) sobrevive.
- En el BODY, el valor sale de `parse_qsl` YA decodificado, y despues `normalize()`
  le aplica `unquote_plus` OTRA VEZ (ronda 0): el `+` se convierte en espacio.

Si eso es cierto, `q=sleep(10%2B6)` llega a la app como "sleep(10+6)" (que MySQL
ejecuta: 10+6=16 segundos) pero el middleware inspecciona "sleep(10 6)" (que no
detecta ninguna regla).
"""
from __future__ import annotations

import json
import sys
from urllib.parse import parse_qsl

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")

from starlette.applications import Starlette  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from gatekeeper import Config, GatekeeperMiddleware  # noqa: E402
from gatekeeper.body import extract_strings  # noqa: E402
from gatekeeper.rules import normalize, scan_detailed  # noqa: E402

CASOS = [
    ("form body con %2B (operador MySQL)", b"q=sleep(10%2B6)",
     "application/x-www-form-urlencoded"),
    ("form body con + crudo", b"q=sleep(10+6)",
     "application/x-www-form-urlencoded"),
    ("json con + crudo", b'{"q":"sleep(10+6)"}', "application/json"),
    ("query con %2B (lo ya arreglado)", None, None),
]


async def eco(request):
    """Lo que la APLICACION ve: su propio parseo del body."""
    info = {"crudo": (await request.body()).decode("utf-8", "replace")}
    try:
        info["form"] = [[k, str(v)] for k, v in (await request.form()).multi_items()]
    except Exception as exc:  # noqa: BLE001
        info["form_error"] = type(exc).__name__
    try:
        info["json"] = await request.json()
    except Exception as exc:  # noqa: BLE001
        info["json_error"] = type(exc).__name__
    return JSONResponse(info)


def app(con_middleware: bool) -> Starlette:
    a = Starlette(routes=[Route("/eco", eco, methods=["GET", "POST"])])
    if con_middleware:
        a.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    return a


print("=" * 78)
for nombre, body, ctype in CASOS:
    if body is None:
        # La query: el texto crudo que ve el middleware.
        crudo = "/x?q=sleep(10%2B6)"
        print(f"\n{nombre}")
        print(f"  crudo que escanea el middleware : {crudo!r}")
        print(f"  tras normalize()                : {normalize(crudo)!r}")
        print(f"  scan_detailed                   : {scan_detailed(crudo)}")
        continue

    print(f"\n{nombre}")
    print(f"  body crudo                      : {body!r}")
    print(f"  parse_qsl (lo que ve la app)    : {parse_qsl(body.decode())}")
    campos = extract_strings(ctype, body)
    print(f"  extract_strings (lo que ve el MW): {campos}")
    if campos:
        valor = campos[0][1]
        print(f"  tras normalize()                : {normalize(valor)!r}")
        print(f"  scan_detailed del valor crudo   : {scan_detailed(valor)}")
        print(f"  scan_detailed tras normalize    : {scan_detailed(normalize(valor))}")

    cabeceras = {"content-type": ctype}
    with TestClient(app(False)) as c:
        sin = c.post("/eco", content=body, headers=cabeceras)
    with TestClient(app(True)) as c:
        con = c.post("/eco", content=body, headers=cabeceras)
    print(f"  estado SIN middleware           : {sin.status_code}")
    print(f"  estado CON middleware           : {con.status_code}")
    if sin.status_code == 200:
        print(f"  la app recibe                   : {json.dumps(sin.json(), ensure_ascii=False)}")
print("=" * 78)
