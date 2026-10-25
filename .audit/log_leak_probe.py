"""Verifica si el contenido del payload puede acabar en el log de auditoria."""
from __future__ import annotations

import json
import logging
import sys

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.body import extract_strings

registros: list[str] = []


class Handler(logging.Handler):
    def emit(self, record):
        registros.append(record.getMessage())


async def home(request):
    return PlainTextResponse("ok")


app = Starlette(routes=[Route("/", home, methods=["GET", "POST"])])
app.add_middleware(GatekeeperMiddleware, config=Config(monitor_only=True, rate_limit=0))

logger = logging.getLogger("gatekeeper")
logger.setLevel(logging.WARNING)
h = Handler()
logger.addHandler(h)

SECRETO = "UNION SELECT password FROM users"

casos = [
    ("form-urlencoded, payload en el NOMBRE del parametro",
     "application/x-www-form-urlencoded", "union%20select%20password%20from%20users"),
    ("form-urlencoded, payload en el VALOR",
     "application/x-www-form-urlencoded", "q=union%20select%20password%20from%20users"),
    ("json valido", "application/json", json.dumps({"q": SECRETO})),
    ("json con clave sospechosa", "application/json", json.dumps({SECRETO: "valor"})),
    ("text/plain", "text/plain", SECRETO),
    ("sin content-type", None, SECRETO),
]

print("=" * 78)
print("¿El contenido del payload llega al log de auditoria?")
print("=" * 78)
for nombre, ctype, body in casos:
    registros.clear()
    headers = {"content-type": ctype} if ctype else {}
    TestClient(app).post("/", content=body.encode(), headers=headers)
    for linea in registros:
        evento = json.loads(linea)
        campo = str(evento.get("field"))
        print(f"\n{nombre}")
        print(f"  field = {campo!r}")
        print(f"  ¿contiene el payload completo? {'SI' if SECRETO.lower() in campo.lower() else 'no'}")
        print(f"  ¿la linea del log contiene el payload? "
              f"{'SI' if SECRETO.lower() in linea.lower() else 'no'}")

print()
print("=" * 78)
print("Punteros generados por extract_strings (form-urlencoded, payload en el nombre)")
print("=" * 78)
for puntero, valor in extract_strings("application/x-www-form-urlencoded",
                                       b"union%20select%20password%20from%20users"):
    print(f"  puntero={puntero!r}  valor={valor!r}")
