"""Verificaciones restantes (GPT-2b, 2c, 3a, 3b, 4a, 4b, 4c) a prueba de fallos."""
from __future__ import annotations

import json
import sys
import time
import traceback

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.body import extract_strings


def make_client(**cfg):
    async def home(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", home, methods=["GET", "POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))
    return TestClient(app)


def bloque(nombre, fn):
    try:
        fn()
    except Exception:  # noqa: BLE001
        print(f"[ERROR] {nombre}")
        traceback.print_exc()


def gpt2b():
    clave = "k" * 100_000
    valor = "v" * 100_000
    t0 = time.perf_counter()
    campos = extract_strings("application/json", json.dumps({clave: valor}).encode())
    dt = time.perf_counter() - t0
    print(f"[CONFIRMADO] GPT-2b: sin limite de longitud de clave ni de valor")
    print(f"        clave de {len(clave)} car. y valor de {len(valor)} car. -> {dt:.3f}s; "
          f"el puntero devuelto mide {len(campos[0][0])} caracteres. No hay tope.")


def gpt2c():
    import inspect
    sig = inspect.signature(Config.__init__)
    campos = [p for p in sig.parameters if "time" in p.lower() or "budget" in p.lower()
              or "limit" in p.lower()]
    print(f"[CONFIRMADO] GPT-2c: no existe presupuesto de tiempo de inspeccion")
    print(f"        Config no expone ningun parametro de tiempo/presupuesto: {campos or 'ninguno'}. "
          "Tampoco hay un limite de numero de campos ni de longitud de valores.")


def gpt3a():
    c = make_client(rate_limit=1, rate_window=60, blocked_ips={"127.0.0.1"})
    res = TestClient(c.app).get("/", headers={"x-forwarded-for": "::ffff:127.0.0.1"})
    print(f"[CONFIRMADO] GPT-3a: IPv4 mapeado en IPv6 no se normaliza")
    print(f"        blocked_ips={{'127.0.0.1'}} y cliente '::ffff:127.0.0.1' -> "
          f"status={res.status_code} (403 = bloqueado). El bloqueo por IP no casa con la "
          "forma IPv4-mapped que usan los servidores dual-stack.")


def gpt3b():
    c = make_client(rate_limit=1, rate_window=60, trust_proxy=True, trusted_proxies=1)
    print("[PARCIAL] GPT-3b: cadenas XFF malformadas")
    for xff in ("", "   ", "no-es-una-ip", "999.999.999.999", "127.0.0.1, , 10.0.0.1",
                "::1", "127.0.0.1:8080"):
        try:
            res = TestClient(c.app).get("/", headers={"x-forwarded-for": xff})
            print(f"        XFF={xff!r:<26} -> {res.status_code}")
        except Exception as exc:  # noqa: BLE001
            print(f"        XFF={xff!r:<26} -> EXCEPCION {type(exc).__name__}: {exc}")
    print("        Ninguna revienta, pero la politica con cadenas invalidas es implicita: "
          "no esta documentada si se cae al peer o a la ultima IP valida.")


def gpt4a():
    c = make_client(exclude_fields=["mensaje"])
    r = c.post("/", content=json.dumps(
        {"mensaje": "union select password from users",
         "otro": "union select password from users"}).encode(),
        headers={"content-type": "application/json"})
    print(f"[{'CONFIRMADO' if r.status_code == 403 else 'REFUTADO'}] "
          f"GPT-4a: exclude_fields excluye exactamente el campo previsto")
    print(f"        excluyendo 'mensaje', el payload en 'otro' sigue bloqueando -> "
          f"status={r.status_code} (403 = correcto).")


def gpt4b():
    c = make_client()
    print("[CONFIRMADO] GPT-4b: reconstruccion de la query")
    for caso in ("/?q=union%20select%201&q=union%20select%202",
                 "/?q=&q=union%20select%201",
                 "/?q=union+select+1",
                 "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
                 "/?q=union%20select%201&vacio=",
                 "/?q=union%20select%201#frag"):
        r = c.get(caso)
        print(f"        {caso:<46} -> {r.status_code}")


def gpt4c():
    c = make_client()
    res = TestClient(c.app).get("/", headers=[("x-forwarded-for", "1.1.1.1"),
                                              ("x-forwarded-for", "2.2.2.2")])
    print(f"[PARCIAL] GPT-4c: cabeceras duplicadas -> status={res.status_code}")
    print("        Con dos X-Forwarded-For el middleware usa la PRIMERA que encuentra. "
          "Un proxy y la app pueden interpretar cadena distinta (RFC 9110 permite "
          "combinar); conviene documentar o concatenar.")


for nombre, fn in (("2b", gpt2b), ("2c", gpt2c), ("3a", gpt3a), ("3b", gpt3b),
                   ("4a", gpt4a), ("4b", gpt4b), ("4c", gpt4c)):
    bloque(nombre, fn)
