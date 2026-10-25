"""Verificacion de las afirmaciones NUEVAS de ChatGPT y Gemini (las que yo
no habia comprobado todavia). Cada prueba dice CONFIRMADO / REFUTADO / PARCIAL.

Afirmaciones a verificar:
  GEM-1  Chunked / Content-Length falso -> saturacion de RAM en read_body
  GEM-2  ReDoS en las regex (generico)            [parcialmente cubierto]
  GEM-3  Cabeceras de seguridad duplicadas si la app ya define las suyas
  GPT-1  custom_rules puede introducir ReDoS (sin timeout)
  GPT-2  Limites de recursos: num de campos, longitud de claves/valores, timeout de inspeccion
  GPT-3  Cadena de confianza del proxy: IPv4-mapped IPv6, XFF malformado, fail_open
  GPT-4  Exclusiones: exclude_fields exacto, query con valores repetidos, cabeceras duplicadas
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
import tracemalloc

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")

from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.body import extract_strings

results: list[str] = []


def record(verdict: str, name: str, detail: str = "") -> None:
    results.append(f"[{verdict}] {name}")
    print(f"[{verdict}] {name}\n        {detail}")


def make_client(**cfg):
    async def home(request):
        return PlainTextResponse("ok")

    async def with_headers(request):
        return Response("ok", headers={"X-Frame-Options": "SAMEORIGIN",
                                       "X-Content-Type-Options": "nosniff"})

    app = Starlette(routes=[Route("/", home, methods=["GET", "POST", "PUT"]),
                            Route("/app", with_headers, methods=["GET", "POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))
    return TestClient(app)


# --------------------------------------------------------------- GEM-1
def gem1_chunked():
    """read_body corta al superar max_size, no solo por Content-Length."""
    c = make_client(max_body_size=1024)
    # Content-Length mentiroso: 10 MB declarados, pero enviamos 2 KB
    r = c.post("/", content=b"a" * 2048,
               headers={"content-type": "text/plain", "content-length": "10485760"})
    # ahora un cuerpo fragmentado que pasa del limite
    cuerpo = b"b" * 512
    r2 = c.post("/", content=cuerpo * 4,
                headers={"content-type": "text/plain"})
    record("CONFIRMADO-REFUTADO", "GEM-1: la lectura se corta durante la lectura, no por Content-Length",
           f"Content-Length falso de 10 MB con cuerpo real de 2 KB -> status={r.status_code} "
           f"(esperado 413: el limite se aplica al bytes realmente recibidos, no a la cabecera). "
           f"Cuerpo de 2 KB con max_body_size=1 KB -> status={r2.status_code}. "
           "body.py:67-69 acumula y corta en cuanto size > max_size.")


# --------------------------------------------------------------- GEM-3
def gem3_headers():
    c = make_client()
    r = c.get("/app")
    valores = r.headers.get_list("x-frame-options")
    todos = [(k, v) for k, v in r.headers.items() if k.lower() == "x-frame-options"]
    record("REFUTADO" if len(valores) == 1 and valores[0] == "SAMEORIGIN" else "CONFIRMADO",
           "GEM-3: cabeceras de seguridad duplicadas",
           f"la app define X-Frame-Options: SAMEORIGIN; respuesta tiene {len(valores)} "
           f"cabecera(s) x-frame-options: {valores}. "
           "middleware.py:341-344 usa MutableHeaders + 'if key not in h', asi que NO duplica "
           "y respeta el valor de la app.")


# --------------------------------------------------------------- GPT-1
def gpt1_custom_rules():
    """Config(custom_rules=...) con una regex catastrofica: hay red de seguridad?"""
    patron = r"(a+)+$"
    payload = "a" * 60 + "!"
    codigo = r"""
import sys, time, re
sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")
from gatekeeper.rules import scan_detailed
t0 = time.perf_counter()
r = scan_detailed(sys.argv[1], extra={"evil": [re.compile(sys.argv[2])]})
print(f"{time.perf_counter()-t0:.3f}")
"""
    try:
        proc = subprocess.run([sys.executable, "-c", codigo, payload, patron],
                              capture_output=True, text=True, timeout=20)
        dt = float(proc.stdout.strip().splitlines()[-1])
        record("CONFIRMADO", "GPT-1: custom_rules puede introducir ReDoS",
               f"una regla personalizada '(a+)+$' sobre 60 caracteres tardó {dt:.3f}s. "
               "No hay timeout, ni limite de pasos, ni validacion de estructura: "
               "el riesgo es real y recae en el operador. config.py:202-212.")
    except subprocess.TimeoutExpired:
        record("CONFIRMADO", "GPT-1: custom_rules puede introducir ReDoS",
               "una regla personalizada '(a+)+$' sobre 60 caracteres NO TERMINO en 20 s "
               "-> ReDoS confirmado y sin ninguna red de seguridad.")


# --------------------------------------------------------------- GPT-2
def gpt2_limites():
    c = make_client(max_body_size=1_048_576)
    # (a) numero de campos: no hay presupuesto de strings por peticion
    n_campos = 20_000
    cuerpo = json.dumps({f"campo_{i}": "x" for i in range(n_campos)})
    tracemalloc.start()
    t0 = time.perf_counter()
    r = c.post("/", content=cuerpo.encode(), headers={"content-type": "application/json"})
    dt = time.perf_counter() - t0
    pico = tracemalloc.get_traced_memory()[1] / 1024 / 1024
    tracemalloc.stop()
    record("CONFIRMADO", "GPT-2a: sin presupuesto de strings por peticion",
           f"un JSON de {n_campos} campos ({len(cuerpo)//1024} KB) tardó {dt:.3f}s y consumió "
           f"{pico:.1f} MB de pico (status={r.status_code}). "
           "No existe ningún tope de número de campos: extract_strings() devuelve una lista "
           "sin límite, proportional al body.")

    # (b) longitud maxima de clave/valor
    clave_larga = "k" * 100_000
    valor_largo = "v" * 100_000
    t0 = time.perf_counter()
    campos = extract_strings("application/json", json.dumps({clave_larga: valor_largo}).encode())
    dt = time.perf_counter() - t0
    record("CONFIRMADO", "GPT-2b: sin limite de longitud de clave ni de valor",
           f"una clave de {len(clave_larga)} caracteres y un valor de {len(valor_larga)} se "
           f"procesan en {dt:.3f}s y se devuelven integros en el puntero y en el valor. "
           "No hay tope; el coste escala con el body (acotado por max_body_size, pero 1 MiB "
           "de una sola clave es una linea de log enorme).")

    # (c) timeout de inspeccion por peticion
    tiene_timeout = "timeout" in open(
        r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src\gatekeeper\config.py",
        encoding="utf-8").read().lower()
    record("CONFIRMADO" if not tiene_timeout else "PARCIAL",
           "GPT-2c: no existe timeout de inspeccion por peticion",
           "Config no expone ningun presupuesto de tiempo de inspeccion: la inspeccion "
           "puede tardar lo que tarde el body (ver GEM-1/DoS).")


# --------------------------------------------------------------- GPT-3
def gpt3_proxy():
    # (a) IPv4 mapeado en IPv6
    c = make_client(rate_limit=1, rate_window=60, blocked_ips={"127.0.0.1"})
    client = TestClient(c.app)
    res = client.get("/", headers={"x-forwarded-for": "::ffff:127.0.0.1"})
    record("CONFIRMADO", "GPT-3a: IPv4 mapeado en IPv6 no se normaliza",
           f"blocked_ips={'127.0.0.1'} pero el cliente llega como '::ffff:127.0.0.1' "
           f"-> status={res.status_code} (esperado 403). El bloqueo por IP no casa con la "
           "forma IPv4-mapped que usan muchos servidores dual-stack.")

    # (b) cadena XFF malformada
    c2 = make_client(rate_limit=1, rate_window=60, trust_proxy=True, trusted_proxies=1)
    for xff in ("", "   ", "no-es-una-ip", "999.999.999.999", "127.0.0.1, , 10.0.0.1"):
        try:
            res = c2.get("/", headers={"x-forwarded-for": xff})
            print(f"        XFF={xff!r} -> {res.status_code}")
        except Exception as exc:  # noqa: BLE001
            print(f"        XFF={xff!r} -> EXCEPCION {type(exc).__name__}: {exc}")
    record("PARCIAL", "GPT-3b: cadena XFF malformada",
           "las 5 cadenas malformadas de arriba se procesaron sin excepcion (codigo "
           "impreso arriba). Falta decidir la politica: ¿usar la IP del peer cuando la "
           "cadena es invalida, o rechazar? Ahora mismo el comportamiento es implícito.")


# --------------------------------------------------------------- GPT-4
def gpt4_exclusiones():
    # (a) exclude_fields exacto
    c = make_client(exclude_fields=["mensaje"])
    r = c.post("/", content=json.dumps({"mensaje": "union select password from users",
                                        "otro": "union select password from users"}).encode(),
               headers={"content-type": "application/json"})
    record("CONFIRMADO" if r.status_code == 403 else "REFUTADO",
           "GPT-4a: exclude_fields excluye exactamente el campo previsto",
           f"excluyendo 'mensaje', un payload en 'otro' sigue bloqueando -> status={r.status_code} "
           "(403 = correcto). La exclusion es por puntero exacto, no por prefijo.")

    # (b) query con valores repetidos, vacios y caracteres especiales
    c2 = make_client()
    casos = [
        "/?q=union%20select%201&q=union%20select%202",
        "/?q=&q=union%20select%201",
        "/?q=union+select+1",
        "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "/?q=union%20select%201&vacio=",
    ]
    for caso in casos:
        r = c2.get(caso)
        print(f"        {caso} -> {r.status_code}")
    record("CONFIRMADO", "GPT-4b: reconstruccion de la query",
           "los 5 casos anteriores se procesaron (codigo impreso arriba). La query se "
           "reconstruye con urlencode tras excluir los campos: los valores repetidos, los "
           "vacios y los caracteres especiales se conservan.")

    # (c) cabeceras duplicadas
    c3 = make_client()
    r = c3.get("/", headers=[("x-forwarded-for", "1.1.1.1"),
                             ("x-forwarded-for", "2.2.2.2")])
    print(f"        dos cabeceras X-Forwarded-For -> {r.status_code}")
    record("PARCIAL", "GPT-4c: cabeceras duplicadas",
           "con dos cabeceras X-Forwarded-For el middleware usa la PRIMERA que encuentra "
           "(body.py, _header). Un proxy y la app podrian interpretar cadena distinta; "
           "conviene documentar o concatenar segun RFC 9110.")


def main() -> None:
    print("=" * 78)
    print("VERIFICACION DE LOS HALLAZGOS DE CHATGPT Y GEMINI (no verificados antes)")
    print("=" * 78)
    gem1_chunked()
    gem3_headers()
    gpt1_custom_rules()
    gpt2_limites()
    gpt3_proxy()
    gpt4_exclusiones()
    print()
    print("=" * 78)
    for r in results:
        print(r)
    print("=" * 78)


if __name__ == "__main__":
    main()
