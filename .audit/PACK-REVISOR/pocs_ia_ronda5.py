"""PoC de la quinta ronda independiente (IA, Claude) contra 0.9.2, tras el
cierre de NUEVO-3/5/6. Confirma el cierre (sin regresión) y encuentra un
nuevo hallazgo: falsos positivos introducidos por el propio parche de
NUEVO-3.
"""
from __future__ import annotations

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.rules import scan_detailed
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Route
from starlette.testclient import TestClient

PASA, FALLA, INFO = "PASA", "FALLA", "INFO"


def poc_r5_regresion_rondas_1_a_4(resultados: list[tuple[str, str, str]]) -> None:
    """Confirma que NUEVO-3, NUEVO-5 y NUEVO-6 siguen cerrados sin regresión."""
    casos = {
        "xss_corchetes": "document['cookie']",
        "xss_optional_chaining": "document?.cookie",
        "ssrf_octal_real": "http://0251.0376.0251.0376/latest/meta-data/",
        "ssrf_loopback_decimal": "http://2130706433/",
    }
    rotos = [n for n, p in casos.items() if not scan_detailed(p)]
    if rotos:
        resultados.append((FALLA, "regresión en hallazgos ya cerrados (rondas 3-4)", f"vuelven a fallar: {rotos}"))
    else:
        resultados.append((PASA, "NUEVO-3, NUEVO-5 y NUEVO-6 siguen cerrados", ""))


def poc_r5_falsos_positivos_self_parent_frames(resultados: list[tuple[str, str, str]]) -> None:
    """NUEVO-7: el parche de NUEVO-3 bloquea código Python/JS legítimo y muy común."""
    async def mostrar(request: Request) -> HTMLResponse:
        codigo = request.query_params.get("snippet", "")
        return HTMLResponse(f"<pre>{codigo}</pre>")

    app = Starlette(routes=[Route("/soporte", mostrar)])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    c = TestClient(app, raise_server_exceptions=False)

    benignos = {
        "test unitario Python (self.assertEqual)": "def test_suma(self):\n    self.assertEqual(suma(2,2), 4)",
        "clase Python (self.nombre, self.id)": "class Usuario:\n    def __init__(self):\n        self.nombre = ''\n        self.id = None",
        "JS legítimo (parent.postMessage)": "window.addEventListener('message', (e) => {\n  if (e.source === parent) handle(e);\n});",
        "JS legítimo (frames.length)": "if (frames.length > 0) { console.log('ok'); }",
    }
    bloqueados = {
        n: c.get("/soporte", params={"snippet": p}).status_code for n, p in benignos.items()
    }
    falsos = [n for n, s in bloqueados.items() if s == 403]
    if len(falsos) >= 3:
        resultados.append((
            FALLA,
            "NUEVO-7: el ensanche de la regla xss (self./parent./frames.) bloquea código legítimo muy común",
            (f"{len(falsos)}/{len(benignos)} fragmentos de código completamente "
            f"benignos se bloquean: {falsos}. `self.nombre`, `self.id` y "
            "`self.assertEqual(...)` son quizá la secuencia más común que "
            "existe en cualquier código Python orientado a objetos (toda "
            "clase que accede a un atributo de instancia, todo test "
            "unitario). `parent.postMessage` es el patrón estándar y "
            "documentado por MDN para comunicación entre iframes. Cualquier "
            "backend que refleje o acepte código como dato -un visor de "
            "tracebacks, una herramienta de soporte, un editor educativo, un "
            "pastebin, un sistema de revisión de código- se rompe con esta "
            "ampliación de la regla, igual de grave en la práctica que un "
            "falso negativo, porque hace el middleware inviable para una "
            "categoría entera de aplicaciones legítimas"),
        ))
    else:
        resultados.append((PASA, "el parche de NUEVO-3 no introduce falsos positivos significativos", ""))


COMPROBACIONES = [
    ("r5_regresion", poc_r5_regresion_rondas_1_a_4, "regresión de NUEVO-3/5/6"),
    ("r5_fp_self_parent", poc_r5_falsos_positivos_self_parent_frames, "falsos positivos del parche de NUEVO-3"),
]
