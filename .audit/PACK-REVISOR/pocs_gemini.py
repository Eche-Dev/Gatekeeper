"""Comprobaciones de seguridad independientes — Gemini.

Este modulo contiene las pruebas de concepto (PoC) desarrolladas durante la
auditoria de seguridad independiente de Gatekeeper.

Se enfoca en:
1. Diferencial de interpretacion de multipart entre Gatekeeper y la aplicacion.
2. Consistencia del prefiltro de reglas en peticiones con longitud >= 128 caracteres.
3. Fronteras de transporte (XFF, JSON UTF-16, campos excluidos).
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.rules import scan_detailed

PASA, FALLA, INFO = "PASA", "FALLA", "INFO"


# =============================================================================
# 1. H-1: Diferencial de boundary multipart (Bypass en formularios)
# =============================================================================
def poc_multipart_duplicate_boundary(resultados: list[tuple[str, str, str]]) -> None:
    """Verifica si un Content-Type con boundary duplicado permite evadir la inspeccion.

    Starlette / python-multipart parsea los parametros del Content-Type en un
    diccionario donde el ultimo 'boundary' sobreescribe a los anteriores.
    Gatekeeper usa el primero que encuentra. Si el atacante manda:
      Content-Type: multipart/form-data; boundary=dummy; boundary=real
    y construye el body con 'real', Gatekeeper busca 'dummy', no extrae ningun campo
    y deja pasar la peticion con 200.
    """
    async def endpoint(request):
        data = await request.form()
        return JSONResponse(dict(data))

    app = Starlette(routes=[Route("/", endpoint, methods=["POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    client = TestClient(app)

    body = (
        b"--real\r\n"
        b'Content-Disposition: form-data; name="q"\r\n\r\n'
        b"1 UNION SELECT 1\r\n"
        b"--real--"
    )
    headers = {"content-type": "multipart/form-data; boundary=dummy; boundary=real"}
    resp = client.post("/", content=body, headers=headers)

    if resp.status_code == 403:
        resultados.append((
            PASA,
            "multipart: boundary duplicado no evade la inspeccion",
            "la peticion fue bloqueada con 403",
        ))
    elif resp.status_code == 200:
        resultados.append((
            FALLA,
            "H-1: multipart boundary duplicado esquiva la deteccion",
            f"estado {resp.status_code}, la app recibio {resp.json()!r}: Gatekeeper uso el primer boundary y Starlette el segundo",
        ))
    else:
        resultados.append((
            INFO,
            "multipart boundary duplicado: respuesta inesperada",
            f"estado {resp.status_code}",
        ))


# =============================================================================
# 2. H-2A: Prefiltro descarta sensitive_files con peticiones >= 128 chars
# =============================================================================
def poc_prefilter_sensitive_files_padding(resultados: list[tuple[str, str, str]]) -> None:
    """Verifica si el prefiltro descarta firmas de sensitive_files en textos largos.

    _vale_la_pena_prefiltrar(text) activa el prefiltro a partir de 128 caracteres.
    Varias firmas (requirements.txt, package-lock.json, composer.json, backup.sql.zip,
    dump.sql, config.bak) carecen de literales en PREFILTER_LITERALS['sensitive_files'].
    Con URL corta dan 403, pero agregando parametros o relleno >= 128 caracteres pasan con 200.
    """
    app = Starlette(routes=[Route("/download", lambda r: PlainTextResponse("ok"))])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    client = TestClient(app)

    casos = [
        ("requirements.txt", "/download?file=/requirements.txt"),
        ("backup.sql.zip", "/download?file=/backup.sql.zip"),
        ("dump.sql", "/download?file=dump.sql"),
        ("config.bak", "/download?file=config.bak"),
    ]

    fallos: list[str] = []
    for nombre, url in casos:
        short_status = client.get(url).status_code
        sep = "&" if "?" in url else "?"
        padded_url = url + sep + "dummy=" + ("x" * 150)
        padded_status = client.get(padded_url).status_code

        if short_status == 403 and padded_status == 200:
            fallos.append(nombre)

    if fallos:
        resultados.append((
            FALLA,
            "H-2A: prefiltro descarta sensitive_files en peticiones >= 128 caracteres",
            f"{len(fallos)}/{len(casos)} firmas se escapan al anadir padding: {', '.join(fallos)}",
        ))
    else:
        resultados.append((
            PASA,
            "prefiltro: sensitive_files se detectan consistentemente con y sin padding",
            "todas las firmas probadas devolvieron 403",
        ))


# =============================================================================
# 3. H-2B: Prefiltro descarta firmas avanzadas de SQLi con peticiones >= 128 chars
# =============================================================================
def poc_prefilter_sqli_padding(resultados: list[tuple[str, str, str]]) -> None:
    """Verifica si el prefiltro descarta firmas de sqli (::jsonb, sqlite, CHR, etc.)."""
    app = Starlette(routes=[Route("/search", lambda r: PlainTextResponse("ok"))])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    client = TestClient(app)

    casos = [
        ("PostgreSQL ::jsonb", "/search?q='{\"b\":2}'::jsonb"),
        ("SQLite compileoption", "/search?q=sqlite_compileoption_used(1)"),
        ("Oracle CHR concatenation", "/search?q=CHR(113)||CHR(122)"),
        ("SQLi is not", "/search?q=id' is not id--"),
    ]

    fallos: list[str] = []
    for nombre, url in casos:
        short_status = client.get(url).status_code
        sep = "&" if "?" in url else "?"
        padded_url = url + sep + "dummy=" + ("x" * 150)
        padded_status = client.get(padded_url).status_code

        if short_status == 403 and padded_status == 200:
            fallos.append(nombre)

    if fallos:
        resultados.append((
            FALLA,
            "H-2B: prefiltro descarta firmas de SQLi en peticiones >= 128 caracteres",
            f"{len(fallos)}/{len(casos)} firmas se escapan al anadir padding: {', '.join(fallos)}",
        ))
    else:
        resultados.append((
            PASA,
            "prefiltro: firmas de SQLi se detectan consistentemente con y sin padding",
            "todas las firmas probadas devolvieron 403",
        ))


# =============================================================================
# 4. H-2C: Prefiltro descarta tags <style> de XSS con peticiones >= 128 chars
# =============================================================================
def poc_prefilter_xss_style_padding(resultados: list[tuple[str, str, str]]) -> None:
    """Verifica si <style> en XSS se descarta por el prefiltro con relleno."""
    texto_corto = "<style>body{background:red}</style>"
    texto_largo = texto_corto + " " + ("a" * 150)

    det_corto = scan_detailed(texto_corto)
    det_largo = scan_detailed(texto_largo)

    if det_corto is not None and det_largo is None:
        resultados.append((
            FALLA,
            "H-2C: prefiltro descarta tag <style> de XSS en textos >= 128 caracteres",
            f"corto: {det_corto[0]}, largo: None (el literal <style no esta en PREFILTER_LITERALS['xss'])",
        ))
    else:
        resultados.append((
            PASA,
            "prefiltro: XSS <style> detectado consistentemente",
            f"corto: {det_corto}, largo: {det_largo}",
        ))


# =============================================================================
# 5. Control positivo: Spoofing de IP con XFF sin confianza no es posible
# =============================================================================
def poc_xff_spoofing_prevented(resultados: list[tuple[str, str, str]]) -> None:
    """Verifica que un cliente no pueda eludir blocked_ips falseando XFF sin trust_proxy."""
    app = Starlette(routes=[Route("/", lambda r: PlainTextResponse("ok"))])
    app.add_middleware(
        GatekeeperMiddleware,
        config=Config(blocked_ips={"198.51.100.5"}, trust_proxy=False),
    )
    client = TestClient(app)

    # Intento de bypass enviando IP legitima en XFF pero origen bloqueado
    # En TestClient el peer por defecto es "testclient", asi que probamos bloquear "testclient"
    app2 = Starlette(routes=[Route("/", lambda r: PlainTextResponse("ok"))])
    app2.add_middleware(
        GatekeeperMiddleware,
        config=Config(blocked_ips={"testclient"}, trust_proxy=False),
    )
    client2 = TestClient(app2)

    resp = client2.get("/", headers={"x-forwarded-for": "8.8.8.8"})
    if resp.status_code == 403:
        resultados.append((
            PASA,
            "XFF no confiable se ignora (peer bloqueado no evade con cabecera)",
            "estado 403",
        ))
    else:
        resultados.append((
            FALLA,
            "XFF no confiable permitio eludir el bloqueo de IP",
            f"estado {resp.status_code}",
        ))


# =============================================================================
# 6. Control positivo: UTF-16 en JSON se inspecciona correctamente
# =============================================================================
def poc_json_utf16_inspected(resultados: list[tuple[str, str, str]]) -> None:
    """Verifica que un JSON codificado en UTF-16 con payload SQLi sea detectado."""
    app = Starlette(routes=[Route("/api", lambda r: PlainTextResponse("ok"), methods=["POST"])])
    app.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0))
    client = TestClient(app)

    json_bytes = '{"query": "1 UNION SELECT 1"}'.encode("utf-16")
    resp = client.post(
        "/api",
        content=json_bytes,
        headers={"content-type": "application/json"},
    )
    if resp.status_code == 403:
        resultados.append((
            PASA,
            "JSON UTF-16 con SQLi se decodifica e inspecciona correctamente",
            "estado 403",
        ))
    else:
        resultados.append((
            FALLA,
            "JSON UTF-16 no fue inspeccionado",
            f"estado {resp.status_code}",
        ))


# --- registro de comprobaciones del revisor Gemini ---------------------------
COMPROBACIONES = [
    ("multipart_duplicate_boundary", poc_multipart_duplicate_boundary,
     "H-1: diferencial de boundary en multipart/form-data"),
    ("prefilter_sensitive_files", poc_prefilter_sensitive_files_padding,
     "H-2A: prefiltro descarta sensitive_files en peticiones >= 128 caracteres"),
    ("prefilter_sqli", poc_prefilter_sqli_padding,
     "H-2B: prefiltro descarta firmas de SQLi en peticiones >= 128 caracteres"),
    ("prefilter_xss_style", poc_prefilter_xss_style_padding,
     "H-2C: prefiltro descarta <style> de XSS en textos >= 128 caracteres"),
    ("xff_spoofing_prevented", poc_xff_spoofing_prevented,
     "control: XFF sin proxy de confianza no evade blocked_ips"),
    ("json_utf16_inspected", poc_json_utf16_inspected,
     "control: JSON UTF-16 se inspecciona y bloquea"),
]
