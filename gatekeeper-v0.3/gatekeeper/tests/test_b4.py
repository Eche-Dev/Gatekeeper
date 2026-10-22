"""B4: packs de reglas opt-in, exclusiones por campo y CLI `gatekeeper report`.

Cada test fija una decisión de diseño, no un detalle:
- el defecto NO cambia de comportamiento (sin packs = once familias);
- excluir un campo es excluirlo de verdad, pero el resto sigue vigilado;
- la CLI sugiere un ajuste que se puede copiar tal cual en la configuración.
"""
import json

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from gatekeeper import Config, GatekeeperMiddleware
from gatekeeper.cli import construir_informe, main
from gatekeeper.rules import PACK_NAMES, RULES, resolve_rules, scan_detailed

XSS = "/search?q=<script>alert(1)</script>"
SQLI = "/search?q=1'%20OR%20'1'='1"
TRAVERSAL = "/f?p=../../etc/passwd"
NOSQL = "/login?user[$ne]=x"
SSTI = "/q={{config.items()}}"
CMDI = "/c=;%20ls%20-la"
PROTO = "/p=__proto__[isAdmin]=true"


async def _ok(request):
    return PlainTextResponse("ok")


def cliente(**cfg) -> TestClient:
    rutas = [
        Route("/search", _ok, methods=["GET", "POST"]),
        Route("/f", _ok, methods=["GET", "POST"]),
        Route("/login", _ok, methods=["GET", "POST"]),
        Route("/q", _ok, methods=["GET", "POST"]),
        Route("/c", _ok, methods=["GET", "POST"]),
        Route("/p", _ok, methods=["GET", "POST"]),
        Route("/", _ok, methods=["GET", "POST"]),
    ]
    app = Starlette(routes=rutas)
    return TestClient(GatekeeperMiddleware(app, Config(rate_limit=0, **cfg)))


# --------------------------------------------------------------- packs


def test_sin_pack_se_evaluan_todas_las_familias():
    """El defecto no cambia: `rule_packs` es opt-in, no un recorte sorpresa."""
    assert resolve_rules(None) == set(RULES)
    assert resolve_rules([]) == set(RULES)
    assert resolve_rules(None) == resolve_rules(["strict"])


def test_pack_strict_es_todas_las_familias():
    assert resolve_rules(["strict"]) == set(RULES)
    assert len(RULES) == 11


@pytest.mark.parametrize(
    "pack,esperadas,fuera",
    [
        ("minimal", {"sqli", "path_traversal"}, {"xss", "nosql"}),
        ("api", {"sqli", "nosql", "ssrf", "cmdi"}, {"xss", "ssti", "proto_pollution"}),
        ("web", {"sqli", "xss", "ssrf"}, {"nosql", "ssti", "proto_pollution"}),
        ("infrastructure", {"ssrf", "log4shell", "crlf", "cmdi"}, {"sqli", "xss"}),
    ],
)
def test_cada_pack_incluye_y_excluye_lo_que_promete(pack, esperadas, fuera):
    activas = resolve_rules([pack])
    assert esperadas <= activas, f"{pack} debería incluir {esperadas}"
    assert not (fuera & activas), f"{pack} no debería incluir {fuera}"


def test_packs_se_combinan():
    assert resolve_rules(["minimal", "web"]) >= {"sqli", "xss", "path_traversal"}


def test_pack_desconocido_falla_al_arrancar():
    """Un nombre mal escrito no puede dejar la app sin protección en silencio."""
    with pytest.raises(ValueError, match="Pack de reglas desconocido"):
        Config(rule_packs=["we"])
    with pytest.raises(ValueError, match="Pack de reglas desconocido"):
        resolve_rules(["no-existe"])


def test_disabled_rules_resta_al_pack():
    config = Config(rule_packs=["minimal"], disabled_rules={"sqli"})
    assert config.active_rules == frozenset({"path_traversal"})


def test_todo_pack_declara_solo_familias_reales():
    """Un pack no puede prometer una familia que no existe: sería protection
    de papel (y `disabled_rules` sobre ella no tendría sentido)."""
    from gatekeeper.rules import RULE_PACKS

    assert set(PACK_NAMES) == set(RULE_PACKS)
    for nombre, familias in RULE_PACKS.items():
        assert familias <= set(RULES), f"el pack '{nombre}' nombra familias inexistentes"
        assert familias, f"el pack '{nombre}' está vacío"


# ---------------------------------------------- middleware con packs


def test_pack_api_deja_pasar_xss_pero_no_sqli():
    c = cliente(rule_packs=["api"])
    assert c.get(XSS).status_code == 200, "una API JSON no renderiza HTML"
    assert c.get(SQLI).status_code == 403


def test_defecto_sigue_bloqueando_xss():
    assert cliente().get(XSS).status_code == 403


def test_pack_api_sigue_bloqueando_lo_que_no_depende_del_html():
    c = cliente(rule_packs=["api"])
    assert c.get(TRAVERSAL).status_code == 403
    assert c.get(CMDI).status_code == 403
    assert c.get("/u=http://169.254.169.254/latest/").status_code == 403


# ------------------------------------------------- exclusiones por campo


def test_exclude_fields_exime_un_parametro_de_query():
    c = cliente(exclude_fields=["template"])
    assert c.get("/search?template=<script>alert(1)</script>").status_code == 200
    assert c.get(XSS).status_code == 403, "excluir uno no exime el resto"


def test_exclude_fields_admite_globs():
    c = cliente(exclude_fields=["doc_*"])
    assert c.get("/search?doc_body=<script>alert(1)</script>").status_code == 200
    assert c.get("/search?doc_body2=<script>x</script>").status_code == 200
    assert c.get(XSS).status_code == 403


def test_exclude_fields_no_rompe_la_deteccion_que_cruza_parametros():
    """`a` exento y el payload en `b`: sigue bloqueando (se quita solo `a`)."""
    c = cliente(exclude_fields=["a"])
    assert c.get("/search?a=<script>alert(1)</script>&b=x").status_code == 200
    assert c.get("/search?a=1&b=<script>alert(1)</script>").status_code == 403


def test_exclude_fields_exime_una_cabecera():
    c = cliente(exclude_fields=["user-agent"])
    assert c.get("/", headers={"user-agent": "<script>alert(1)</script>"}).status_code == 200
    assert c.get("/", headers={"referer": "http://x/?q=<script>alert(1)</script>"}).status_code == 403


def test_exclude_fields_exime_un_puntero_json():
    c = cliente(exclude_fields=["bio"])
    assert c.post("/", json={"user": {"bio": "<script>alert(1)</script>"}}).status_code == 200
    assert c.post("/", json={"user": {"name": "<script>alert(1)</script>"}}).status_code == 403


def test_exclude_fields_admite_el_puntero_completo():
    c = cliente(exclude_fields=["/user/bio"])
    assert c.post("/", json={"user": {"bio": "<script>alert(1)</script>"}}).status_code == 200


def test_exclude_fields_acepta_lista_vacia():
    c = cliente(exclude_fields=[])
    assert c.get(XSS).status_code == 403


# -------------------------------------------------- scan_detailed con `only`


def test_scan_detailed_respeta_el_subconjunto():
    solo_sqli = frozenset({"sqli"})
    assert scan_detailed("<script>alert(1)</script>", only=solo_sqli) is None
    assert scan_detailed("1' OR '1'='1", only=solo_sqli)[0] == "sqli"


def test_scan_detailed_evalua_las_personalizadas_aunque_haya_pack():
    import re

    extra = {"wp": [re.compile(r"wp-login")]}
    assert scan_detailed("/wp-login.php", extra=extra, only=frozenset({"sqli"}))[0] == "wp"


# ------------------------------------------------------------- la CLI


def test_cli_report_sobre_eventos_json(tmp_path, capsys):
    log = tmp_path / "gk.log"
    log.write_text(
        "\n".join(
            [
                json.dumps({"event": "attack_detected", "ip": "1.1.1.1", "method": "GET",
                            "path": "/search", "rule": "sqli", "source": "query",
                            "field": "q", "blocked": True}),
                json.dumps({"event": "attack_detected", "ip": "1.1.1.2", "method": "GET",
                            "path": "/search", "rule": "sqli", "source": "query",
                            "field": "q", "blocked": True}),
                json.dumps({"event": "rate_limited", "ip": "1.1.1.3", "path": "/x"}),
            ]
        ),
        encoding="utf-8",
    )
    informe = construir_informe(log)
    assert "sqli" in informe
    assert "exclude_fields:\n  - q" in informe
    assert "disabled_rules: [sqli]" in informe
    assert "rate_limited" not in informe, "solointeresting los ataques"


def test_cli_report_sobre_log_de_acceso_generico(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(
        "\n".join([
            "GET /buscar?q=1'+OR+'1'='1 200",
            "GET /perfil?q=<script>alert(1)</script> 200",
            "GET /salud 200",
        ]),
        encoding="utf-8",
    )
    informe = construir_informe(log)
    assert "sqli" in informe and "xss" in informe
    assert "salud" not in informe, "una request limpia no es un ataque"


def test_cli_report_json_legible_por_maquina(tmp_path, capsys):
    log = tmp_path / "gk.log"
    log.write_text(
        json.dumps({"event": "attack_detected", "rule": "xss", "path": "/p",
                    "field": "/bio", "blocked": False}),
        encoding="utf-8",
    )
    assert main(["report", str(log), "--json"]) == 0
    datos = json.loads(capsys.readouterr().out)
    assert datos == {"total": 1, "rules": {"xss": 1}, "fields": {"/bio": 1}}


def test_cli_report_falla_si_el_log_no_existe(tmp_path, capsys):
    assert main(["report", str(tmp_path / "nope.log")]) == 2
    assert "no existe" in capsys.readouterr().err


def test_cli_no_filtra_payloads_ni_guarda_contenido(tmp_path):
    """El informe se construye con lo que el log ya trae; no inventa ni imprime
    el valor del payload (esa es la garantía de la auditoría sin fugas)."""
    log = tmp_path / "gk.log"
    log.write_text(
        json.dumps({"event": "attack_detected", "rule": "sqli", "path": "/s",
                    "field": "q", "blocked": True}),
        encoding="utf-8",
    )
    informe = construir_informe(log)
    assert "1' OR" not in informe
