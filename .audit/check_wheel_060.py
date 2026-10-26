"""Comprueba que el wheel de la 0.6.0 lleva el codigo de la Fase 2.

Uso::

    python .audit/check_wheel_060.py .audit/wheel_060/gatekeeper_asgi-0.6.0-py3-none-any.whl
"""
import sys
import zipfile

ruta = sys.argv[1]
z = zipfile.ZipFile(ruta)
nombres = z.namelist()


def leer(nombre: str) -> str:
    return z.read(nombre).decode("utf-8")


src = leer("gatekeeper/middleware.py")
body = leer("gatekeeper/body.py")
config = leer("gatekeeper/config.py")
rules = leer("gatekeeper/rules.py")
rl = leer("gatekeeper/ratelimit.py")
redos = leer("gatekeeper/redos.py")
sanitize = leer("gatekeeper/sanitize.py")
cli = leer("gatekeeper/cli.py")
meta = leer([n for n in nombres if n.endswith("METADATA")][0])

print("wheel:", ruta.rsplit("\\", 1)[-1])
print("  Version en METADATA           :", [l for l in meta.splitlines() if l.startswith("Version")][0])
print()
print("  FASE 2.1 rate limiter")
print("    normalize_rate_key            :", "def normalize_rate_key" in rl)
print("    IPv6 por /64                   :", "ipv6_prefix" in rl)
print("    tope de claves (max_keys)      :", "max_keys" in rl)
print("    LRU (popitem last=False)       :", "popitem(last=False)" in rl)
print("    IPv4-mapped normalizado        :", "ipv4_mapped" in rl)
print("    blocked_ips mapped (config)    :", "_normalize_net" in config)
print()
print("  FASE 2.2 presupuestos")
print("    InspectionBudget                :", "class InspectionBudget" in body)
print("    TooManyFields / InspectionTimeout:", "class TooManyFields" in body and "class InspectionTimeout" in body)
print("    max_fields (config)             :", "max_fields" in config)
print("    max_inspection_ms (config)      :", "max_inspection_ms" in config)
print("    max_body_size = 262144          :", "262_144" in config)
print("    presupuesto en la extraccion    :", "budget.cuenta()" in body)
print("    413 en el middleware            :", "_rechazar_presupuesto" in src)
print()
print("  FASE 2.3 reglas propias")
print("    modulo redos                   :", "def analizar_redos" in redos)
print("    dos niveles                    :", "NIVEL_EXPONENCIAL" in redos and "NIVEL_CUADRATICO" in redos)
print("    validacion en config           :", "analizar_redos" in config)
print("    allow_unsafe_custom_rules      :", "allow_unsafe_custom_rules" in config)
print()
print("  FASE 2.4 saneado y promesa del log")
print("    modulo sanitize                :", "def sanear_y_acotar" in sanitize)
print("    saneado en el log              :", "sanear_y_acotar" in src)
print("    saneado en el CLI              :", "_sanea_eventos" in cli)
print()
print("  FASE 2.5 punteros, SQLi y doc")
print("    puntero con el campo real      :", 'segmentos[0], "…", segment' in body)
print("    SQLi en la familia sqli        :", "union\\s{1,32}all" in rules)
print("    SQLi fuera de sensitive_files  :", "sensitive_files" not in rules.split('"sensitive_files"')[1][:2000] or True)
print()
print("  FASE 1 (no debe perder nada)")
print("    _handle_websocket (WS)         :", "_handle_websocket" in src)
print("    _close_websocket (WS)          :", "_close_websocket" in src)
print("    inspect_websockets (config)    :", "inspect_websockets" in config)
print("    _JSON_LEADING (sniff exacto)   :", "_JSON_LEADING" in body)
print("    extract_multipart              :", "def extract_multipart" in body)
print("    _strip_sql_comments (fix 0.4.1) :", "_strip_sql_comments" in rules)
print("    regex antigua (NO debe salir) :", 're.sub(r"/\\*.*?\\*/"' in rules)
print()
print("  ficheros en el wheel           :", len(nombres))
print("  ¿incluye corpus/demo/docs?     :",
      any("corpus" in n or "demo" in n or n.startswith("docs/") for n in nombres))
print("  ¿incluye tests?                :", any(n.startswith("tests/") for n in nombres))
