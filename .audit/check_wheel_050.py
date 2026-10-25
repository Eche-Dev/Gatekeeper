import glob
import sys
import zipfile

ruta = sys.argv[1]
z = zipfile.ZipFile(ruta)
src = z.read("gatekeeper/middleware.py").decode("utf-8")
body = z.read("gatekeeper/body.py").decode("utf-8")
config = z.read("gatekeeper/config.py").decode("utf-8")
meta = z.read("gatekeeper_asgi-0.5.0.dist-info/METADATA").decode()

print("wheel:", ruta.rsplit("\\", 1)[-1])
print("  Version en METADATA           :", [l for l in meta.splitlines() if l.startswith("Version")][0])
print("  _handle_websocket (WS)         :", "_handle_websocket" in src)
print("  _close_websocket (WS)          :", "_close_websocket" in src)
print("  inspect_websockets (config)    :", "inspect_websockets" in config)
print("  looks_like_json (sniff)        :", "def looks_like_json" in body)
print("  _JSON_LEADING (sniff exacto)   :", "_JSON_LEADING" in body)
print("  extract_multipart              :", "def extract_multipart" in body)
print("  inspect_multipart (config)     :", "inspect_multipart" in config)
print("  _strip_sql_comments (fix 0.4.1) :", "_strip_sql_comments" in body)
print("  regex antigua (NO debe salir) :", 're.sub(r"/\\*.*?\\*/"' in body)
nombres = z.namelist()
print("  ficheros en el wheel           :", len(nombres))
print("  ¿incluye corpus/demo/docs?     :",
      any("corpus" in n or "demo" in n or n.startswith("docs/") for n in nombres))
print("  ¿incluye tests?                :", any(n.startswith("tests/") for n in nombres))
