import json
import sys

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")
from gatekeeper.body import looks_like_json

CASOS = [
    ("JSON normal", b'{"q":"union select 1"}'),
    ("JSON con espacios delante", b"   " + b'{"q":"union select 1"}'),
    ("JSON con 100 espacios delante", b" " * 100 + b'{"q":"union select 1"}'),
    ("JSON con 5000 espacios delante", b" " * 5000 + b'{"q":"union select 1"}'),
    ("JSON con tab/CR/LF delante", b"\t\r\n " + b'{"q":"union select 1"}'),
    ("JSON con BOM UTF-8", b"\xef\xbb\xbf" + b'{"q":"union select 1"}'),
    ("array JSON", b'[{"q":"union select 1"}]'),
    ("binario PNG", b"\x89PNG\r\n\x1a\n"),
    ("texto normal", b"hola mundo"),
]

print(f"{'caso':<32} {'json.loads':>12} {'looks_like_json':>16}  ¿bypass?")
print("-" * 80)
for nombre, cuerpo in CASOS:
    try:
        json.loads(cuerpo)
        parsea = "SI"
    except Exception:
        parsea = "no"
    sniff = looks_like_json(cuerpo)
    # Bypass real: la app lo parsea como JSON pero Gatekeeper no lo detecta.
    bypass = "SI <<<" if (parsea == "SI" and not sniff) else ""
    print(f"{nombre:<32} {parsea:>12} {str(sniff):>16}  {bypass}")
