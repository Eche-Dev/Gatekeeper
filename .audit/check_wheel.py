import sys
import zipfile

whl = sys.argv[1]
z = zipfile.ZipFile(whl)
src = z.read("gatekeeper/rules.py").decode("utf-8")
print("contiene _strip_sql_comments :", "_strip_sql_comments" in src)
print("contiene la regex antigua    :", 're.sub(r"/\\*.*?\\*/"' in src)
meta = z.read("gatekeeper_asgi-0.4.1.dist-info/METADATA").decode()
print("Version en METADATA          :", [l for l in meta.splitlines() if l.startswith("Version")][0])
print("Requires-Python              :", [l for l in meta.splitlines() if l.startswith("Requires-Python")][0])
nombres = z.namelist()
print("ficheros en el wheel         :", len(nombres))
print("¿incluye corpus/demo/docs?   :",
      any("corpus" in n or "demo" in n or n.startswith("docs/") for n in nombres))
print("¿incluye tests?              :", any(n.startswith("tests/") for n in nombres))
