import json, sys, pathlib, re, collections
sys.path.insert(0, "tools")
import importlib.util
spec = importlib.util.spec_from_file_location("ev", "tools/evaluate.py")
ev = importlib.util.module_from_spec(spec)
sys.modules["ev"] = ev
spec.loader.exec_module(ev)
d = json.loads(pathlib.Path("corpus/crs_payloads.json").read_text(encoding="utf-8"))

print("=== Estructura de carriers para ataques ===")
for it in list(d["payloads"])[:5]:
    if it["expect"] != "attack":
        continue
    c, i = ev._crs_carriers(it)
    uri = it.get("uri", "?")
    print(f"URI: {uri!r}")
    print(f"  carriers: {c}")
    print(f"  expect: {it['expect']}")
    print()