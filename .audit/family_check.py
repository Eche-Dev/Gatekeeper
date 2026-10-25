import sys

sys.path.insert(0, r"D:\ADEV\ProyectosVScode\Gatekeeper\gatekeeper-v0.3\gatekeeper\src")
from gatekeeper.rules import RULES, scan_detailed

fam = {}
for nombre, patron in RULES.items():
    for p in patron:
        fam.setdefault(nombre, []).append(p.pattern)

for nombre in ("sqli", "sensitive_files"):
    for p in fam.get(nombre, []):
        if "union" in p or "or" in p[:20]:
            print(nombre, "->", p[:75])

print()
print("'union select 1' con only={'sensitive_files'} (sqli desactivado):",
      scan_detailed("union select 1", only={"sensitive_files"}))
print("'union select 1' con only={'sqli'}:",
      scan_detailed("union select 1", only={"sqli"}))
print("'1' or '1'='1' con only={'sensitive_files'}:",
      scan_detailed("1' or '1'='1", only={"sensitive_files"}))
