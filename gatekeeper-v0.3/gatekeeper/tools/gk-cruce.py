import json, sys, pathlib, re, collections
sys.path.insert(0, ".")
import importlib.util
spec = importlib.util.spec_from_file_location("ev", "tools/evaluate.py")
ev = importlib.util.module_from_spec(spec)
sys.modules["ev"] = ev
spec.loader.exec_module(ev)

d = json.loads(pathlib.Path("corpus/crs_payloads.json").read_text(encoding="utf-8"))
attacks = [it for it in d["payloads"] if it["expect"] == "attack"]
benign = [it for it in d["payloads"] if it["expect"] == "benign"]

print("=== Implementando cruce query+body ===")
print(f"Attacks: {len(attacks)}, Benign: {len(benign)}")

# Paso 1: Medir detección actual individual
detected_individual = 0
for it in attacks:
    c, i = ev._crs_carriers(it)
    if any(ev.scan(x) for x in c if x):
        detected_individual += 1
print(f"Ataques detectados individualmente: {detected_individual}/{len(attacks)} ({detected_individual/len(attacks)*100:.1f}%)")

# Paso 2: Medir detección con cruce query+body
# El cruce consiste en combinar query string + body y escanear el conjunto
cross_detected = 0
cross_new = 0  # nuevos que no se detectaban individualmente
fp_cross = 0   # falsos positivos en benignos

# Para ataques, contar cuántos se detectan con cruce
for it in attacks:
    c, i = ev._crs_carriers(it)
    # Encontrar query y body carriers
    query_text = ""
    body_text = ""
    for carrier in c:
        # carriers pueden ser strings completos o partes
        # Identificar cuál es query y cuál es body por posición o nombre
        pass
    # Por ahora, analicemos los ataques con 2 carriers
    if len(c) == 2:
        t1, t2 = c[0], c[1]
        # Probar combinación query+body
        combined = " ".join(t1.split()) + " " + " ".join(t2.split())
        # Quitar duplicados y normalizar
        combined_norm = ev.normalize(combined) if hasattr(ev, 'normalize') else combined
        # Escanear combinado
        h = ev.scan_detailed(combined_norm)
        if h:
            cross_detected += 1
            # Ver si alguno individual también lo detectaba
            ind1 = ev.scan_detailed(t1) if t1 else None
            ind2 = ev.scan_detailed(t2) if t2 else None
            if not ind1 and not ind2:
                cross_new += 1
                print(f"    NUEVO por cruce: {uri[:50]!r}")
                print(f"      carriers: {t1[:50]!r} + {t2[:50]!r}")
                print(f"      combined: {combined_norm[:60]!r}")
                print(f"      regla: {h[0]}")

# Para benignos, verificar FP cruzados
print("\nVerificando FP en benignos...")
for it in benign[:50]:  # muestreo
    c, i = ev._crs_carriers(it)
    if len(c) == 2:
        t1, t2 = c[0], c[1]
        combined = " ".join(t1.split()) + " " + " ".join(t2.split())
        combined_norm = ev.normalize(combined) if hasattr(ev, 'normalize') else combined
        h = ev.scan_detailed(combined_norm)
        if h:
            fp_cross += 1
            print(f"    FP cruzado: {it.get('uri')!r} -> {h[0]}")

print(f"\nResultado cruce query+body:")
print(f"  Ataques detectados con cruce: {cross_detected}")
print(f"  Nuevos descubiertos (no Individual): {cross_new}")
print(f"  FP en benignos (muestreo): {fp_cross}")