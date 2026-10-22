#!/usr/bin/python
# Simpler approach: modify rules.py to add cross-carrier detection

with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

# Find the scan_detailed function and modify it
output = []
i = 0
while i < len(lines):
    line = lines[i]
    
    # Check if this is the scan_detailed signature line
    if i < len(lines) - 1 and 'def scan_detailed(' in line and 'use_prefilter: bool = True,' in line:
        # Add carriers and allow_cross_carrier parameters
        output.append(line)  # def scan_detailed(
        output.append('    value: str,\n')
        output.append('    disabled: set[str] | None = None,\n')
        output.append('    extra: dict[str, list[re.Pattern[str]]] | None = None,\n')
        output.append('    only: frozenset[str] | set[str] | None = None,\n')
        output.append('    use_prefilter: bool = True,\n')
        output.append('    carriers: list[str] | None = None,\n')
        output.append('    allow_cross_carrier: bool = False,\n')
        # Skip the old ') ->' line, we'll add it later
        i += 1
        # Skip the old ') -> tuple[str, str] | None:' line
        while i < len(lines) and not (') -> tuple[str, str] | None:' in lines[i]):
            i += 1
        if i < len(lines):
            i += 1  # skip the old signature closing line
        # Add the new signature closing line
        output.append(') -> tuple[str, str] | None:\n')
        output.append('    """Como `scan()`, pero devuelve `(regla, patrón)` ó el patrón es el "motivo"\n')
        output.append('    que se registra en los eventos de auditoría para poder tunear sin adivinar.\n')
        output.append('\n')
        output.append('    `only` limita la evaluación a un subconjunto de familias (los packs de\n')
        output.append('    `Config.active_rules`); las reglas personalizadas de `extra` se evalúan\n')
        output.append('    siempre, porque son tuyas y las pediste explícitamente.\n')
        output.append('\n')
        output.append('    `use_prefilter` activa el descarte de familias cuyo literal obligatorio no\n')
        output.append('    aparece en el texto (ver `PREFILTER_LITERALS`). No cambia qué se detecta:\n')
        output.append('    un test lo verifica contra los dos corpus (propio y CRS) y falla si alguien\n')
        output.append('    añade una regla sin prefilarla o la prefila mal.\n')
        output.append('\n')
        output.append('    `carriers` y `allow_cross_carrier` permiten escanear la combinación de\n')
        output.append('    múltiples carriers (p. ej. query + body) para detectar ataques donde las\n')
        output.append('    partes clave están repartidas por campos. Si es True, combina los carriers\n')
        output.append('    marcados antes de escanear.\n')
        output.append('    \"\"\"\n')
        output.append('    text = normalize(value)\n')
        output.append('    # Cross-carrier query+body detection (opcional)\n')
        output.append('    if allow_cross_carrier and carriers:\n')
        output.append('        # Agrupar carriers por tipo: query vs body\n')
        output.append('        query_parts = []\n')
        output.append('        body_parts = []\n')
        output.append('        for c in carriers:\n')
        output.append('            cl = c.lower()\n')
        output.append('            # Señales de que es contenido de query (palabras clave SQL, operadores)\n')
        output.append('            if not query_parts and any(kw in cl for kw in ["union", "select", "or ", "and "]):\n')
        output.append('                query_parts.append(c)\n')
        output.append('            # Señales de que es contenido de body (XML, JSON, HTML, tags)\n')
        output.append('            if not body_parts and any(kw in cl for kw in ["<", "{", "<?xml"]):\n')
        output.append('                body_parts.append(c)\n')
        output.append('        if query_parts and body_parts:\n')
        output.append('            combined = " ".join(query_parts + body_parts)\n')
        output.append('            text = normalize(combined)\n')
    else:
        output.append(line)
        i += 1

with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'w', encoding='utf-8') as f:
    f.writelines(output)

print("Done modifying rules.py")