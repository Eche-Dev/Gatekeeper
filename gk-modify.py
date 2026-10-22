#!/usr/bin/env python
"""Modify rules.py to add cross-carrier query+body detection."""

with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Replace the scan_detailed function signature and add cross-carrier logic
old = """def scan_detailed(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
    only: frozenset[str] | set[str] | None = None,
    use_prefilter: bool = True,
) -> tuple[str, str] | None:
    """Como `scan()`, pero devuelve `(regla, patrón)` ó el patrón es el "motivo"
    que se registra en los eventos de auditoría para poder tunear sin adivinar.

    `only` limita la evaluación a un subconjunto de familias (los packs de
    `Config.active_rules`); las reglas personalizadas de `extra` se evalúan
    siempre, porque son tuyas y las pediste explícitamente.

    `use_prefilter` activa el descarte de familias cuyo literal obligatorio no
    aparece en el texto (ver `PREFILTER_LITERALS`). No cambia qué se detecta:
    un test lo verifica contra los dos corpus (propio y CRS) y falla si alguien
    añade una regla sin prefilarla o la prefila mal.
    """
    text = normalize(value)"""

new = """def scan_detailed(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
    only: frozenset[str] | set[str] | None = None,
    use_prefilter: bool = True,
    carriers: list[str] | None = None,
    allow_cross_carrier: bool = False,
) -> tuple[str, str] | None:
    """Como `scan()`, pero devuelve `(regla, patrón)` ó el patrón es el "motivo"
    que se registra en los eventos de auditoría para poder tunear sin adivinar.

    `only` limita la evaluación a un subconjunto de familias (los packs de
    `Config.active_rules`); las reglas personalizadas de `extra` se evalúan
    siempre, porque son tuyas y las pediste explícitamente.

    `use_prefilter` activa el descarte de familias cuyo literal obligatorio no
    aparece en el texto (ver `PREFILTER_LITERALS`). No cambia qué se detecta:
    un test lo verifica contra los dos corpus (propio y CRS) y falla si alguien
    añade una regla sin prefilarla o la prefila mal.

    `carriers` y `allow_cross_carrier` permiten escanear la combinación de
    múltiples carriers (p. ej. query + body) para detectar ataques donde las
    partes clave están repartidas por campos. Si es True, combina los carriers
    marcados antes de escanear.
    """
    text = normalize(value)
    # Cross-carrier query+body detection (opcional)
    if allow_cross_carrier and carriers:
        # Agrupar carriers por tipo: query vs body
        query_parts = []
        body_parts = []
        for c in carriers:
            cl = c.lower()
            # Señales de que es contenido de query (palabras clave SQL, operadores)
            if not query_parts and any(kw in cl for kw in ["union", "select", "or ", "and "]):
                query_parts.append(c)
            # Señales de que es contenido de body (XML, JSON, HTML, tags)
            if not body_parts and any(kw in cl for kw in ["<", "{", "<?xml"]):
                body_parts.append(c)
        if query_parts and body_parts:
            combined = " ".join(query_parts + body_parts)
            text = normalize(combined)

    # Resto de la función original
    desactivada = disabled or set()"""

print(f"Old string length: {len(old)}")
print(f"New string length: {len(new)}")
print(f"Old in content: {old in content}")

if old in content:
    content = content.replace(old, new, 1)
    with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Successfully modified rules.py")
else:
    print("Old string NOT found - showing context...")
    idx = content.find('def scan_detailed')
    if idx >= 0:
        print(f"Found at index {idx}")
        print("--- context ---")
        print(content[idx:idx+600])