#!/usr/bin/env python
"""Add carriers and allow_cross_carrier to scan_detailed in rules.py"""

with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

output = []
i = 0
while i < len(lines):
    line = lines[i]
    
    # Check if this is the scan_detailed signature completion line
    if i < len(lines) - 1 and 'def scan_detailed(' in line and 'use_prefilter: bool = True,' in line:
        # This is the signature line - we need to modify it
        # The line is: '    use_prefilter: bool = True,\n'
        # We need to add carriers and allow_cross_carrier after it
        
        # First, output the current line
        output.append(line)  # '    use_prefilter: bool = True,\n'
        i += 1
        
        # Next line should be ') -> tuple[str, str] | None:'
        if i < len(lines) and ') -> tuple[str, str] | None:' in lines[i]:
            # Replace this line with the extended signature
            output[-1] = '    use_prefilter: bool = True,\n'  # Keep the modified line
            output.append('    carriers: list[str] | None = None,\n')
            output.append('    allow_cross_carrier: bool = False,\n')
            output.append(lines[i])  # ') -> tuple[str, str] | None:'
            i += 1
        
        # Now add the docstring update
        # The docstring starts next
        # Skip the old docstring and rewrite it
        # Count how many lines the old docstring takes
        doc_start = i
        indent_level = None
        doc_lines = 0
        while i < len(lines):
            if lines[i].startswith('    """'):
                doc_lines += 1
            elif lines[i].startswith('    """') and i > doc_start:
                # End of docstring
                doc_lines += 1
                break
            elif lines[i].startswith('    ') and not lines[i].startswith('    """'):
                doc_lines += 1
            else:
                break
        
        # Actually, let's just add the new docstring content and the cross-carrier code
        # by replacing from '"""' onwards
        
        # Find the end of the old docstring
        j = i
        in_doc = False
        doc_end = -1
        while j < len(lines):
            if '"""' in lines[j]:
                if in_doc:
                    doc_end = j
                    break
                else:
                    in_doc = True
            j += 1
        
        if doc_end >= 0:
            # We have the old docstring from i to doc_end
            # Replace lines i through doc_end with new content
            
            # New docstring ending and cross-carrier code
            new_after_sig = '''    """Como `scan()`, pero devuelve `(regla, patrón)` ó el patrón es el "motivo"
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
    """'''
            
            # Replace lines i to doc_end inclusive with new content
            output = output[:doc_start - i]  # This won't work right, let me restart
            
    # This is getting too complex. Let me just use a simpler regex replacement approach.
    break

# Write back what we have
with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'w', encoding='utf-8') as f:
    f.writelines(output[:i] if i > 0 else lines)

print(f"Processed up to line {i}")