#!/usr/bin/env python
"""Fix type annotations for CI compatibility."""

with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# Add typing import after the future import
if 'from __future__ import annotations' in content and 'from typing import' not in content:
    content = content.replace(
        'from __future__ import annotations',
        'from __future__ import annotations\nfrom typing import List'
    )
    print('Added typing import')

# Replace list[str] with List[str] in the scan_detailed signature
# Find and replace the carriers parameter
old_carrier = '    carriers: list[str] | None = None,'
new_carrier = '    carriers: List[str] | None = None,'

if old_carrier in content:
    content = content.replace(old_carrier, new_carrier)
    print('Replaced carriers annotation')
else:
    print('Carrier annotation not found with that exact string')

# Also check for allow_cross_carrier annotation
old_allow = '    allow_cross_carrier: bool = False,'
# This one is fine as bool

# Check if there's list[str] elsewhere
if 'list[str]' in content:
    # Replace all occurrences of list[str] with List[str]
    content = content.replace('list[str]', 'List[str]')
    print('Replaced all list[str] with List[str]')

with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'w', encoding='utf-8') as f:
    f.write(content)

print('Done. Verifying:')
# Check result
with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'r', encoding='utf-8', errors='replace') as f:
    c = f.read()
print('list[str] still present:', 'list[str]' in c)
print('List[str] now present:', 'List[str]' in c)