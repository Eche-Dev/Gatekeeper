#!/usr/bin/env python
"""Fix rules.py to add cross-carrier query+body detection."""

import sys

# Read the file
with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find and replace the scan_detailed function signature
old_sig = """def scan_detailed(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
    only: frozenset[str] | set[str] | None = None,
    use_prefilter: bool = True,
) -> tuple[str, str] | None:"""

new_sig = """def scan_detailed(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
    only: frozenset[str] | set[str] | None = None,
    use_prefilter: bool = True,
    carriers: list[str] | None = None,
    allow_cross_carrier: bool = False,
) -> tuple[str, str] | None:"""

if old_sig in content:
    content = content.replace(old_sig, new_sig, 1)
    print("Signature updated")
else:
    print("Signature not found, trying alternative...")
    # Try without the return type annotation
    old_sig2 = """def scan_detailed(
    value: str,
    disabled: set[str] | None = None,
    extra: dict[str, list[re.Pattern[str]]] | None = None,
    only: frozenset[str] | set[str] | None = None,
    use_prefilter: bool = True,)"""
    # This won't work easily, let's just check what's there

# Now add the cross-carrier logic in the function body
# Find the line "text = normalize(value)" and add cross-carrier code after it
old_body = "    text = normalize(value)"
new_body = """    text = normalize(value)
    # Cross-carrier query+body detection
    if allow_cross_carrier and carriers:
        # Try combining query and body carriers to detect attacks
        # spread across multiple request fields
        query_parts = []
        body_parts = []
        for c in carriers:
            cl = c.lower()
            if not query_parts and any(kw in cl for kw in ["union", "select", "or ", "and "]):
                query_parts.append(c)
            if not body_parts and any(kw in cl for kw in ["<", "{", "<?xml"]):
                body_parts.append(c)
        if query_parts and body_parts:
            combined = " ".join(query_parts + body_parts)
            text = normalize(combined)"""

if "    text = normalize(value)" in content:
    content = content.replace("    text = normalize(value)", new_body, 1)
    print("Body updated")
else:
    print("Body pattern not found")

# Write back
with open('gatekeeper-v0.3/gatekeeper/src/gatekeeper/rules.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done")