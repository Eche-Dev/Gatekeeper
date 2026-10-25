import re
with open('D:\\ADEV\\ProyectosVScode\\Gatekeeper\\gatekeeper-v0.3\\gatekeeper\\docs\\compatibilidad.md', 'r', encoding='utf-8') as f:
    content = f.read()
links = re.findall(r'\[([^\]]+)\]\(#([^)]+)\)', content)
for text, url in links:
    print(f'Link: "{text}" -> "#{url}"')
print()
headers = re.findall(r'^(## .+)$', content, re.MULTILINE)
for h in headers:
    print(f'Header: "{h}"')