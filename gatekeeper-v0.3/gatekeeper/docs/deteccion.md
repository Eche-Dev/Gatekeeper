# Detección y medición

## Cómo inspecciona Gatekeeper

Cada cadena se normaliza antes de tocar las reglas:

```
petición ──► decode()          3 rondas de URL-decoding + escapes %uXXXX (IIS)
           ──► NFKC            ＜script (ancho completo) → <script
           ──► decode()        segundo pase acotado (NFKC puede revelar %U0027)
           ──► quitar /**/     comentarios SQL = espacio en blanco en MySQL
           ──► minúsculas
           ──► reglas (regex)  sobre el texto ya normalizado
```

Todas las reglas integradas usan **cuantificadores acotados** (`\s{0,16}`):
dos `\s*` adyacentes son O(n²) — en v0.3 eso se midió (118 s de CPU con
80.000 espacios) y se corrigió; hay test de regresión.

## Qué cubre y qué no

| Cubre | No cubre (y por qué) |
|---|---|
| SQLi con firma reconocible | Payloads sin firma (`>>`, `RegExp`): no somos un motor de contexto |
| XSS con etiqueta, handler o esquema | Entidades HTML (`&#60;script`): decidido y documentado |
| Traversal `../` en frontera de segmento | UTF-8 sobre-long (`%c0%af`): requeriría validar encoding |
| Ficheros sensibles con separador de ruta | Enumeración passiva (`?id=7`) |
| JSON y form bodies | Cabeceras, cookies, XML, multipart |
| — | Ataques a la lógica, authn/authz, CSRF, rate abuse por usuario |

## El corpus propio

83 payloads de ataque y 62 peticiones benignas, **redactados para este proyecto**
a partir de técnicas documentadas públicamente (OWASP WSTG, cheat sheets de
PortSwigger), con procedencia en [corpus/README.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/README.md).

| Métrica | Valor |
|---|---|
| Ataques detectados | 78 / 83 (**94.0%**) |
| Falsos negativos sin documentar | 0 (5 documentados) |
| Falsos positivos sin documentar | **0** / 62 (4 documentados) |

Los FP/FN documentados existen y se listan con su motivo en
[corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md):
texto técnico que cita vectores (`sleep(5)` en búsquedas), entidades HTML,
blind boolean carácter a carácter… La regla es que **un límite se documenta, no
se esconde**.

## El corpus externo (OWASP CRS)

[coreruleset/coreruleset](https://github.com/coreruleset/coreruleset)
(Apache-2.0, commit `30cb436`) es la colección de regresión de referencia del
mundo WAF. Sus tests de las familias que afirman cubrir — **930 (LFI), 941 (XSS)
y 942 (SQLi)** — se importan a `corpus/crs_payloads.json` con `tools/import_crs.py`
(licencia y procedencia incluidas).

| Métrica (CRS) | Valor |
|---|---|
| Tests importados | 1379 (982 en alcance) |
| Ataques detectados | 185 / 982 (**18.8%**) |
| Negativos de CRS bloqueados | 8 / 185 (4.3%) |
| Excluidos y declarados | 212 (cabeceras y content-types no inspeccionados) |

!!! success "Por qué se publica el 18.8%"
    Un 94% propio junto a un 18.8% ajeno es la señal de que la medición es
    honesta. El corpus de CRS está diseñado para un WAF de 500+ reglas que
    acepta los falsos positivos que Gatekeeper no acepta; aquí su número es una
    **línea base con guarda de regresión**, no una promesa. Y los 8 FP de CRS
    son, uno a uno, texto legítimo que cita vectores de inyección.

## Cómo se mide

```bash
python tools/evaluate.py               # resumen de ambos corpus
python tools/evaluate.py --write-report   # regenera corpus/REPORT.md
python tools/evaluate.py --check       # sale con 1 si empeora (es lo que corre CI)
python tools/evaluate.py --json        # salida legible por máquina
python tools/import_crs.py --check     # procedencia del corpus externo
```

Umbrales actuales en CI: detección ≥ 90% y 0 FP sin documentados (corpus
propio); ≥ 18% de detección y ≤ 5% de FP sobre CRS (guarda de línea base).

## Cómo se añade una regla (resumen)

1. Firma **genérica**, no un caso concreto del examen.
2. Medir antes/después con `evaluate.py` y añadir casos benignos que no deben
   saltar.
3. Cuantificadores acotados; sin ellos, ReDoS.
4. Si la colisión con tráfico legítimo es inevitable, el caso va a
   `benign.json` con `known_fp` y el motivo.

El proceso completo está en
[CONTRIBUTING.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/CONTRIBUTING.md).

---

Siguiente: [Seguridad →](seguridad.md)
