# Detección y medición

## Cómo inspecciona Gatekeeper

Cada cadena se normaliza antes de tocar las reglas:

```
petición ──► decode()          3 rondas de URL-decoding + escapes %uXXXX (IIS)
           ──► entidades       numéricas (&#60;) y nombradas (&lt;) por rondas
           ──► NFKC            ＜script (ancho completo) → <script
           ──► decode()        segundo pase acotado (NFKC puede revelar %U0027)
           ──► comentarios     /**/ = espacio en blanco; /*!50000union*/ se
                             desenvuelve a `union` (MySQL lo ejecuta)
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
| XSS con etiqueta, handler, esquema, entidad numérica **o nombrada** | `java script:` con espacio: el navegador no lo descarta, no es un esquema |
| Traversal `../` en frontera de segmento (incl. sobre-long `%c0%af`) | Truncación por `%00`: no aplica en Python 3 (lanza error) |
| Ficheros sensibles con separador de ruta | Enumeración passiva (`?id=7`) |
| NoSQL (`$ne`, `$nin`, `$where`, `$regex`), comandos (`; ls`, `` `id` ``), SSRF (metadata y `file://`/…), SSTI (`{{7*7}}`), CRLF con cabecera, Log4Shell (`${jndi:…}`), proto-pollución | Filtros Mongo con `$gt`/`$lt`/`$in` (legítimos); `localhost` como destino (OAuth de desarrollo); binarios sin separador shell delante |
| Cualquier body textual (JSON, form, `text/plain`, XML o sin `content-type`) y cabeceras `User-Agent`/`Referer`/`Cookie` | Bodies binarios y `multipart/form-data`: sin parser propio hasta v0.4 |
| — | Ataques a la lógica, authn/authz, CSRF, rate abuse por usuario |

El desglose completo, con la frontera de falsos positivos de cada familia, está
en [Modelo de amenazas](amenazas.md).

## El corpus propio

131 payloads de ataque y 72 peticiones benignas, **redactados para este proyecto**
a partir de técnicas documentadas públicamente (OWASP WSTG, cheat sheets de
PortSwigger), con procedencia en [corpus/README.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/README.md).

| Métrica | Valor |
|---|---|
| Ataques detectados | **131 / 131 (100.0%)** |
| Falsos negativos sin documentar | 0 |
| Falsos positivos sin documentar | **0** / 72 (5 documentados) |

Los 5 FP documentados existen y se listan con su motivo en
[corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md):
texto técnico que cita vectores (`sleep(5)` en búsquedas, `<script>` como término
de búsqueda, `javascript:` en prosa, `%252e%252e%252f` al hablar de codificación,
`__proto__` en una búsqueda sobre proto-pollución). Colisionan con la firma por
construcción — la regla es que **un límite se documenta, no se esconde**.

## El corpus externo (OWASP CRS)

[coreruleset/coreruleset](https://github.com/coreruleset/coreruleset)
(Apache-2.0, commit `30cb436`) es la colección de regresión de referencia del
mundo WAF. Sus tests de las familias que afirman cubrir — **930 (LFI), 941 (XSS)
y 942 (SQLi)** — se importan a `corpus/crs_payloads.json` con `tools/import_crs.py`
(licencia y procedencia incluidas).

| Métrica (CRS) | Valor |
|---|---|
| Tests importados | 1379 (1135 en alcance) |
| Ataques detectados | 238 / 1135 (**21.0%**) |
| Negativos de CRS bloqueados | 9 / 232 (3.9%) |
| Excluidos y declarados | 12 (cabeceras fuera de `inspect_headers` y bodies binarios) |

!!! success "Por qué se publica el 21.0%"
    Un 100% propio junto a un 21.0% ajeno es la señal de que la medición es
    honesta. El corpus de CRS está diseñado para un WAF de 500+ reglas que
    acepta los falsos positivos que Gatekeeper no acepta; aquí su número es una
    **línea base con guarda de regresión**, no una promesa. Y los 9 FP de CRS
    son, uno a uno, tráfico que cita o imita vectores de inyección (texto de
    documentación, benchmarks y paths de test).

Las familias nuevas de 0.3.1 también suben este número (+19 detecciones): los
tests de CRS incluyen vectores de comandos y SSTI que Gatekeeper ahora
reconoce aunque el test sea de la familia 930/941/942.

## Cómo se mide

```bash
python tools/evaluate.py               # resumen de ambos corpus
python tools/evaluate.py --write-report   # regenera corpus/REPORT.md
python tools/evaluate.py --check       # sale con 1 si empeora (es lo que corre CI)
python tools/evaluate.py --json        # salida legible por máquina
python tools/import_crs.py --check     # procedencia del corpus externo
```

Umbrales actuales en CI: detección **100%** y 0 FP sin documentados (el corpus
propio es la promesa pública); ≥ 19% de detección y ≤ 5% de FP sobre CRS
(guarda de línea base).

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
