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

### Las fronteras que la Fase 3 añadió (y lo que cuestan)

Endurecer una firma para que no salte con la prosa siempre tiene un precio. La
Fase 3 lo midió caso por caso (`.audit/f3_ajustes.py`: cuántos ataques
dependían **solo** de la firma) y estas son las fronteras que quedaron:

| Frontera | Qué NO se detecta ahora | Por qué |
|---|---|---|
| `union all` exige contexto de consulta o de ruta detrás | `union all` solo, sin `select`/`from`/`null`/`values`/`table`/`(`/`/` | «union all» en un tutorial de SQL es de las búsquedas más frecuentes |
| `WAITFOR DELAY` exige el literal de tiempo detrás | `waitfor delay` sin comilla ni dígito | La forma real (`WAITFOR DELAY '0:0:5'`) siempre lo lleva |
| `like null` exige el cierre del payload detrás | `like null` en medio de una frase | La forma de ataque cierra el payload (`1 LIKE NULL--`) |
| Operadores NoSQL exigen objeto JSON o parámetro | `$ne` suelto en un texto | El ataque va dentro de un objeto (`{"$ne": ""}`, `user[$ne]=x`) |
| `sleep` exige argumento numérico | `sleep(8 hours)` y cualquier unidad | Es prosa, no una función SQL |

Las cuatro primeras salen de un corpus de **100 peticiones legítimas nuevas**
en español e inglés (abajo). Lo que **no** se tocó, y por tanto sigue
saltando, está en la tabla de límites del [modelo de amenazas](amenazas.md) y
en el informe del corpus: `{{config}}` (vector de Jinja2), `${env:...}` y
`${jndi}` (familia Log4Shell), el salto de línea seguido de cabecera (CRLF) y
la IP de metadata citada en una explicación (SSRF).

El desglose completo, con la frontera de falsos positivos de cada familia, está
en [Modelo de amenazas](amenazas.md).

## El corpus propio

159 payloads de ataque y 131 peticiones benignas, **redactados para este proyecto**
a partir de técnicas documentadas públicamente (OWASP WSTG, cheat sheets de
PortSwigger), con procedencia en [corpus/README.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/README.md).

| Métrica | Valor |
|---|---|
| Ataques detectados | **159 / 159 (100.0%)** |
| Falsos negativos sin documentar | 0 |
| Falsos positivos sin documentar | **0** / 131 (8 documentados) |

Estas cifras miden los escaneos individuales del corpus; no incluyen el modo
opt-in `inspect_cross_carrier=True`.

Los 8 FP documentados existen y se listan con su motivo en
[corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md):
texto técnico que cita vectores (`sleep(5)` en búsquedas, `<script>` como término
de búsqueda, `javascript:` en prosa, `%252e%252e%252f` al hablar de codificación,
`__proto__` en una búsqueda sobre proto-pollución, `{{config}}` en una
búsqueda sobre plantillas de Jinja, `${env:…}`/`${jndi}` en una búsqueda sobre
Log4Shell, y un cuerpo de correo con un salto de línea y una cabecera citada).
Colisionan con la firma por construcción — la regla es que **un límite se
documenta, no se esconde**.

### El corpus de falsos positivos (100 casos nuevos, en español e inglés)

La Fase 3 añadió **100 peticiones legítimas nuevas**, escritas a mano en los dos
idiomas del proyecto:

- **50 en el corpus de desarrollo** (`corpus/benign.json`, `benign-082` …
  `benign-131`): es el que se puede ajustar. Los 10 que saltaban motivaron
  cuatro endurecimientos de firma, medidos uno por uno para no perder
  detecciones.
- **50 en el corpus retenido** (`corpus/heldout_benign.json`, `hob-091` …
  `hob-140`): escritos **después** de congelar las firmas y medidos **una vez**.
  Un falso positivo ahí no se corrige con una firma escrita para él: se
  documenta. De los tres que saltaron, dos los resolvieron los ajustes que
  motivó el corpus de desarrollo y el tercero (la IP de metadata citada en una
  explicación) sigue abierto y documentado.

Todo el procedimiento —qué se midió, qué se cambió y qué NO se cambió— está
en [`corpus/HELDOUT.md`](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/HELDOUT.md)
y en los informes generados.

## El corpus retenido (held-out)

!!! info "Por qué existe un corpus aparte"
    El corpus de desarrollo se puede usar para **ajustar** las reglas: cada
    firma nueva se escribe para el caso que la motivó. Al final, su 100% mide
    memoria, no generalización.

    El corpus retenido se escribió **una vez**, sin mirar las firmas de las
    reglas, y desde entonces solo se **mide**. Es la diferencia entre
    "las reglas detectan esto" y "las reglas detectan lo que se escribieron
    para ellas".

| Métrica | Desarrollo | **Retenido** |
|---|---|---|
| Ataques detectados | 159/159 (100%) | **103/109 (94,5%)** |
| Falsos positivos sin documentar | 0 | **0** / 140 |
| Falsos negativos documentados | 0 | 6 |
| Falsos positivos documentados | 8 | 5 |

!!! success "Por qué el retenido da 94,5% y no 100%"
    Porque es **más difícil a propósito**: incluye técnicas que las reglas no
    cubren, y esas están marcadas con su motivo (`documented_miss`). Un 100%
    aquí significaría que el corpus retenido se ajustó, que es exactamente lo
    que no debe pasar.

    El umbral de CI está en **85%**, no en 100%, por la misma razón: es una
    guarda de regresión, no una promesa.

Metodología completa (cómo se escribió, qué reglas de uso tiene y qué fallos
encontró):
[corpus/HELDOUT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/HELDOUT.md).
Informe generado:
[corpus/HELDOUT_REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/HELDOUT_REPORT.md).

!!! warning "El corpus retenido no es una promesa de que no haya más"
    Mide sobre **109 ataques y 140 peticiones legítimas**. Es una muestra, no
    un censo. La conclusión honesta es "estas 109 técnicas y estos 140 patrones
    se comportan así", no "la detección es completa".

!!! tip "La única forma de saberlo con tu tráfico"
    Los corpus son sintéticos. Para ver si Gatekeeper bloquea **tu** tráfico
    legítimo hace falta observarlo en modo monitor durante un tiempo: es el
    procedimiento de [Medir con tráfico real](trafico-real.md), con sus
    requisitos de autorización y qué se puede publicar.

## El corpus externo (OWASP CRS)

[coreruleset/coreruleset](https://github.com/coreruleset/coreruleset)
(Apache-2.0, commit `30cb436`) es la colección de regresión de referencia del
mundo WAF. Sus tests de las familias que afirman cubrir — **930 (LFI), 941 (XSS)
y 942 (SQLi)** — se importan a `corpus/crs_payloads.json` con `tools/import_crs.py`
(licencia y procedencia incluidas).

| Métrica (CRS) | Valor |
|---|---|
| Tests importados | 1379 (1135 en alcance) |
| Ataques detectados | 465 / 1135 (**41.0%**) |
| Negativos de CRS bloqueados | 11 / 232 (4.7%) |
| Excluidos y declarados | 12 (cabeceras fuera de `inspect_headers` y bodies binarios) |

!!! success "Por qué se publica el 41.0%"
    Un 100% propio junto a un 41.0% ajeno es la señal de que la medición es
    honesta. El corpus de CRS está diseñado para un WAF de 500+ reglas que
    acepta los falsos positivos que Gatekeeper no acepta; aquí su número es una
    **línea base con guarda de regresión**, no una promesa. Y los 11 FP de CRS
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
