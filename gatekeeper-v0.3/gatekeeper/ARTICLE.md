<!--
  Artículo listo para publicar tal cual en dev.to, Hashnode o echedev.vercel.app.
  El GIF ya apunta a la URL raw definitiva del repo; no hay que sustituir nada.
  Tags sugeridos para dev.to (al final del todo): python, security, fastapi, ...
  Original en español; si pides traducción al inglés, publícala en cross-post.
-->

# Un DoS de 118 segundos: el ReDoS que encontré midiendo mi propio middleware de seguridad

*o: cómo medir un WAF casero sin mentirte a ti mismo*

![Demo del comportamiento de Gatekeeper](https://raw.githubusercontent.com/Eche-Dev/Gatekeeper/main/gatekeeper-v0.3/gatekeeper/docs/assets/demo.gif)

**Gatekeeper** es un middleware ASGI que escribí para FastAPI/Starlette: rate
limiting, cabeceras de seguridad y detección de patrones de ataque (SQLi, XSS,
path traversal) en query y body. El código está en
[GitHub](https://github.com/Eche-Dev/Gatekeeper) y la
[documentación aquí](https://eche-dev.github.io/Gatekeeper/).

Este artículo no es un tutorial de "mira lo bien que funciona". Es sobre las dos
cosas que más me costaron y que más aprendí: **medir el proyecto con un corpus
que no escribí yo** y **el ReDoS cuadrático que esa medición destapó**.

## Primero, lo incómodo: el 19.3%

Cuando publiqué las primeras métricas de Gatekeeper tenían cara de póster:
**100% de detección** (83/83) sobre mi corpus propio y **cero falsos
positivos** sin documentar. Bonito. También sospechoso: el corpus lo había
escrito yo, con las técnicas que mi middleware sabía bloquear. Un examen que
haces tú no mide nada.

Así que añadí una segunda batería escrita por gente distinta: los tests de
regresión de [OWASP CRS](https://github.com/coreruleset/coreruleset), la
colección de reglas de referencia del mundo WAF (Apache-2.0, con licencia y
commit de procedencia incluidos). Importé 1.379 tests de las familias que
afirman cubrir —LFI, XSS y SQLi— y los pasé por Gatekeeper.

Resultado: **19.3% de detección** (219/1135 en alcance).

```
Corpus propio (83 ataques):       100.0%  ← el número del póster
Corpus OWASP CRS  (1135 ataques):  19.3%  ← el número de verdad
```

Y lo publiqué igual, con la guarda en CI para que no baje. ¿Por qué? Porque un
100% junto a un 19.3% es la única señal creíble de que la medición es honesta.
El corpus de CRS está diseñado para un WAF de 500 reglas que acepta falsos
positivos que Gatekeeper no acepta (su propio conjunto de negativos tiene un
3.9% de bloqueos que, uno a uno, son texto legítimo citando vectores de
inyección). El 19.3% no es una meta: es una **línea base con guarda de
regresión**. Y el día en que una regla nueva suba ese número de verdad, va a
subir acompañado de los tests benignos que la justifican.

Lo que esa segunda batería me compró, además de honestidad, fue confianza para
tunear: cada cambio de regla ahora se mide contra dos corpus y contra el
histograma de misses (spoiler: hay evasiones sin firma genérica que no se
arreglan con una regex más, y parar de tunear también es una decisión).

## Lo que la medición destapó: 118 segundos por petición

Una de las familias de CRS es "ataques con recursos excesivos". Yo me reía:
*"mi middleware no parsea, solo compara strings con regex, ¿qué recurso
excesivo?"*.

Hasta que medí. Con un script tonto de crecimiento:

```python
import time
from gatekeeper.rules import scan

for n in (10_000, 20_000, 40_000, 80_000):
    payload = "or" + " " * n
    t = time.perf_counter()
    scan(payload)
    print(f"n={n:>6}  {time.perf_counter() - t:8.2f} s")
```

```
n= 10000      1.86 s
n= 20000      7.41 s
n= 40000     29.70 s
n= 80000    118.30 s   ← el tiempo se multiplica x4 cuando doblas la entrada
```

**Cuadrático.** Y con bodies admitidos de 1 MiB, cualquiera podía quemarme el
event loop del servidor con una sola petición. Un DoS casero, sin
autenticación, contra un middleware cuyo trabajo era justamente no dejar pasar
maldades.

### La causa: dos cuantificadores sin techo

La regla de tautologías de SQLi contenía algo así:

```python
r"(?:\bor\b|\band\b)\s*[(']?\s*['\"]?\w+..."
#                        ^^          ^^
#                     \s*          \s*   ← dos estrellas adyacentes
```

Dos cuantificadores de blancos sin límite consecutivos son la receta clásica
de **backtracking cuadrático**: para `or` + 80.000 espacios, el motor de regex
prueba cada reparto posible de los espacios entre los dos `\s*` antes de
rendirse. No es un bug de Python; es cómo funcionan las Thompson NFA
retrocedentes. Con 80 KB de basura y cores compartidos, eso es un bloqueo de
minutos por petición.

### La corrección: acotar todo

```python
# antes: \s*          # después:
(?:\bor\b|\band\b)\s{0,16}[(']?\s{0,16}['\"]?\w+...
```

La misma expresión con techo (`\s{0,16}`) es lineal: la misma batería con
**1.000.000 de caracteres** pasa a tardar **menos de 1 segundo**. Y16 espacios
de techo no pierden detección ninguna — ningún payload real de CRS lleva más
blancos que eso entre `or` y su comilla.

Recorrí `rules.py` entero y acoté **todos** los cuantificadores de blancos
adyacentes. El fichero que hizo el ReDoS ya no existe, y hay un test de
regresión con las ocho entradas patológicas (espacios, comillas, `%u0027`
repetido, un megabyte de `a`) que falla en segundos si alguien reintroduce el
patrón.

## Cómo evité repetirlo: fuzzing con property-based

Un test de regresión protege contra *ese* ReDoS. Contra los que aún no existen
protegen invariantes, y para invariantes está [hypothesis](https://hypothesis.readthedocs.io/):

- `normalize()` es idempotente (`normalize(normalize(x)) == normalize(x)`)
  con entradas arbitrarias de unicode, percent-encoding y bytes;
- ninguna entrada arbitraria revienta `scan()`, `extract_strings()` ni
  `Config()` con excepciones que no sean las documentadas;
- `allow_paths` **nunca** exime una ruta con indicios de traversal: si
  `/docs/*` está permitido, `/docs/../admin` no se cuela. Esa propiedad está
  escrita como tal, y es la diferencia entre una feature y un agujero.

El día que introduje a propósito un `\s*` adyacente para ver qué pasaba, el
fuzzer lo cazó antes que yo.

## El GIF del final

Todo lo anterior se ve en una petición real contra la demo
([`demo/`](https://github.com/Eche-Dev/Gatekeeper/tree/main/gatekeeper-v0.3/gatekeeper/demo)):
tráfico normal pasa, `' OR 1=1--` recibe 403, y la auditoría del servidor
registra la regla que saltó **sin registrar el contenido del payload** (un log
de seguridad no debe ser un depósito de credenciales interceptadas).

## Lo que me llevo

1. **Mide con corpus de otros.** Tu examen propio mide tu examen propio. Un
   corpus externo (CRS, SecLists, lo que sea) con procedencia y licencia
   claras te da una línea base real.
2. **Publica el número malo.** El 19.3% es lo que hace creíble el 100%.
3. **Los cuantificadores adyacentes son una bomba de relojería.** Acótalos
   (`\s{0,16}`), siempre. Cuesta cero rendimiento y te ahorra un DoS.
4. **Mide el crecimiento, no solo el tiempo.** "Tarda 2 s" puede ser lineal
   con constante gorda; "x4 al doblar la entrada" es cuadrático y es un
   incidente futuro.
5. **Guarda tus métricas en CI.** Detección 100% sobre tu corpus, cero FP sin documentar,
   línea base de CRS sin bajar: si alguien (tú, a las 2 a.m.) rompe una
   regla, el pipeline lo dice, no la sensación.

Gatekeeper sigue siendo una capa adicional de defensa en profundidad, no un
WAF ni una sustitución de las consultas parametrizadas. Eso también está en el
README, sin adornos.

---

**Enlaces**: [Repositorio](https://github.com/Eche-Dev/Gatekeeper) ·
[Documentación](https://eche-dev.github.io/Gatekeeper/) ·
[Informe de medición completo](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md) ·
[Proceso de seguridad](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md)

¿Feedback o has encontrado una evasión? Ábrelo en
[issues](https://github.com/Eche-Dev/Gatekeeper/issues) — o escríbeme, si es
de seguridad.

<!-- Tags dev.to: #python #security #fastapi #opensource #performance #waf -->
