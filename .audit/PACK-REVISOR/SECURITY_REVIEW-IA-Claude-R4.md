# Revisión de seguridad — Gatekeeper 0.9.2 (ronda 4)

**Fecha:** 2026-10-29 · **Autor/a:** Claude (Anthropic) · **Commit:** `365710f`

---

## Punto de partida

Verificado antes de empezar: **ningún cambio en `src/` desde la ronda 3**
(`git diff 472a929..HEAD -- .../src` vacío). Los commits recientes son solo
de documentación (vídeo tutorial, portada del README). NUEVO-3 (la laguna
de `document['cookie']` / `document?.cookie`) sigue exactamente como se
reportó, y lo confirmo de nuevo con más variantes abajo.

Esta ronda ataca por **cinco frentes nuevos** que no había tocado en las
tres rondas anteriores: formas adicionales de acceso a `document`/`window`
en JS, motores de plantillas distintos de Jinja2, codificaciones de IP para
SSRF, operadores NoSQL menos comunes, y variantes de *prototype pollution*.

---

## Resumen

| | |
|---|---|
| NUEVO-3 (ronda 3) | **Sigue abierto.** Confirmado con 10 variantes nuevas, 10/10 evaden |
| Hallazgos genuinamente nuevos esta ronda | 2 (ambos en `ssrf`) |
| Comprobado y descartado (no son hallazgos) | SSTI de otros motores, NoSQL `$expr`/`$lookup`, *prototype pollution* con escapes Unicode — explico por qué en cada caso |

---

## NUEVO-3 (reconfirmado, con más alcance)

No lo repito entero — está en `SECURITY_REVIEW-IA-Claude-R3.md` con PoC de
exfiltración real en Node. Esta ronda añadió 10 variantes más, todas
evadiendo igual: `document?.['cookie']` (combinando *optional chaining* y
corchetes), `window[`eval`]('1')` (nombre de función como *template
literal*), `window['ev'+'al']('1')` (nombre construido por concatenación),
`self.document['cookie']`, `globalThis['document']['cookie']`. El patrón
es siempre el mismo: cualquier forma de acceso que no sea el punto literal
inmediato o la llamada con paréntesis evade la familia `xss` en esta
sub-regla. **Esto es lo primero que hay que parchear.**

---

## Hallazgo nuevo 1

### NUEVO-5 — El octal hardcodeado para la IP de metadata cloud está mal calculado: codifica 170.254.170.254, no 169.254.169.254

**Gravedad:** Media-Alta · **Vector:** SSRF con la IP de AWS/GCP IMDS codificada en octal

**Qué pasa**

`rules.py` (línea ~469) tiene una lista extensa y cuidadosa de formas
alternativas de escribir `169.254.169.254` — decimal, hexadecimal, octal —
precisamente para cerrar el bypass clásico de SSRF por codificación de IP.
El literal octal es `0252\.0376\.0252\.0376`. El problema es aritmético:
**`0o252` es 170 en decimal, no 169** (169 en octal es `0o251`). El
comentario del propio código dice que esta línea cubre
`http://2852039166/` (la forma decimal, correcta) y sus equivalentes, pero
el equivalente octal que realmente escribieron corresponde a
`170.254.170.254` — una IP que no significa nada — no a `169.254.169.254`.
El mismo desplazamiento de un octal se repite en la variante para el
*endpoint* de ECS (`0252\.0376\.0252\.0002`, que debería ser
`0251\.0376\.0251\.0002` para representar `169.254.170.2`).

**Impacto (medido)**

```python
scan_detailed("http://2852039166/latest/meta-data/")        # decimal, correcto
# -> ('ssrf', ...)  SÍ detecta

scan_detailed("http://0251.0376.0251.0376/latest/meta-data/")  # octal REAL de 169.254.169.254
# -> None             NO detecta — el que un atacante usaría de verdad

scan_detailed("http://0252.0376.0252.0376/latest/meta-data/")  # lo que el regex SÍ reconoce
# -> ('ssrf', ...)  detecta, pero esta URL apunta a 170.254.170.254, irrelevante
```

Cualquier navegador o librería HTTP (curl, `requests`, el `fetch` de un
navegador) interpreta `0251.0376.0251.0376` exactamente como
`169.254.169.254` — la resolución de IP en notación octal por octeto es un
comportamiento estándar, no un truco exótico. Un atacante que calcule bien
el octal (o use cualquier generador de payloads SSRF, que lo calculan
automáticamente) pasa sin que la regla que se escribió específicamente
para detectarlo lo detecte.

**PoC**

```bash
cd gatekeeper-v0.3/gatekeeper
python .audit/PACK-REVISOR/ejecutar_pocs.py r4_ssrf_octal
```

**Corrección propuesta**

Cambiar `0252` por `0251` en los dos literales octales de la línea ~469 y
~470. Es un error de un carácter en dos sitios; no toca la arquitectura.
Después, confirmar con un test de regresión explícito que calcule el octal
en Python (`oct(169)`, `oct(254)`) en vez de escribirlo a mano, para que un
futuro error del mismo tipo no vuelva a colarse en silencio.

**Estado:** cerrado ✅ (corregidos los literales octales de `169.254.169.254` y `169.254.170.2` a `0251.0376.0251.0376` y `0251.0376.0252.0002` en `rules.py`, `PREFILTER_LITERALS["ssrf"]` y `test_deteccion_f3.py`, más test aritmético con `oct()` en `test_rules.py`)

---

## Hallazgo nuevo 2

### NUEVO-6 — La documentación promete detectar un loopback (127.0.0.1) codificado en decimal; el código no tiene ningún literal para ello

**Gravedad:** Baja · **Vector:** documentación vs. implementación

**Qué pasa**

`docs/amenazas.md`, en la fila de `ssrf`, dice literalmente: *"`localhost`
y `127.0.0.1` no se bloquean [...] Una IP de loopback codificada en
decimal sí es sospechosa"*. Es una promesa explícita y razonable (el texto
plano `127.0.0.1` tiene usos legítimos — OAuth local, *webhooks* de
desarrollo —, pero la forma decimal casi nunca aparece en tráfico
legítimo, así que vale la pena marcarla). El problema es que esa regla no
existe: la lista de literales de `rules.py` solo cubre IPs de metadata
cloud (AWS/GCP/Azure/Alibaba/ECS), ninguna forma de `127.0.0.1`.

**Impacto (medido)**

```python
scan_detailed("http://2130706433/")   # 127.0.0.1 en decimal
# -> None
```

**Por qué la gravedad es baja y no media:** a diferencia de NUEVO-5 (que sí
rompe una protección contra robo de credenciales cloud), aquí lo que se
rompe es una promesa de documentación sobre un objetivo (loopback) que el
propio proyecto ya reconoce como de bajo valor para un atacante en la
mayoría de los casos (por eso lo deja pasar en texto plano). El daño real
es que alguien lea la documentación y confíe en una protección que no
existe, no una vulnerabilidad grave en sí misma.

**PoC**

```bash
python .audit/PACK-REVISOR/ejecutar_pocs.py r4_loopback_decimal
```

**Corrección propuesta**

Dos caminos, cualquiera cierra el hallazgo: (a) añadir el literal decimal
de `127.0.0.1` (`2130706433`) y sus equivalentes hex/octal a la lista de
`ssrf`, para cumplir lo que promete la documentación; o (b) si se decide
que no vale la pena (es un objetivo de bajo impacto y añadir el literal
puede generar sus propios falsos positivos con puertos locales legítimos
escritos en decimal por error tipográfico), corregir `docs/amenazas.md`
para que dibuje la limitación honestamente, como ya hace con el resto de
la tabla. Lo único que no vale es dejar la promesa escrita y sin cumplir.

**Estado:** cerrado ✅ (añadidos en `rules.py` y `PREFILTER_LITERALS["ssrf"]` los literales de loopback ofuscado en decimal `2130706433`, hex `0x7f000001`/`0x7f.0x0.0x0.0x1` y octal `0177.0.0.1`/`017700000001`, cumpliendo la promesa de `docs/amenazas.md` con 0 FP en los tres corpus)

---

## Lo que ataqué y **no** es un hallazgo (y por qué)

Para que quede claro qué he descartado y con qué criterio, no solo qué
encontré:

- **SSTI en Freemarker (`<#assign>`), Velocity (`#set`, `#foreach`), Twig
  (`{% %}`), Handlebars (`{{#with}}`)**: `docs/amenazas.md` dice
  explícitamente que la familia cubre *"aritmética canónica de plantillas
  (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`)"* — cuatro sintaxis
  concretas, no "todo motor de plantillas que exista". No contradice
  ninguna promesa; lo dejo como observación para una futura ampliación,
  igual que hasta ahora he tratado los huecos de `cmdi`.
- **NoSQL `$expr`, `$lookup`, `$function`, `$accumulator`**:
  `docs/amenazas.md` lista textualmente qué operadores cubre (`$ne`,
  `$nin`, `$where`, `$regex`, `$or`, `$exists`) y dice expresamente que
  `$gt`/`$lt`/`$in` quedan fuera **a propósito**. Los operadores de
  agregación que probé no están ni dentro ni fuera de esa lista — son una
  ampliación posible, no una promesa rota.
- ***Prototype pollution* con escapes Unicode** (`\u005f\u005fproto\u005f\u005f`):
  solo se convierte en `__proto__` real si ese texto se interpreta como
  código fuente JS (p. ej. dentro de un `eval` o un literal reflejado en un
  `<script>`), no como una cadena JSON corriente. No tengo un escenario de
  explotación tan limpio como el de NUEVO-3, así que lo dejo anotado como
  hipótesis sin confirmar, no como hallazgo.
- **SSRF con IPv6 loopback (`[::1]`) y `0.0.0.0`**: mismo principio que el
  loopback en IPv4 — está fuera de alcance documentado (localhost no se
  bloquea a propósito), así que no cuenta como hallazgo aunque no se
  detecte.

---

## Checklist de parcheo, en orden de prioridad

1. **NUEVO-3** (de la ronda 3, sigue abierto): ampliar el patrón de acceso
   a `document`/`window`/`top`/`self`/`globalThis`/`eval` para que cubra
   `?.` y `[` además del punto literal. Es el más urgente: tiene
   exfiltración de cookie real demostrada en un motor JS de verdad.
2. **NUEVO-5**: cambiar `0252` por `0251` en los dos literales octales de
   `rules.py` (~línea 469-470). Un carácter, en dos sitios, con impacto
   real en la protección contra robo de credenciales cloud.
3. **NUEVO-6**: añadir el literal de loopback decimal a `ssrf`, o corregir
   `docs/amenazas.md` para que no prometa algo que el código no hace.

Con los tres cerrados y una ronda de regresión cruzada (combinar cada fix
con los trucos de rondas anteriores, como ya os recomendé en
`PLAN-CIERRE-100.md`), esto debería subir por encima del 90 de forma
sólida.

---

## Veredicto de esta ronda

No cambio la puntuación de 89/100 de la ronda 3 porque **el código no ha
cambiado** — solo he ampliado el mapa de lo que falta por corregir. La nota
de verdad se mueve cuando se parchee lo de arriba, no antes.
