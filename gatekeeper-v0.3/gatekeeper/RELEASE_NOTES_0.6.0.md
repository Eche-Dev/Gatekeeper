# Gatekeeper 0.6.0

## Qué es

Convierte a Gatekeeper en algo que **no se puede usar para agotar tus
recursos** y en algo que **no deja que el atacante se meta en tu terminal**.

La Fase 2 cierra cinco cosas, todas medidas:

| Problema | Antes | Ahora |
|---|---:|---:|
| RAM del rate limiter con 200.000 IPs distintas | 174,9 MB | **9,4 MB** |
| CPU por petición con 26.000 campos | 1,34 s | **0,003 s** (413) |
| IPv6 rotando dentro del mismo /64 | Ilimitado | **1 cubo** |
| Regex propia catastrófica (`(a+)+$`) | Colgaba el proceso | **Rechazada al arrancar** |
| ESC en la ruta → terminal del operador | Se ejecutaba | **0 bytes ESC** |

## Qué cambia

### 1 · El rate limiter ya no crece sin límite

El backend en memoria guardaba un `deque` por cada IP distinta, sin tope.
Medido: **200.000 IPs costaban 174,9 MB** de RAM (875 B por clave), y la poda
era O(n) en cada limpieza.

Ahora la tabla está acotada (`rate_max_keys`, 10.000 por defecto) y al llegar
al tope sale la clave **menos usada** (LRU). Con el tope, esas mismas
200.000 IPs ocupan **9,4 MB** y la inserción es O(1).

```python
Config(rate_max_keys=50_000)   # si atiendes a más clientes distintos
```

Con Redis no hay tope en el middleware: las claves caducan a los
`rate_window` segundos. La protección es de Redis (`maxmemory` +
`maxmemory-policy`).

### 2 · La IPv6 se cuenta por prefijo, y `::ffff:` es la misma IP

Un /64 es el prefijo delegable más pequeño (RFC 6177): quien tiene un /64
puede rotar 2^64 direcciones sin que el contador se entere. Ahora las
direcciones del mismo prefijo cuentan juntas (`rate_ipv6_prefix`, /64 por
defecto; 128 = sin agrupar).

Y `::ffff:1.2.3.4` y `1.2.3.4` son **el mismo cubo**: antes llevaban dos
contadores, y el límite se podía eludir solo alternando la forma.

```python
Config(rate_ipv6_prefix=128)   # sin agrupar (no recomendado)
```

### 3 · `blocked_ips` con una entrada IPv4-mapped ya no es un no-op

`blocked_ips={"::ffff:127.0.0.1"}` (o `{"::ffff:0:0/96"}`) se aceptaba al
arrancar y **no bloqueaba nada**: la IP entrante se normaliza a IPv4 y se
comparaba contra una red IPv6, que nunca coincide. Una protección que no
protege. Ahora esas entradas se traducen a su equivalente IPv4 y bloquean las
dos formas.

### 4 · Presupuesto de campos y de tiempo de inspección

El límite de tamaño del body **no acotaba el trabajo de inspección**: el
coste escala con el número de **campos** (~67 µs por campo), no con los
bytes. Medido: 20.000 campos costaban **1,34 s** de CPU en una sola
petición, y un body de muchos campos es pequeño.

- `max_fields` (1000 textos inspeccionados: una clave y su valor cuentan
  como dos). Al superarlo: **413** y evento `too_many_fields`.
- `max_inspection_ms` (1000 ms). Al superarlo: **413** y evento
  `inspection_timeout`.

Los campos que sobran **no se ignoran**: ignorarlos sería un bypass, porque
el atacante mandaría el payload en el campo que se queda sin inspeccionar.
Igual con el presupuesto de tiempo: si la petición pasara al agotarlo, el
atacante podría gastarlo a propósito para que su payload quedara sin
inspeccionar. Por eso no hay modo "fail-open".

```python
Config(max_fields=5000, max_inspection_ms=0)   # 0 = sin límite de tiempo
```

### 5 · `max_body_size` baja a 256 KiB

```python
Config(max_body_size=1_048_576)   # vuelve a 1 MiB
```

### 6 · Las reglas propias se validan al arrancar

`custom_rules` se compilaba tal cual: `(a+)+$` sobre 60 caracteres no
terminaba en 20 segundos. Eso es un DoS en el propio WAF, y no hace falta
adversario: basta con que la regla reciba una entrada adversa.

Ahora el patrón se analiza **de forma estática** (sin ejecutarlo: medirlo
exigiría un timeout, y en Python no hay forma de interrumpir un regex en
marcha, así que la propia medición sería el DoS), con dos niveles:

- **Exponencial** → `ValueError` al arrancar: cuantificadores anidados sin
  nada obligatorio detrás (`(a+)+`), alternativas que se solapan en un grupo
  repetido (`(a|a)+`, `(a|ab)+`) y referencias atrás repetidas.
- **Cuadrático** → aviso en el log, la app arranca: cuantificadores anidados
  con separador detrás (`(?:\w+\.)+\w+`). No cuelga con una entrada corta,
  pero se degrada con el tamaño (medido: 7,4 s con 50.000 caracteres). Son
  patrones legítimos, así que no se rechazan.

```python
Config(allow_unsafe_custom_rules=True)   # acepta el riesgo exponencial (y avisa)
```

### 7 · La salida va saneada

Lo que el CLI imprime lo elige el atacante (el nombre de un campo, la ruta):
un `\x1b[2J` en la URL podía borrar la pantalla del operador o reescribir el
título de su ventana. En el formato JSON, `json.loads` convertía el `\u001b`
del archivo en un ESC real.

Ahora todo el texto que se imprime **y** todo el que se registra va saneado
(sin ESC ni otros caracteres de control; el ESC se marca como `\e`) y
acotado a 256 caracteres.

### 8 · El puntero JSON a 64 niveles ya no pierde el campo

Al llegar al límite de profundidad se marcaba el corte y se devolvía la ruta
del **padre**: la atribución apuntaba al campo equivocado y `exclude_fields`
(compara por el último segmento) no casaba con el campo real, de modo que un
campo exento a 64 niveles seguía bloqueándose. Ahora el puntero conserva la
clave exterior, marca el corte y acaba en el campo que saltó.

### 9 · Dos SQLi estaban en la familia equivocada

`union all` y `or '…` vivían en `sensitive_files`, así que
`disabled_rules=["sqli"]` **no los apagaba**: `union all select 1` se seguía
detectando y se reportaba como `sensitive_files`. Ahora están en `sqli`.

## Migración desde 0.5.0

**Sin cambios en la API pública**: no hay deprecaciones ni renombrados, y las
reglas nuevas son opt-in por su valor por defecto.

**Los cambios de comportamiento que sí pueden afectar:**

1. **`max_body_size` baja de 1 MiB a 256 KiB.** Un body mayor recibe un
   **413** donde antes pasaba. Si tu app acepta bodies grandes:

   ```python
   Config(max_body_size=1_048_576)   # o lo que necesites
   ```

2. **Presupuesto de campos (1000 textos).** Una petición con más campos de
   los permitidos recibe un **413** y se audita `too_many_fields`. Una clave
   y su valor cuentan como dos, así que el límite son ~500 campos JSON.

3. **Presupuesto de tiempo (1 s).** Una petición cuya inspección pase de 1 s
   recibe un **413** y se audita `inspection_timeout`. Con `max_fields` por
   defecto, el peor caso legítimo es ~100 ms en una máquina normal.

4. **Las reglas propias se validan al arrancar.** Si tienes una regex con
   cuantificadores anidados o alternativas solapadas, Gatekeeper **no
   arranca** hasta que la reescribas (o pongas `allow_unsafe_custom_rules=True`).

5. **El log va saneado y acotado.** Si tenías un pipeline que esperaba los
   caracteres de control en el log, ya no están. Y el nombre del campo va
   acotado a 256 caracteres.

```bash
pip install --upgrade gatekeeper-asgi
```

## La promesa del log, dicha con precisión

Antes la documentación decía que "nunca se registra el contenido del
payload". Eso era **falso**: el **nombre** de un campo lo elige el atacante,
así que un parámetro cuyo nombre es el payload entero llegaba entero al log.

Lo que se garantiza, y ahora se dice con precisión en `SECURITY.md`,
`docs/`, el README y `corpus/events.json`:

- Los **valores** nunca se registran: ni el cuerpo, ni la query, ni los
  valores de las cabeceras.
- El **nombre** del campo que saltó sí se registra (sin él no se puede
  atribuir un falso positivo). Va **saneado** y **acotado**.

El log es texto no confiable, no un depósito de credenciales interceptadas.

## Detección: sin cambios

Verificado con los tres corpus, antes y después:

| Corpus | Detección | Falsos positivos |
|---|---:|---:|
| Propio | 159/159 (100 %) | 0 no documentados |
| Retenido (held-out) | 103/109 (94,5 %) | 0 no documentados |
| OWASP CRS (alcance evaluado) | 465/1.135 (41,0 %) | 11/232 (4,7 %, documentados) |
| Modo cruzado | 7/7 | 0 |

**Ninguna regla nueva.** Lo que se ha movido son los SQLi de la ruta a su
familia, y el corpus no se mueve.

## Qué NO cubre

- El **contenido** de los ficheros adjuntos (sí los nombres).
- Los **frames** de un WebSocket (sí el handshake).
- Binarios que no son JSON (imagen, PDF, zip…).
- El tráfico entre query y body si `inspect_cross_carrier=False`.
- Autenticación, autorización y consultas parametrizadas: eso va en tu app.
- El regex **dentro** de un mismo texto (un `timeout` de Python no puede
  interrumpir un regex que ya está corriendo): lo que se controla es el
  **número de campos**, no el coste de una única evaluación.

## Compatibilidad

Sin cambios: Python 3.10–3.14, Starlette 0.23.0–1.10.0, FastAPI
0.103.2–0.162.0, uvicorn/hypercorn/daphne y Redis 5.0/7.2. La matriz completa
y **medida** está en [docs/compatibilidad.md](docs/compatibilidad.md).

## Instalación

```bash
pip install gatekeeper-asgi          # núcleo
pip install "gatekeeper-asgi[yaml]"   # + configuracion desde YAML
pip install "gatekeeper-asgi[redis]"  # + rate limit distribuido
```

## Reportar un problema

- **Vulnerabilidades**: [GitHub Security Advisories](https://github.com/Eche-Dev/Gatekeeper/security/advisories/new).
  No abras un issue público con un fallo explotable.
- **Errores que no son vulnerabilidades**: issue en GitHub.

El DoS de disponibilidad de la 0.4.0 (corregido en la 0.4.1) está en
[SECURITY.md](SECURITY.md), en la sección «Vulnerabilidades corregidas».
