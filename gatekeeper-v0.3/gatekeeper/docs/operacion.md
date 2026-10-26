# Guía operativa

Cómo operar Gatekeeper en producción: qué observar, qué alertar, cómo desplegar
sin surprises y cómo volver atrás si algo va mal.

## Qué se registra

Gatekeeper emite eventos JSON en el logger `gatekeeper`. El catálogo completo
está en [`corpus/events.json`](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/events.json)
y hay un test que comprueba que el catálogo y el código no se desincronizan.

| Evento | Qué significa | Respuesta |
|---|---|---|
| `attack_detected` | Una firma de ataque saltó | 403 (o 200 en modo monitor) |
| `rate_limited` | La IP pasó del límite | 429 con `Retry-After` |
| `blocked_ip` | La IP está en `blocked_ips` | 403 |
| `body_too_large` | El body pasó de `max_body_size` | 413 |
| `too_many_fields` | La petición pasó de `max_fields` | 413 |
| `inspection_timeout` | La inspección pasó de `max_inspection_ms` | 413 |
| `rate_backend_error` | El backend de rate limit no responde | 503 o la petición pasa |

Cada evento lleva `ts`, `event`, `ip`, `method` y `path`, más los campos
propios de su tipo (`rule`, `source`, `field`, `pattern` en los ataques).

!!! danger "El log lleva datos personales"
    La **IP** y la **ruta** son datos personales. El log en crudo **no se
    publica** y no se envía a terceros sin mirar. Lo publicable son los
    agregados (cuántas veces saltó cada regla, en qué campos, qué ajustes se
    hicieron).

    Lo que **nunca** se registra: el payload, el cuerpo, los valores de las
    cabeceras, cookies o tokens. Solo el *nombre* de la cabecera que saltó.

## Métricas

`tools/metrics.py` convierte el log en una exposición Prometheus:

```bash
python tools/metrics.py trafico.log
```

```
# HELP gatekeeper_attacks_total Ataques detectados por familia y transportador.
# TYPE gatekeeper_attacks_total counter
gatekeeper_attacks_total{rule="sqli",source="query"} 2
gatekeeper_attacks_total{rule="xss",source="body"} 1
gatekeeper_rate_limited_total 2
gatekeeper_blocked_ips_total 1
gatekeeper_body_too_large_total 1
gatekeeper_rate_backend_errors_total{fail_open="true"} 1
```

Para exponerlas en vivo:

```bash
python tools/metrics.py trafico.log --port 9090
# http://127.0.0.1:9090/metrics
```

!!! tip "Lo que hay que alertar"
    - **`rate_backend_errors_total`**: el backend no responde. Con
      `rate_fail_open=True` el tráfico sigue pasando **sin rate limit**: no es
      un incidente de disponibilidad, es un hueco de seguridad silencioso.
      Es la alerta más importante.
    - **Un salto puntual de `rate_limited_total`**: puede ser un ataque de
      volumetría o un límite mal puesto.
    - **`body_too_large_total` sostenida**: casi siempre es un cliente que
      manda bodies enormes, no un ataque.
    - **Un `rule` nuevo con muchos eventos**: suele ser un falso positivo
      sobre tráfico legítimo. Es lo que te dice qué ajustar.

## Despliegue gradual

El orden menos riesgoso primero. Cada paso es reversible sin desplegar código.

### Paso 0 — Sin proteccion, pero Midiendo

```python
config = Config(
    rate_limit=0,            # todavia no
    monitor_only=True,       # registra, no bloquea
)
```

Todo el tráfico pasa y se registra lo que se bloquearía. Es el único momento
en el que se pueden ver los falsos positivos sin coste.

Cuánto tiempo: un ciclo completo de tráfico (si hay estacionalidad, un ciclo
de cada tipo). Una semana es un mínimo; un mes, si el tráfico varía.

### Paso 1 — Bloquear ataques, sin tocar el rate limit

```python
config = Config(
    rate_limit=0,
    monitor_only=False,      # ya bloquea
)
```

Las firmas de ataque se bloquean (403). El rate limit sigue apagado, porque es
el que puede dar falsos positivos con más facilidad (un límite mal calculado
es un 429 para un usuario legítimo).

### Paso 2 — Activar el rate limit

```python
config = Config(
    rate_limit=<tu límite>,
    rate_window=60,
)
```

!!! warning "Calcula el limite con el traffic real, no con una intuicion"
    Con el backend en memoria, el límite es **por proceso**. Con 4 workers,
    `rate_limit=100` admite ~400/min. Si hay varias réplicas, el límite
    efectivo se multiplica por el número de instancias: para un límite global,
    Redis (ver [Despliegue](despliegue.md)).

### Paso 3 — Considerar el modo combinado

```python
config=Config(inspect_cross_carrier=True)
```

Detecta firmas partidas entre la query y el body. **Opt-in** porque combinar
contextos puede aumentar los falsos positivos. Mídelo en monitor primero: la
[guía de tráfico real](trafico-real.md) explica cómo.

## Rollback

Ante un bloqueo masivo, el orden de menos a más invasivo:

| Síntoma | Qué cambiar | Efecto |
|---|---|---|
| Falsos positivos en un campo concreto | `exclude_fields=["campo"]` | Ese campo deja de escanearse |
| Falsos positivos de una familia entera | `disabled_rules=["sqli"]` | Esa familia se apaga |
| Bloqueo masivo, sin tiempo de analizar | `monitor_only=True` | Deja de bloquear, sigue registrando |
| Rate limit equivocando | `rate_limit=0` | Se apaga el rate limit |
| Todo lo anterior insuficiente | Quitar el middleware | La app vuelve a su estado anterior |

!!! danger "monitor_only=True no es un plan de rollback"
    Con el modo monitor, el tráfico pasa pero **tampoco se bloquea**. Si lo
    que se estaba frenando era un ataque real, volver a dejarlo pasar es
    asumir el riesgo a sabiendas. Es una medida para volver a la normalidad
    mientras se investiga, no una solución.

Los cuatro primeros cambios son **de configuración**: no requieren desplegar
código, y en un despliegue con variables de entorno se pueden aplicar sin
reconstruir imagen.

!!! note "El rollback y la observacion van juntos"
    Si no estás mirando las métricas, no sabrás cuándo has vuelto a la
    normalidad ni si el problema ha vuelto. Por eso las alertas del apartado
    anterior son parte del procedimiento, no un extra.

## Límites operativos

| Límite | Defecto | Qué pasa |
|---|---|---|
| Tamaño de body | 256 KiB (`max_body_size`) | 413. El corte es por bytes acumulados, tanto con `Content-Length` como leyendo el stream |
| Número de campos | 1000 textos (`max_fields`) | 413. El coste de inspeccionar escala con los campos (~67 µs por campo), no con los bytes |
| Tiempo de inspección | 1000 ms (`max_inspection_ms`) | 413. Red de seguridad para lo que no se puede prever por estructura |
| Memoria por petición | ~2× el tamaño del body | Acotado por `max_body_size`. Un body que excede el límite se corta sin acumularlo |
| Velocidad de escaneo | ~200-400 µs por petición | Medido en local; ver el README del paquete. No es un SLA |
| Inspeccionado | Ruta, query, headers configurados, body textual | `multipart` y los binarios **no** se inspeccionan |

!!! note "Sobre la latencia"
    Las cifras del README son medidas locales, no de producción. Mide en tu
    máquina con `python benchmarks/latency.py` antes de prometer nada.

## Topologías comprobadas

Gatekeeper es ASGI puro. Se ha probado con estos servidores, levantados como
procesos reales y con peticiones HTTP de verdad
(`tests/test_servidores_asgi.py`):

| Servidor | Probado en CI |
|---|---|
| uvicorn | Sí |
| hypercorn | Sí |
| daphne | Sí |

!!! note "Daphne y el 413"
    Daphne espera a que llegue el body declarado antes de pasar la petición a
    la aplicación. Por eso el 413 por `Content-Length` sin enviar el body no
    se puede comprobar con daphne (sí con uvicorn e hypercorn, y con el
    stream leído en todos). Es un comportamiento de daphne, no de Gatekeeper.

!!! note "hypercorn y daphne viven en el extra `servers`"
    No están en el extra `dev` a propósito: daphne arrastra Twisted, cuya
    versión estable tiene avisos de seguridad con parche solo en una release
    candidate. El runtime de Gatekeeper no depende de ellos, así que no
    arrastra ese riesgo. El job de auditoría de CI audita `dev` (limpio) y
    informa del `servers` sin bloquear el pipeline.

---

Siguiente: [Seguridad →](seguridad.md)
