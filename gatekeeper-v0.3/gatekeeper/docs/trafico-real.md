# Procedimiento: medir con tráfico real

El corpus retenido mide sobre **109 ataques y 140 peticiones legítimas**
sintéticas. Son una muestra, y su origen son técnicas conocidas, no el tráfico
que tu aplicación recibe de verdad. La única forma de saber si Gatekeeper
bloquea tráfico legítimo real es **dejarlo observar tráfico real** durante un
tiempo y mirar lo que bloquea.

Este es el procedimiento. Requiere autorización: solo se aplica a peticiones que
tu aplicación recibe de forma habitual, y solo se publican datos agregados.

!!! danger "Legal y ethical"
    - Solo sobre tráfico que **tú** sirves, con el consentimiento de quien
      tenga el derecho sobre ese tráfico.
    - **Nunca** captures peticiones de terceros que no sean usuarios tuyos, ni
      las escales a un escáner, ni las compartas.
    - Los logs de auditoría **no llevan los valores** de los payloads (solo
      la regla, el patrón y el **nombre** del campo). Ese nombre lo elige el
      atacante, así que puede acabar en el log: va saneado y acotado, pero
      trátalo como texto no confiable. Aun así, la IP y la ruta son datos
      personales: trátalos como tales y publícate solo los agregados.

## 1. Poner en modo monitor

El modo monitor registra lo que bloquearía, pero **no bloquea nada**:

```python
import logging
import sys

from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

logging.basicConfig(
    level=logging.WARNING,
    format="%(message)s",
    stream=sys.stdout,
)

app = FastAPI()

config = Config(
    rate_limit=0,            # el rate limit tambien se midió antes de activarlo
    monitor_only=True,       # registra, no bloquea
)
app.add_middleware(GatekeeperMiddleware, config=config)
```

!!! warning "`rate_limit=0` durante la observación"
    Con el rate limit activo, el tráfico que se pasa del límite recibe 429 y
    **deja de llegar a la aplicación**: no verás los falsos positivos que
    provoca. Se mide primero el rate limit, y se activa después.

## 2. Recoger los eventos

Gatekeeper escribe eventos JSON en el logger `gatekeeper`. La configuración de
logging del ejemplo anterior los manda a la salida estándar; para guardarlos en
un fichero, apunta `stream` a un `open(...)` o usa la configuración del
servidor de logs que ya tengas.

Cada evento lleva `event`, `rule`, `source`, `field`, `pattern` y `ip`:

```json
{"ts": 1750000000.0, "event": "attack_detected", "ip": "203.0.113.7",
 "method": "GET", "path": "/buscar", "rule": "sqli", "source": "query",
 "field": "q", "pattern": "\\bunion\\b\\s{1,32}(all\\s{1,32})?\\bselect\\b",
 "blocked": false}
```

El `field` es lo importante: **dónde** está el valor que disparó la regla. Sin
él no se puede ajustar nada.

!!! tip "Cuánto tiempo recoger"
    Un ciclo completo. Si tu tráfico tiene estacionalidad (fin de semana,
     cierres de mes), recoge al menos un ciclo de cada uno. Una semana es un
    mínimo razonable; un mes, si el tráfico es estacional.

## 3. Analizar el log

`gatekeeper report` convierte el log en un informe con lo que se ajustaría:

```bash
gatekeeper report trafico.log
```

El informe dice qué reglas saltan, en qué rutas y en qué campos, y propone el
ajuste (un `exclude_fields` o un `disabled_rules`).

Para procesar muchos logs a la vez, el formato JSON es para máquinas:

```bash
gatekeeper report trafico.log --json > informe.json
```

## 4. Decidir, con los datos delante

Cada par (regla, campo) que se repite es un candidato. La decisión es de
negocio, no técnica:

| Situación | Ajuste |
|---|---|
| Es tráfico legítimo y el campo es tuyo (una URL de webhook, un filtro de fecha) | `exclude_fields: ["<campo>"]` |
| Es tráfico legítimo y el campo lo rellena un usuario con texto libre | `exclude_fields` + revisar la regla |
| Es tráfico legítimo y la regla no aporta nada en tu app | `disabled_rules: ["<familia>"]` |
| Es un ataque de verdad | **no se toca nada** |

!!! danger "No ajustes sobre la suposición"
    Un `exclude_fields` es una excepción permanente en el escaneo. Añadir uno
    "por si acaso" abre un hueco que nadie va a volver a mirar. Cada exclusión
    tiene que estar justificada por un caso concreto que hayas visto.

## 5. Medir el cambio

Después de ajustar, repite:

```bash
python tools/evaluate.py --check
python tools/evaluate_heldout.py --check
```

Y vuelve a observar en modo monitor un rato: el falso positivo que ajustaste
tiene que haber desaparecido, y **no puede haber aparecido otro**.

## 6. Activar el bloqueo

Cuando los falsos positivos reales estén a cero (o aceptados y documentados):

```python
config = Config(
    rate_limit=<tu límite>,
    monitor_only=False,
)
```

Y **deja el rollback escrito antes de activar**:

| Problema | Qué hacer |
|---|---|
| Falso positivo en un campo concreto | `exclude_fields` |
| Falsos positivos de una familia entera | `disabled_rules` |
| Bloqueo masivo, sin tiempo de analizar | `monitor_only=True` |

Los cuatro son cambios de configuración: no requieren desplegar código, y
`monitor_only` es reversible al instante.

## Qué se publica

Al terminar, lo publicable es **agregado**, nunca el log:

- qué reglas saltaron y cuántas veces,
- qué campos se ajustaron y por qué,
- el tiempo de observación y el volumen de tráfico.

El log en crudo (con IPs y rutas) **no se publica**: es dato de terceros.

!!! note "Esto no cambia las cifras del corpus"
    El corpus retenido y el de desarrollo miden sobre casos sintéticos. El
    tráfico real **no cambia esas cifras**: da contexto sobre falsos positivos
    que las firmas tienen en un contexto concreto, y sirve para decidir los
    ajustes de la configuración de cada despliegue.

    Las cifras del README siguen siendo las del corpus, y el corpus no se
    reescribe con tráfico real: un corpus tiene que ser estable para que sus
    cifras signifiquen algo.
