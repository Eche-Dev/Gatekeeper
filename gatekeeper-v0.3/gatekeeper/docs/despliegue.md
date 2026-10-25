# Despliegue

Cómo configurar Gatekeeper según **la topología real** en la que va a vivir.
Cada sección dice qué valores cambian y por qué.

!!! tip "La regla que resume todo"
    La única decisión que **no** es opcional según la topología es el backend de
    rate limit: en memoria cada proceso cuenta lo suyo. Todo lo demás tiene un
    valor por defecto que funciona.

## Un solo proceso

El caso por defecto. `uvicorn app:app` con un worker, o un contenedor con una
réplica.

```python
config=Config(rate_limit=100, rate_window=60)
```

El backend en memoria es correcto y es lo más rápido: no hay red de por medio.
El límite se aplica **por proceso**, así que con una sola instancia el número
que ves en la config es el número real.

!!! note "Cuándo dejar de usar memoria"
    En cuanto tengas **más de una instancia** (varios workers, varias réplicas
    de Kubernetes, dos contenedores), el límite efectivo se multiplica.
    4 workers con `rate_limit=100` admiten ~400/min. Saltando a
    [varios workers](#varios-workers).

!!! note "La memoria del backend en memoria está acotada"
    El backend en memoria recuerda como mucho `rate_max_keys` IPs distintas
    (10.000 por defecto). Al llegar al tope sale la menos usada, de modo que
    una inundación de IPs inventadas no puede hacer crecer el proceso sin
    límite. Antes de esa protección, 300.000 IPs distintas costaban ~245 MB
    de RAM. Si atiendes a más de 10.000 clientes simultáneos, sube el valor
    (o pasa a Redis).

## Varios workers

Con varios workers en la misma máquina (gunicorn, `uvicorn --workers 4`), cada
proceso tiene su propio contador en memoria. **El límite se multiplica por el
número de workers.**

Para un límite global, el contador tiene que estar fuera del proceso:

```python
config=Config(
    rate_limit=100,
    rate_window=60,
    rate_backend="redis",
    redis_url="redis://localhost:6379/0",
)
```

Necesitas el extra:

```bash
pip install "gatekeeper-asgi[redis]"
```

La ventana deslizante se actualiza con un **script Lua atómico**: dos workers que
lleguen a la vez no pueden colarse por encima del límite (un pipeline de varios
comandos sí lo permitiría). El cliente es `redis.asyncio`, así que no bloquea el
event loop.

!!! info "Hace falta Redis 5.0 o superior"
    Gatekeeper fuerza el protocolo **RESP2** al conectar. El cliente `redis-py`
    moderno (8.x) hace handshake RESP3 por defecto, y un Redis 5.x o 6.0 no lo
    entiende: falla con `unknown command HELLO` en la primera petición. Con
    RESP2 forzado, Gatekeeper habla con cualquier Redis ≥ 5.0. Probado contra
    Redis 5.0 y 7.2.

    La ventana deslizante solo usa `EVAL`, `ZADD` y `ZRANGE`: RESP3 no le
    aporta nada, así que no se pierde ninguna función.

!!! warning "Redis es una dependencia crítica"
    Con `rate_backend="redis"`, si Redis no responde el middleware **no puede
    contar**. Decide tú qué pasa con `rate_fail_open`:

    | `rate_fail_open` | Comportamiento | Cuándo |
    |---|---|---|
    | `True` (defecto) | Se admite la petición y se audita `rl_backend_unavailable` | Si la disponibilidad importa más que el límite exacto |
    | `False` | `503` con `{"detail": "rate_limit_backend_unavailable"}` | Si el límite es un requisito de seguridad, no un extra |

    En ambos casos el fallo queda en la auditoría: Redis no puede caerse en
    silencio. Para un servicio público, `True` con alertas configuradas suele
    ser la elección menos mala; para un panel de administración o un endpoint
    con coste por petición, `False`.

!!! success "La garantía del límite global, verificada"
    Con Redis, el límite es **global**, no por worker. Está comprobado contra
    un Redis real en CI (`tests/test_redis_real.py`):

    - 50 workers distintos contra la misma IP: se admiten exactamente 10 con
      `rate_limit=10`. Ni uno se cuela.
    - El contador **sobrevive a un reinicio** del proceso: está en Redis, no en
      la memoria del worker. Con el backend en memoria, un reinicio pondría el
      contador a cero y el límite se podría evadir reiniciando.
    - Dos IPs distintas tienen contadores separados.

!!! note "Con Redis, el tope de claves no es del middleware"
    En Redis, cada IP es una clave que caduca a los `rate_window` segundos, así
    que la memoria no crece sin límite en el tiempo; pero sí crece con el
    número de IPs distintas de una ventana. Si eso es un problema en tu
    despliegue, la protección es del lado de Redis (`maxmemory` +
    `maxmemory-policy`), no del middleware. Lo que sí hace Gatekeeper es
    agrupar las IPv6 por /64 al contar, que es donde se concentran las
    rotaciones.

### Varias réplicas de Kubernetes

Igual que varios workers: **Redis es obligatorio** para que el límite sea
global. Cada pod es un proceso distinto con su propia memoria.

Si tu despliegue tiene más de una réplica, la configuración de memoria es un
error silencioso: la protección parece estar y no lo está.

## Docker

El middleware es ASGI puro: funciona igual en un contenedor.

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir "gatekeeper-asgi[redis]"

COPY app.py .
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

Lo que cambia respecto a un despliegue sin contenedor:

- **Un contenedor, un worker**: el backend en memoria vale, porque el contenedor
  es el proceso. Si lanzas varios workers **dentro** del contenedor, o varias
  réplicas del contenedor, necesitas Redis.
- **El health check** no debería pasar por las rutas inspeccionadas. Usa
  `allow_paths=["/health"]` para que el probe no consuma rate limit ni pueda
  ser bloqueado por un falso positivo.

```python
config=Config(rate_limit=100, rate_window=60, allow_paths=["/health"])
```

!!! warning "El rate limit también aplica a las rutas exentas"
    `allow_paths` exime de **inspección**, no de rate limit. Si quieres que el
    health check tampoco cuente, sube `rate_limit` o quítalo del camino del
    probe.

El [`demo/Dockerfile`](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/demo/Dockerfile)
del repositorio es un ejemplo ejecutable.

## Detrás de un proxy inverso

nginx, Traefik, un load balancer de nube, un CDN… **La parte importante**: con un
proxy delante, la conexión TCP la abre el proxy, no el cliente. Gatekeeper ve
la IP del proxy. Sin configurar nada, todas las peticiones cuentan como si
fueran del mismo cliente: el rate limit deja de distinguir usuarios y un
`blocked_ips` deja de bloquear a nadie útil.

Por eso `trust_proxy` viene **desactivado** por defecto: activarlo sin un proxy
real delante es trusting en el cliente, y el cliente controla esa cabecera.

### Configuración mínima

```python
config=Config(
    rate_limit=100,
    rate_window=60,
    trust_proxy=True,
    trusted_proxies=1,          # cuántos proxies TUYOS hay en la cadena
    trusted_proxy_cidrs={"10.0.0.0/8"},  # desde qué redes te llegan
)
```

Y en el proxy, la IP real tiene que viajar en `X-Forwarded-For`:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
}
```

### Por qué `X-Forwarded-For` se lee de derecha a izquierda

La primera entrada de la cabecera la escribe **el cliente**, y es la que puede
manipular. Cada proxy tuyo **añade** una entrada al final. Por eso Gatekeeper
lee `ips[-trusted_proxies]`: el cliente real es el que está a la distancia
exacta de tus proxies.

```
X-Forwarded-For: <IP que pone el cliente>, <IP real>
                 └──────── manipulado ────────┘  └─ la añade tu proxy ─┘
```

Con `trusted_proxies=1`, Gatekeeper toma la **última** entrada: la que escribe
tu proxy, no el cliente.

!!! danger "Activar `trust_proxy` sin proxy delante es abrir una puerta"
    Si la app es accesible directamente (no solo por el proxy) y activas
    `trust_proxy`, cualquiera puede mandar `X-Forwarded-For: 1.2.3.4` y:
    - saltarse el rate limit (rotando la cabecera), y
    - esquivar `blocked_ips`.

    Por eso existe `trusted_proxy_cidrs`: si lo configuras, Gatekeeper **solo**
    cree el XFF cuando el peer TCP pertenece a esas redes. Si alguien llega
    saltándose el proxy, el peer no está en la lista y el XFF se ignora por
    completo.

    ```python
    # Correcto: solo se cree el XFF si el peer es de la red de proxies.
    config=Config(trust_proxy=True, trusted_proxies=1, trusted_proxy_cidrs={"10.0.0.0/8"})

    # Riesgoso: la app es accesible también sin proxy.
    config=Config(trust_proxy=True, trusted_proxies=1)
    ```

### Cuántos proxies hay en tu cadena

`trusted_proxies` es el número de proxies **tuyos** (los que reescriben la
cabecera), no el número de saltos de red.

| Topología | `trusted_proxies` |
|---|---|
| nginx → app | `1` |
| CDN → nginx → app (nginx reescribe) | `1` |
| CDN → app (el CDN añade su IP al final) | `1` |
| nginx → nginx → app | `2` |

Si la cadena es inconsistente (faltan entradas porque alguien saltó el proxy),
Gatekeeper **no adivina**: usa el peer y sigue siendo conservador.

## Matriz de decisión

| Situación | `rate_backend` | `trust_proxy` | `trusted_proxy_cidrs` |
|---|---|---|---|
| Un proceso, sin proxy | `memory` | `False` | — |
| Varios workers | `redis` | `False` | — |
| Varias réplicas | `redis` | `False` | — |
| Detrás de nginx | `redis` si hay varios workers | `True` | Recomendado |
| Directo a internet, sin proxy | `redis` si hay varios workers | **`False`** | — |

## Lo que **no** cambia

- **El body se inspecciona siempre**, sin importar la topología. El límite de
  1 MiB (`max_body_size`) también.
- **Las cabeceras de seguridad** se añaden siempre.
- **La auditoría** va al logger `gatekeeper` en todos los casos. Si recoges
  logs centralizados (Loki, ELK, CloudWatch), los eventos JSON se pueden
  filtrar por `event` y por `rule` para alertar.

## Checklist antes de activar en producción

1. **¿Cuántas instancias tienes?** Si es más de una, `rate_backend="redis"`.
2. **¿Hay un proxy delante?** Si lo hay, `trust_proxy=True` **y**
   `trusted_proxy_cidrs` con sus redes.
3. **¿El rate limit es global o por instancia?** Con Redis es global.
4. **¿Has visto los falsos positivos?** Arranca con `monitor_only=True` y
   revisa los eventos antes de bloquear.
5. **¿Tu health check pasa por una ruta exenta?** `allow_paths=["/health"]`.

## Reversión

Si algo bloquea tráfico legítimo, el orden menos invasivo primero:

1. `monitor_only=True` → deja de bloquear, sigue registrando.
2. `exclude_fields=[...]` → exime el campo concreto que dispara la regla.
3. `disabled_rules={"sqli"}` → apaga la familia entera.
4. `allow_paths=[...]` → exime la ruta.

Los cuatro son cambios de configuración: no hace falta desplegar código, y
`monitor_only` es reversible al instante.

---

Siguiente: [Modelo de amenazas →](amenazas.md)
