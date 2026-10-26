# Inicio rápido

Esta página es para quien tiene Gatekeeper delante de una aplicación y quiere
**verlo funcionando en cinco minutos**, sin leer la documentación entera.

!!! info "Publicado en PyPI"
    Gatekeeper se instala desde PyPI: `pip install gatekeeper-asgi`. La 0.4.0
    tiene un DoS de disponibilidad corregido en la **0.4.1**: actualiza a
    `0.4.1` o superior. Ver [Instalación](instalacion.md).

## 1. Instalar

```bash
pip install --upgrade "gatekeeper-asgi>=0.4.1"
```

Comprueba que está:

```bash
python -c "import gatekeeper; print(gatekeeper.__version__)"
```

## 2. Añadir el middleware

Crea `app.py`:

```python
from fastapi import FastAPI
from gatekeeper import Config, GatekeeperMiddleware

app = FastAPI()


@app.get("/saludo")
async def saludo() -> dict[str, str]:
    return {"mensaje": "hola"}


app.add_middleware(
    GatekeeperMiddleware,
    config=Config(rate_limit=100, rate_window=60),
)
```

Y arráncalo:

```bash
uvicorn app:app --port 8000
```

## 3. Comprobar que funciona

!!! success "Los dos comandos de abajo son la prueba"
    Una petición normal debe responder **200**. Un ataque debe recibir **403**.
    Si el ataque devuelve 200, Gatekeeper **no está protegiendo** esa ruta:
    revisa que el middleware esté añadido.

**Petición permitida (debe responder 200):**

```bash
curl -i "http://localhost:8000/saludo"
```

**Petición bloqueada (debe responder 403):**

```bash
curl -i "http://localhost:8000/saludo?q=1%20UNION%20SELECT%20password%20FROM%20users"
```

!!! tip "Si el ataque devuelve 200"
    - ¿Añadiste el middleware **antes** de que la app empiece a servir?
      `add_middleware` tiene que ir en el módulo, antes de arrancar el servidor.
    - ¿La ruta está en `allow_paths`? Las rutas exentas no se inspeccionan
      (pero sí siguen sujetas a rate limit).
    - ¿La query está en `exclude_fields`? Los campos exentos se quitan del
      objetivo antes de escanear.

**Con cuerpo (también debe dar 403):**

```bash
curl -i -X POST "http://localhost:8000/saludo" \
  -H "Content-Type: application/json" \
  -d '{"nombre": "'\'' OR '\''1'\''='\''1'\''"}'
```

## 4. Ver la auditoría

Gatekeeper escribe eventos JSON en el logger `gatekeeper`. En la terminal donde
corres uvicorn verás, al bloquear:

```json
{"ts": 1750000000.0, "event": "attack_detected", "ip": "127.0.0.1", "method": "GET", "path": "/saludo", "rule": "sqli", "source": "query", "field": "q", "pattern": "\\bunion\\b\\s{1,32}(all\\s{1,32})?\\bselect\\b", "blocked": true}
```

El campo `pattern` dice **qué regla saltó**, para que puedas ajustar sin
adivinar. Los **valores** del payload no se escriben nunca en el log; el
**nombre** del campo (`field`) sí, porque es lo que permite atribuir el
falso positivo. Ese nombre lo elige el atacante, así que va saneado (sin
caracteres de control) y acotado: trátalo como texto no confiable.

!!! warning "Primero observa, luego bloquea"
    Si no sabes todavía qué falsos positivos te va a dar tu tráfico, arranca en
    modo monitor: registra los bloqueos pero **no rechaza nada**.

    ```python
    config=Config(rate_limit=100, rate_window=60, monitor_only=True)
    ```

    Revisa los eventos, ajusta `exclude_fields` o `disabled_rules`, y solo
    entonces quita `monitor_only`.

## 5. Lo siguiente

Ya tienes Gatekeeper delante de la app. Ahora decide la configuración de tu
despliegue:

| Si tu despliegue es… | Lee |
|---|---|
| Un solo proceso | [Despliegue](despliegue.md#un-solo-proceso) |
| Varios workers (gunicorn, uvicorn --workers) | [Despliegue](despliegue.md#varios-workers) |
| Docker o Kubernetes | [Despliegue](despliegue.md#docker) |
| Detrás de nginx / Traefik / un LB | [Despliegue](despliegue.md#detras-de-un-proxy-inverso) |
| Todavía no lo sé | [Despliegue](despliegue.md) desde el principio |

Y para entender qué se inspecta y qué no (y por qué), [Modelo de amenazas](amenazas.md).

---

Siguiente: [Despliegue →](despliegue.md)
