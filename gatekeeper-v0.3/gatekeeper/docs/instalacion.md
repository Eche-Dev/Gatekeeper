# Instalación

!!! tip "¿Solo quieres verlo funcionar?"
    Si tu objetivo es comprobar que Gatekeeper bloquea lo que debe en cinco
    minutos, empieza por la [guía de inicio rápido](inicio-rapido.md): instala,
    añade el middleware y lanza los dos comandos que verifican que un ataque
    recibe 403.

## Desde PyPI

```bash
pip install gatekeeper-asgi             # núcleo
pip install "gatekeeper-asgi[yaml]"     # + configuración por YAML
pip install "gatekeeper-asgi[redis]"    # + rate limit compartido entre workers
```

La versión publicada es la **0.4.x** (la carpeta del repositorio se llama
`v0.3` por razones históricas). El paquete se publica con *Trusted Publishing*
y lleva **provenance verificado** por GitHub: en la ficha de PyPI verás que
todos los ficheros se subieron con metadatos de provenance firmados.

!!! warning "0.4.0 tiene un DoS de disponibilidad corregido en 0.4.1"
    La 0.4.0 bloqueaba el event loop con una petición grande y sin
    autenticación. **Actualiza a 0.4.1 o superior.** Detalle y PoC en
    [Seguridad](seguridad.md) y en
    [SECURITY.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/SECURITY.md).

## Desde el repositorio

=== "pip"

    ```bash
    git clone https://github.com/Eche-Dev/Gatekeeper.git
    pip install ./Gatekeeper/gatekeeper-v0.3/gatekeeper
    ```

=== "desarrollo"

    ```bash
    git clone https://github.com/Eche-Dev/Gatekeeper.git
    cd Gatekeeper/gatekeeper-v0.3/gatekeeper
    pip install -e ".[dev]"
    ```

## Extras

| Extra | Instala | Cuándo |
|---|---|---|
| `gatekeeper-asgi[yaml]` | PyYAML | Quieres `Config.from_yaml("gatekeeper.yaml")` |
| `gatekeeper-asgi[redis]` | redis | Rate limit compartido entre workers |
| `gatekeeper-asgi[dev]` | herramientas de desarrollo | Contribuyes al proyecto |
| `gatekeeper-asgi[servers]` | hypercorn, daphne | Pruebas con servidores ASGI reales |

```bash
pip install "gatekeeper-asgi[redis]"
```

El núcleo solo depende de `starlette` (cualquier versión ≥ 0.23; FastAPI ya la
incluye).

!!! info "Por qué los servidores están en un extra aparte"
    `daphne` arrastra `Twisted`, cuya versión **estable** (26.4.0) tiene
    avisos de seguridad cuyos parches solo están en una *release candidate*
    (26.10.0rc1). El runtime de Gatekeeper no depende de ninguno de los dos,
    así que no tiene por qué arrastrar ese riesgo: por eso están en
    `servers` y no en `dev`.

    Para ejecutar las pruebas con servidores reales:
    `pip install -e ".[dev,servers]"`. En CI se instalan los dos extras.

!!! info "Versiones de Redis admitidas"
    Con el extra `[redis]` hace falta un **Redis 5.0 o superior** (probado
    contra Redis 5.0 y 7.2). Gatekeeper fuerza el protocolo **RESP2** al
    conectar: el cliente `redis-py` moderno hace handshake RESP3 por defecto y
    un Redis 5.x o 6.0 no lo entiende (`unknown command HELLO`). La ventana
    deslizante solo usa `EVAL`/`ZADD`/`ZRANGE`, así que RESP2 no le quita
    nada. Si usas un Redis gestionado (ElastiCache, MemoryDB, Upstash),
    cualquiera de esos servicios habla RESP2 sin problema.

## Requisitos

- **Python 3.10 o superior.** El CI prueba 3.10, 3.11, 3.12 y 3.13; el
  mantenimiento local se hace en 3.14.
- **Starlette 0.23 o superior** (FastAPI ya la incluye). La matriz completa
  de versiones probadas está en
  [Compatibilidad y soporte](compatibilidad.md).
- Un servidor ASGI (uvicorn, hypercorn, daphne…). El middleware es ASGI puro:
    funciona con FastAPI y con Starlette puro.

!!! info "La matriz de compatibilidad está medida"
    La tabla de versiones no es una suposición: `tools/compat_matrix.py` crea
    un entorno virtual por cada combinación y comprueba que el middleware
    bloquea un ataque, deja pasar lo legítimo y pone las cabeceras de
    seguridad. Se puede regenerar con `python tools/compat_matrix.py`.

## Verificar la instalación

```bash
python -c "import gatekeeper; print(gatekeeper.__version__)"
```

Si usas comprobación de tipos, comprueba también que los tipos llegan:

```bash
python -m pip install mypy
echo 'from gatekeeper import Config
config: int = Config()' > consumidor.py
mypy consumidor.py   # debe quejarse: Config no es int (gracias a py.typed)
rm consumidor.py
```

---

Siguiente: [Uso →](uso.md) · [Despliegue →](despliegue.md)

