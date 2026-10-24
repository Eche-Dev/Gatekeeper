# Instalación

!!! info "Aún no en PyPI"
    Gatekeeper no está publicado en PyPI todavía: se publicará cuando el
    proyecto se decida completo. Por ahora se instala desde el repositorio.

!!! tip "¿Solo quieres verlo funcionar?"
    Si tu objetivo es comprobar que Gatekeeper bloquea lo que debe en cinco
    minutos, empieza por la [guía de inicio rápido](inicio-rapido.md): instala,
    añade el middleware y lanza los dos comandos que verifican que un ataque
    recibe 403.

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

El núcleo solo depende de `starlette` (cualquier versión ≥ 0.37; FastAPI ya la
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

- **Python 3.10 o superior.** El CI prueba 3.10, 3.11 y 3.12; el mantenimiento
  local se hace en 3.14.
- Un servidor ASGI (uvicorn, hypercorn, daphne…). El middleware es ASGI puro:
    funciona con FastAPI y con Starlette puro.

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

