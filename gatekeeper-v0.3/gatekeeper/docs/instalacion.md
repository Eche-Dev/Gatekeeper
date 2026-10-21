# Instalación

!!! info "Aún no en PyPI"
    Gatekeeper no está publicado en PyPI todavía: se publicará cuando el
    proyecto se decida completo. Por ahora se instala desde el repositorio.

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

```bash
pip install "gatekeeper-asgi[redis]"
```

El núcleo solo depende de `starlette` (cualquier versión ≥ 0.37; FastAPI ya la
incluye).

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

Siguiente: [Uso →](uso.md)
