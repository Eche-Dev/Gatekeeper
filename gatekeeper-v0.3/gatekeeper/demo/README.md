# Demo de Gatekeeper

App de juguete (una "tienda" sin datos ni estado) con el middleware delante y
un **playground** en la portada: botones que lanzan peticiones reales y pinta
el `200`/`403`, mientras la terminal del servidor muestra la auditoría.

![Demo](../docs/assets/demo.gif)

## Ejecutar en local

```bash
cd demo
pip install -e .. fastapi uvicorn
uvicorn app:app --reload
```

Abre <http://127.0.0.1:8000/> y toca los botones. En la terminal verás los
eventos de auditoría (`attack_detected` con la regla que saltó; nunca con los
valores del payload).

Desde la terminal, lo mismo:

```bash
curl -s "http://127.0.0.1:8000/health"
curl -s -G "http://127.0.0.1:8000/api/search" --data-urlencode "q=zapatillas"
curl -s -G "http://127.0.0.1:8000/api/search" --data-urlencode "q=' OR 1=1--"
curl -s -G "http://127.0.0.1:8000/api/search" --data-urlencode "q=<script>alert(1)</script>"
curl -s -G "http://127.0.0.1:8000/api/search" --data-urlencode "q=../../etc/shadow"
```

## Desplegar

### Vercel (un comando)

```bash
cd demo
vercel --prod
```

`requirements.txt` instala Gatekeeper desde el repo (para probar el demo con
el código local; en producción, `pip install gatekeeper-asgi` desde PyPI) y
`vercel.json` apunta al runtime de Python. Sale en `tu-proyecto.vercel.app`.

### Docker (cualquier sitio)

```bash
docker build -t gatekeeper-demo .
docker run -p 8000:8000 gatekeeper-demo
```

## Nota honesta

Esta demo es un juguete a propósito: el catálogo es una lista de cuatro
cadenas, no hay autenticación ni base de datos y **no la uses como plantilla
de tu app real**. Lo que sí es real es el middleware: rate limiting activo
(120/min por IP), inspección de query y body, y auditoría sin payloads.
