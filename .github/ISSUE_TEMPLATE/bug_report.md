---
name: 🐞 Informar de un error
about: Algo no funciona como documenta Gatekeeper
labels: bug
---

<!-- ⚠️ Si es una vulnerabilidad de seguridad, NO abras un issue público:
     sigue el proceso de gatekeeper-v0.3/gatekeeper/SECURITY.md -->

## Versión y entorno

- Versión de Gatekeeper (o commit):
- Versión de Python:
- Servidor ASGI (uvicorn / hypercorn / daphne / otro):
- Framework (FastAPI / Starlette / otro):

## Qué esperabas y qué pasó

<!-- Comportamiento esperado vs real. Con `monitor_only=True` puedes verificarlo
     sin bloquear. -->

## Cómo se reproduce

<!-- Pasos mínimos, con la configuración (Config(...)) y una petición de ejemplo.
     No pegues payloads reales de producción. -->

## Logs

<!-- La auditoría de Gatekeeper nunca incluye el contenido de los payloads:
     los eventos `attack_detected` traen la regla y la IP, no el texto. -->
