# Corpus cross.json

Este archivo forma parte del proyecto Gatekeeper v0.3.

Es un corpus opt-in, de solo desarrollo, y no es un conjunto de retencion de seguridad para produccion.

Mede deteccion de ataques cruzados (objetivo + body juntos) con inspect_cross_carrier=True.
No se mezcla con el corpus principal (attacks.json/benign.json) ni con la evaluacion REPORT.md.
Para activar en produccion, revisar primero los falsos positivos con trafico real en modo monitor_only.
