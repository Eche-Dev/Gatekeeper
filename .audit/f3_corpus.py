#!/usr/bin/env python3
"""F3.5 - Corpus de falsos positivos en espanol e ingles (100 casos nuevos).

Dos lotes:

- LOTE A (desarrollo, `corpus/benign.json`, benign-082..benign-131): su unico
  proposito es AJUSTAR. Si un caso salta, se ajusta la regla y se vuelve a
  medir (medido sobre el corpus externo de CRS para no perder detecciones).
- LOTE B (retenido, `corpus/heldout_benign.json`, hob-091..hob-140): se escribe
  DESPUES de congelar las reglas de la Fase 3 y se MIDE UNA VEZ. Un falso
  positivo aqui NO se arregla con una regla nueva: se documenta. Ese es el
  valor de este corpus.

Uso:
    python .audit/f3_corpus.py            # mide los dos lotes
    python .audit/f3_corpus.py --write    # escribe los casos en los corpus
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "gatekeeper-v0.3" / "gatekeeper"
sys.path.insert(0, str(PKG / "src"))

from gatekeeper.rules import scan  # noqa: E402

# --- LOTE A: desarrollo (se puede ajustar) ---------------------------------
# (id, payload, note[, known_fp])
LOTE_A: list[tuple] = [
    ("benign-082", "/search?q=union+all+en+sql+como+se+usa",
     "«union all» en prosa: la firma de ruta pide el contexto de una consulta"),
    ("benign-083", "/search?q=how+to+use+union+all+in+sqlite",
     "«union all» en ingles, mismo caso"),
    ("benign-084", "/search?q=waitfor+delay+en+sql+server",
     "«waitfor delay» en prosa: la firma de tiempo no distingue la explicacion"),
    ("benign-085", "/search?q=like+null+en+sql+que+significa",
     "«like null» en prosa: la firma exige la forma `like null` pegada"),
    ("benign-086", "/search?q=union+of+sets+in+python+with+two+lists",
     "«union» como sustantivo en ingles"),
    ("benign-087", "/blog/tutorial-de-select-y-where-en-postgres",
     "«select» y «where» en un titulo de blog"),
    ("benign-088", "/search?q=drop+de+tablas+en+sqlalchemy",
     "«drop» sin punto y coma delante"),
    ("benign-089", "/search?q=truncate+table+without+drop+in+postgresql",
     "«truncate table» sin punto y coma delante"),
    ("benign-090", "/search?q=como+filtrar+por+fecha+con+order+by+en+mysql",
     "«order by» seguido de palabra, no de numero"),
    ("benign-091", "/search?q=group+by+de+datos+en+pandas+agg",
     "«group by» sin numero detras"),
    ("benign-092", "/search?q=substring+en+python+como+se+usa",
     "«substring» sin parentesis"),
    ("benign-093", "/search?q=ascii+art+generator+free",
     "«ascii» sin parentesis"),
    ("benign-094", "/search?q=length+of+an+array+in+javascript",
     "«length» sin parentesis"),
    ("benign-095", "/search?q=cast+de+tipos+en+typescript",
     "«cast» sin parentesis"),
    ("benign-096", "/search?q=count+de+palabras+en+un+documento+pdf",
     "«count» sin parentesis"),
    ("benign-097", "/search?q=min+y+max+en+python+sin+librerias",
     "«min»/«max» sin parentesis"),
    ("benign-098", "/search?q=rand+en+php+para+generar+contrasenas",
     "«rand» sin parentesis"),
    ("benign-099", "/search?q=convert+to+int+in+javascript",
     "«convert» sin parentesis"),
    ("benign-100", "/search?q=regexp+en+javascript+expresion+regular",
     "«regexp» sin parentesis"),
    ("benign-101", "/search?q=version+de+node+22+actual",
     "«version» en prosa"),
    ("benign-102", "/search?q=how+to+call+substring+in+sql+server",
     "«substring» sin parentesis ni comparacion"),
    ("benign-103", "/search?q=como+usar+script+en+html+para+incrustar+codigo",
     "«script» en prosa: la documentacion lo nombra"),
    ("benign-104", "/search?q=how+to+embed+a+script+tag+in+html",
     "«script tag» en prosa"),
    ("benign-105", "/search?q=javascript+como+lenguaje+de+navegador",
     "«javascript» sin dos puntos"),
    ("benign-106", "/search?q=que+es+el+operador+$ne+de+mongodb",
     "«$ne» documentado en una busqueda"),
    ("benign-107", "/search?q=how+to+use+mongodb+$exists+operator",
     "«$exists» documentado en una busqueda"),
    ("benign-108", "/search?q=plantilla+de+jinja+con+{{config}}+y+variables",
     "«{{config}}» en una busqueda sobre plantillas",
     "limite conocido: `{{config}}` es el vector de Jinja2 mas corto; romperlo "
     "para tapar una busqueda de documentacion no sale a cuenta"),
    ("benign-109", "/search?q=log4j+como+usar+${env:PATH}+en+un+fichero",
     "«${env:...}» documentado en una busqueda",
     "limite conocido: la familia Log4Shell es critica; `${env:...}` en un "
     "valor se trata como exfiltracion aunque alguien lo cite en un tutorial"),
    ("benign-110", "/search?q=que+significa+${jndi}+en+log4j",
     "«${jndi}» documentado en una busqueda",
     "limite conocido: mismo motivo que el caso anterior (familia Log4Shell)"),
    ("benign-111", "/api/importar?archivo=informe+2024&formato=csv",
     "importacion de fichero con fecha en el nombre"),
    ("benign-112", "/api/pedidos?estado=enviado&orden=asc&pagina=2",
     "filtros y paginacion"),
    ("benign-113", "/docs/guia/instalacion",
     "ruta de documentacion"),
    ("benign-114", "/search?q=mejor+monitor+para+programar+en+2026",
     "busqueda corriente"),
    ("benign-115", "/search?q=best+laptop+for+developers+2026",
     "busqueda corriente en ingles"),
    ("benign-116", "/api/v2/usuarios?email=ana.garcia%40ejemplo.com",
     "email con arroba codificado"),
    ("benign-117", "/api/v2/usuarios?email=john.doe%40example.org",
     "email con arroba codificado (ingles)"),
    ("benign-118", "/search?q=como+configurar+un+proxy+para+10.0.0.5",
     "IP privada: no es la de metadata, se puede permitir"),
    ("benign-119", "/search?q=como+configurar+un+proxy+para+192.168.1.1",
     "IP privada en otro rango"),
    ("benign-120", "/api/webhooks?url=http://localhost:3000/hooks",
     "webhook a localhost: legitimo en desarrollo"),
    ("benign-121", "/search?q=rm+rf+en+un+sistema+de+ficheros+linux",
     "«rm» sin separador de shell delante"),
    ("benign-122", "/search?q=cat+file+command+in+linux",
     "«cat» sin separador delante"),
    ("benign-123", "/search?q=como+usar+curl+para+descargar+archivos",
     "«curl» sin separador delante"),
    ("benign-124", "/search?q=whoami+command+windows+cmd",
     "«whoami» sin separador delante"),
    ("benign-125", "/search?q=ejecutar+dos+comandos+con+&&+en+bash",
     "«&& bash» explicado en prosa"),
    ("benign-126", "/search?q=ls+-la+en+linux+para+ver+archivos",
     "«ls» sin separador delante"),
    ("benign-127", "/search?q=eval+en+javascript+es+peligroso",
     "«eval» sin parentesis ni separador"),
    ("benign-128", "/search?q=system+y+exec+en+php+ejemplos",
     "«system»/«exec» sin parentesis ni separador"),
    ("benign-129", "/blog/2026/01/15/como-empezar-en-fastapi",
     "fecha en el slug de un articulo"),
    ("benign-130", "/blog/2026/01/15/getting-started-with-fastapi",
     "fecha en el slug de un articulo (ingles)"),
    ("benign-131", "{\"body\": \"Hola\\nLocation: Madrid\"}",
     "cuerpo de correo con salto de linea y una cabecera citada",
     "limite conocido: un salto de linea seguido de una cabecera puede ser un "
     "response splitting; el patron no puede distinguirlo de un texto que la cita"),
]

# --- LOTE B: retenido (se mide, no se ajusta) --------------------------------
LOTE_B: list[tuple] = [
    ("hob-091", "/catalogo/zapatillas?marca=nike&talla=42&precio_max=99.90",
     "filtros de catalogo"),
    ("hob-092", "/banking/transfer?amount=250.50&currency=EUR&beneficiary=ES9121",
     "transferencia bancaria"),
    ("hob-093", "/hospital/appointments?specialty=cardiology&date=2026-03-10",
     "citas medicas"),
    ("hob-094", "/university/courses?code=CS101&term=2026S&mode=hybrid",
     "matriculas universitaire"),
    ("hob-095", "/vuelos?origen=BCN&destino=PMI&fecha=2026-04-01",
     "busqueda de vuelos"),
    ("hob-096", "/tramites?tramite=renovacion+dni&comunidad=cataluna",
     "tramite administrativo"),
    ("hob-097", "/recipes/search?ingredients=tomato%2C+ajo&q=arrroz",
     "recetas con lista de ingredientes"),
    ("hob-098", "/jobs?role=backend+developer&remote=yes&salary_min=45000",
     "ofertas de empleo"),
    ("hob-099", "/forum/thread?title=how+to+use+union+all+in+sql&page=2",
     "titulo de hilo que explica SQL"),
    ("hob-100", "/support/ticket?subject=Error+en+la+consulta+SQL+al+guardar",
     "ticket de soporte que menciona SQL"),
    ("hob-101", "/docs/sql?query=SELECT+name+FROM+users+WHERE+id+%3D+42",
     "consulta SQL de ejemplo en la documentacion"),
    ("hob-102", "/blog/notes/using+select+and+order+by+in+reports",
     "«select» y «order by» en un titulo"),
    ("hob-103", "/news?tag=union+europea+de+baloncesto",
     "«union» en el nombre de una institucion"),
    ("hob-104", "/weather?city=Oviedo&units=metric&lang=es",
     "consulta de tiempo"),
    ("hob-105", "/music/search?artist=Ramones&album=leave+it+to+moon",
     "busqueda musical"),
    ("hob-106", "/photos?tag=gato&size=large&page=3",
     "galeria de fotos"),
    ("hob-107", "/sports/matches?team=real+madrid&competition=liga&season=2026",
     "resultados deportivos"),
    ("hob-108", "/library/search?author=Garcia+Marquez&title=ciudad+de+los+espias",
     "catalogo de biblioteca"),
    ("hob-109", "/gaming/guides?game=elden+ring&query=boss+de+la+primera+zona",
     "guia de videojuego"),
    ("hob-110", "/travel/tips?tag=backpacking+europe&lang=en",
     "consejos de viaje"),
    ("hob-111", "/faq?q=como+configurar+un+webhook+de+github",
     "pregunta frecuente sobre webhooks"),
    ("hob-112", "/faq?q=how+to+escape+single+quotes+in+sql",
     "pregunta sobre escapar comillas"),
    ("hob-113", "/faq?q=que+significa+coalesce+en+sql",
     "nombre de funcion SQL en prosa"),
    ("hob-114", "/faq?q=difference+between+cast+and+convert+in+sql",
     "comparacion de funciones en prosa"),
    ("hob-115", "/faq?q=como+usar+like+con+patrones+en+sql",
     "«like» con otra palabra detras"),
    ("hob-116", "/faq?q=how+to+use+group+by+with+having+clause",
     "«group by»/«having» sin numeros"),
    ("hob-117", "/faq?q=ejemplo+de+having+en+consultas+sql",
     "«having» sin comparacion numerica"),
    ("hob-118", "/faq?q=como+usar+benchmark+en+go+para+medir",
     "«benchmark» sin parentesis"),
    ("hob-119", "/faq?q=what+is+waitfor+delay+in+sql+server",
     "«waitfor delay» explicado en ingles"),
    ("hob-120", "/faq?q=cuando+usar+substring+en+sql+server",
     "«substring» sin parentesis"),
    ("hob-121", "/faq?q=how+to+use+mid+function+in+oracle+sql",
     "«mid» sin parentesis"),
    ("hob-122", "/faq?q=como+extraer+caracteres+con+ascii+en+sql",
     "«ascii» sin parentesis"),
    ("hob-123", "/faq?q=java+script+o+javascript+que+diferencia",
     "«javascript» sin esquema"),
    ("hob-124", "/faq?q=how+to+load+javascript+on+page+load+without+blocking",
     "carga de un script en una pagina"),
    ("hob-125", "/faq?q=como+incrustar+codigo+de+tercero+en+mi+web",
     "insercion de codigo de terceros"),
    ("hob-126", "/faq?q=is+it+safe+to+use+eval+in+javascript",
     "«eval» sin parentesis"),
    ("hob-127", "/faq?q=que+es+el+prototype+en+javascript",
     "«prototype» sin «constructor»"),
    ("hob-128", "/faq?q=how+to+avoid+prototype+pollution+in+nodejs",
     "«prototype pollution» sin «constructor»"),
    ("hob-129", "/faq?q=como+prevenir+ataques+ssrf+en+tu+api",
     "pregunta sobre SSRF"),
    ("hob-130", "/faq?q=how+to+block+ssrf+attacks+with+allowlist",
     "pregunta sobre SSRF en ingles"),
    ("hob-131", "/faq?q=que+es+el+metadata+de+aws+169.254.169.254",
     "la IP de metadata citada en una explicacion",
     "limite conocido: la IP de metadata se bloquea en cualquier posicion; "
     "explicarla en un articulo salta. No se afloja porque el parametro de "
     "destino (`?ip=169.254.169.254`) es un SSRF real"),
    ("hob-132", "/faq?q=how+to+rotate+api+keys+in+github+actions",
     "rotacion de claves de API"),
    ("hob-133", "/faq?q=como+configurar+autenticacion+por+clave+api",
     "autenticacion por clave"),
    ("hob-134", "/faq?q=how+to+read+the+environment+variables+in+python",
     "variables de entorno"),
    ("hob-135", "/faq?q=configurar+variables+de+entorno+con+dotenv",
     "variables de entorno con dotenv"),
    ("hob-136", "/api/v1/orders?status=shipped&min_total=50&currency=EUR&page=2",
     "filtros de pedidos"),
    ("hob-137", "/api/v1/invoices?year=2026&month=02&format=pdf",
     "listado de facturas"),
    ("hob-138", "/api/v1/geo/cities?lat=43.3623&lng=-8.4115&radius=25",
     "consulta geografica"),
    ("hob-139", "/api/v1/metrics?window=24h&resolution=5m&include=nulls",
     "consulta de metricas"),
    ("hob-140", "/api/v1/users?q=Ana+Garcia&role=admin&active=true",
     "busqueda de usuarios"),
]


def measure(nombre: str, lote: list[tuple]) -> list[tuple[str, str, str]]:
    """Devuelve los casos que la deteccion marca (id, regla, payload)."""
    salta: list[tuple[str, str, str]] = []
    for caso in lote:
        id_, payload = caso[0], caso[1]
        regla = scan(payload)
        if regla:
            salta.append((id_, regla, payload))
    print(f"\n=== {nombre}: {len(lote)} casos, {len(salta)} marcados ===")
    for id_, regla, payload in salta:
        print(f"  {id_:12s} {regla:16s} {payload}")
    return salta


def _bloque_a(casos: list[tuple]) -> str:
    lineas = []
    for caso in casos:
        id_, payload, note = caso[0], caso[1], caso[2]
        campos = (
            f'"id": "{id_}", "payload": {json.dumps(payload, ensure_ascii=False)}, '
            f'"note": {json.dumps(note, ensure_ascii=False)}'
        )
        if len(caso) > 3 and caso[3]:
            campos += f', "known_fp": {json.dumps(caso[3], ensure_ascii=False)}'
        lineas.append("    {" + campos + "}")
    return ",\n".join(lineas)


def _bloque_b(casos: list[tuple]) -> str:
    bloques = []
    for caso in casos:
        id_, payload, note = caso[0], caso[1], caso[2]
        bloque = (
            "    {\n"
            f'      "id": "{id_}",\n'
            f'      "payload": {json.dumps(payload, ensure_ascii=False)},\n'
            f'      "note": {json.dumps(note, ensure_ascii=False)}'
        )
        if len(caso) > 3 and caso[3]:
            bloque += f',\n      "known_fp": {json.dumps(caso[3], ensure_ascii=False)}'
        bloques.append(bloque + "\n    }")
    return ",\n".join(bloques)


def escribir() -> None:
    """Añade los dos lotes a los corpus (idempotente: se puede re-ejecutar)."""
    benign = PKG / "corpus" / "benign.json"
    data = json.loads(benign.read_text(encoding="utf-8"))
    ids_a = {c[0] for c in LOTE_A}
    existentes = [c for c in data["payloads"] if c["id"] not in ids_a]
    nuevos = []
    for c in LOTE_A:
        caso = {"id": c[0], "payload": c[1], "note": c[2]}
        if len(c) > 3 and c[3]:
            caso["known_fp"] = c[3]
        nuevos.append(caso)
    lineas = [
        "    {" + ", ".join(
            f"{json.dumps(k, ensure_ascii=False)}: {json.dumps(v, ensure_ascii=False)}"
            for k, v in caso.items()
        ) + "}"
        for caso in existentes + nuevos
    ]
    cuerpo = "{\n" + f"  {json.dumps('description', ensure_ascii=False)}: " \
        + json.dumps(data["description"], ensure_ascii=False) + ",\n" \
        + '  "payloads": [\n' + ",\n".join(lineas) + "\n  ]\n}\n"
    benign.write_text(cuerpo, encoding="utf-8")
    print(f"escrito {benign} (+{len(nuevos)} casos, {len(existentes)} previos)")

    heldout = PKG / "corpus" / "heldout_benign.json"
    data = json.loads(heldout.read_text(encoding="utf-8"))
    ids_b = {c[0] for c in LOTE_B}
    existentes = [c for c in data["payloads"] if c["id"] not in ids_b]
    nuevos = []
    for c in LOTE_B:
        caso = {"id": c[0], "payload": c[1], "note": c[2]}
        if len(c) > 3 and c[3]:
            caso["known_fp"] = c[3]
        nuevos.append(caso)
    cabecera = {k: v for k, v in data.items() if k != "payloads"}
    cabecera["batch2"] = {
        "count": len(nuevos),
        "written_after": "Fase 3 (firmas congeladas en la rama objetivo100)",
        "note": (
            "Segundo lote de trafico legitimo benigno, escrito DESPUES de congelar "
            "las firmas de la Fase 3 (tautologia con literales vacios, booleano "
            "ciego, sleep numerico, XSS por atributos, cmdi con salto de linea, "
            "SSRF con IP en decimal/hex/octal). Se mide una vez: un falso positivo "
            "aqui NO se corrige con una firma nueva, se documenta. Antes de los "
            "ajustes que el lote de desarrollo si motivaron, este lote tenia 3 "
            "falsos positivos; dos los resolvieron esos ajustes (union all y "
            "waitfor delay) y el tercero (la IP de metadata citada en una "
            "explicacion) sigue abierto y documentado."
        ),
    }
    data = {**cabecera, "payloads": existentes + nuevos}
    heldout.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"escrito {heldout} (+{len(nuevos)} casos, {len(existentes)} previos)")


def main() -> int:
    if "--write" in sys.argv:
        escribir()
    a = measure("LOTE A (desarrollo, ajustable)", LOTE_A)
    b = measure("LOTE B (retenido, se mide)", LOTE_B)
    print(f"\nResumen: A={len(a)}/{len(LOTE_A)} marcados, B={len(b)}/{len(LOTE_B)} marcados")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
