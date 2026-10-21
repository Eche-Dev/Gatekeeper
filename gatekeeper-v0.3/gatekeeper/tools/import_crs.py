#!/usr/bin/env python3
"""Extrae el corpus de regresión de OWASP CRS a corpus/crs_payloads.json.

CRS (Core Rule Set) es la colección de regresión de referencia del ecosistema
WAF. Importar sus payloads permite medir Gatekeeper contra un corpus EXTERNO,
escrito por gente distinta, en vez de solo contra el nuestro.

Uso:
    git clone --depth 1 https://github.com/coreruleset/coreruleset %TEMP%/crs
    python tools/import_crs.py --crs-dir %TEMP%/crs

Alcance y metodología:
- Solo las familias que Gatekeeper afirma cubrir: 930 (LFI/traversal),
  941 (XSS) y 942 (SQLi), de tests/regression/tests/ de CRS.
- `expect=attack` cuando CRS espera que su regla salte (expect_ids);
  `expect=benign` cuando CRS espera que nada salte (no_expect_ids) y sirve
  como tráfico negativo para medir falsos positivos.
- `carrier` registra dónde vive el payload (body/query/path/headers) para que
  el evaluador excluya con transparencia lo que Gatekeeper no inspecciona
  (cabeceras y bodies con content-type no inspeccionable).

Licencia: OWASP CRS es Apache-2.0. Se conserva corpus/LICENSE-APACHE-2.0.txt y
la atribución en corpus/README.md. No edites el JSON a mano: reimporta.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "corpus" / "crs_payloads.json"
SOURCE_URL = "https://github.com/coreruleset/coreruleset"

FAMILIES = {
    "REQUEST-930-APPLICATION-ATTACK-LFI": "path_traversal",
    "REQUEST-941-APPLICATION-ATTACK-XSS": "xss",
    "REQUEST-942-APPLICATION-ATTACK-SQLI": "sqli",
}

# Cabeceras estructurales de plantilla: no llevan payload en los tests de CRS.
STRUCTURAL_HEADERS = {
    "host", "accept", "accept-encoding", "connection", "content-length", "content-type",
}
TEMPLATE_UA = "OWASP CRS test agent"


def classify_carrier(uri: str, data: str | None, headers: dict) -> str:
    """¿Dónde vive el payload de este test?"""
    if data:
        return "body"
    if "?" in uri:
        return "query"
    extra = {
        k: v for k, v in headers.items()
        if k.lower() not in STRUCTURAL_HEADERS
        and not (k.lower() == "user-agent" and v == TEMPLATE_UA)
    }
    return "headers" if extra else "path"


def git_commit(crs_dir: Path) -> tuple[str | None, str | None]:
    """(sha, fecha) del checkout, o (None, None) si no es un repo git."""
    try:
        out = subprocess.run(
            ["git", "-C", str(crs_dir), "log", "-1", "--format=%H|%cI"],
            capture_output=True, text=True, check=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    sha, _, iso = out.stdout.strip().partition("|")
    return sha or None, iso or None


def extract(crs_dir: Path) -> tuple[list[dict], Counter]:
    entries: list[dict] = []
    stats: Counter = Counter()
    for dirname, family in FAMILIES.items():
        tests_dir = crs_dir / "tests" / "regression" / "tests" / dirname
        if not tests_dir.is_dir():
            raise SystemExit(f"falta el directorio de tests: {tests_dir}")
        for path in sorted(tests_dir.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            crs_rule = doc.get("rule_id")
            for test_idx, test in enumerate(doc.get("tests") or [], 1):
                desc = str(test.get("desc") or "")
                test_id = test.get("test_id", test_idx)
                for stage_idx, stage in enumerate(test.get("stages") or [], 1):
                    inp = stage.get("input") or {}
                    log = (stage.get("output") or {}).get("log") or {}
                    if log.get("expect_ids"):
                        expect = "attack"
                    elif log.get("no_expect_ids"):
                        expect = "benign"
                    else:
                        continue  # test sin expectativa explícita: no se puntúa
                    headers = inp.get("headers") or {}
                    content_type = next(
                        (v for k, v in headers.items() if k.lower() == "content-type"), None
                    )
                    uri = str(inp.get("uri") or "")
                    raw_data = inp.get("data")
                    data = str(raw_data) if raw_data is not None else None
                    carrier = classify_carrier(uri, data, headers)
                    entries.append({
                        "id": f"crs-{path.stem}-t{test_id}-s{stage_idx}",
                        "crs_rule": crs_rule,
                        "family": family,
                        "expect": expect,
                        "carrier": carrier,
                        "uri": uri,
                        "data": data,
                        "content_type": content_type,
                        "desc": desc,
                    })
                    stats[f"{expect}:{carrier}"] += 1
    return entries, stats


def build(crs_dir: Path) -> dict:
    if not crs_dir.is_dir():
        raise SystemExit(
            f"no existe {crs_dir}: clona CRS con\n"
            f"  git clone --depth 1 {SOURCE_URL} <directorio>"
        )
    entries, stats = extract(crs_dir)
    ids = [e["id"] for e in entries]
    if len(ids) != len(set(ids)):
        raise SystemExit("ids duplicados: revisa el importador")
    sha, commit_date = git_commit(crs_dir)
    return {
        "source": {
            "project": "OWASP Core Rule Set (CRS)",
            "url": SOURCE_URL,
            "license": "Apache-2.0",
            "license_file": "LICENSE-APACHE-2.0.txt",
            "commit": sha,
            "commit_date": commit_date,
            "retrieved": date.today().isoformat(),
            "imported_by": "tools/import_crs.py",
            "scope": "tests/regression/tests/REQUEST-{930,941,942}",
            "changes": (
                "Extraídos de los YAML de regresión de CRS a JSON: payload, "
                "expectativa y transportador. Los payloads no se editan."
            ),
            "stats": dict(sorted(stats.items())),
        },
        "payloads": entries,
    }


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--crs-dir",
        type=Path,
        default=Path(os.environ.get("TEMP", "/tmp")) / "crs",
        help="checkout de coreruleset/coreruleset (por defecto: %%TEMP%%/crs)",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true",
                        help="no escribe: solo valida el JSON existente")
    args = parser.parse_args(argv)

    if args.check:
        data = json.loads(args.out.read_text(encoding="utf-8"))
        source, payloads = data["source"], data["payloads"]
        assert source["license"] == "Apache-2.0", "falta la licencia en la fuente"
        assert source.get("commit"), "falta el commit de procedencia"
        ids = [p["id"] for p in payloads]
        assert len(ids) == len(set(ids)), "ids duplicados"
        print(f"✅ {args.out.name}: {len(payloads)} payloads, commit {source['commit'][:9]}")
        return 0

    data = build(args.crs_dir)
    args.out.write_text(
        json.dumps(data, ensure_ascii=False, indent=1, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    stats = data["source"]["stats"]
    print(f"escrito {args.out} ({len(data['payloads'])} payloads)")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print(f"  commit: {data['source']['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
