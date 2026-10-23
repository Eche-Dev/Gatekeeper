#!/usr/bin/env python3

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

CORPUS_FILE = ROOT / "corpus" / "cross.json"
REPORT_FILE = ROOT / "corpus" / "CROSS_REPORT.md"
DEFAULT_MIN = 1.0
DEFAULT_MAX_FP = 0.0

@dataclass
class M:
    attacks_total: int = 0
    attacks_blocked: int = 0
    benign_total: int = 0
    benign_blocked: int = 0
    documented_fp: int = 0
    missed: list = field(default_factory=list)
    false_positives: list = field(default_factory=list)

    @property
    def dr(self):
        return self.attacks_blocked / self.attacks_total if self.attacks_total else 0

    @property
    def fpr(self):
        undoc = self.benign_blocked - self.documented_fp
        return undoc / self.benign_total if self.benign_total else 0

def load():
    d = json.loads(CORPUS_FILE.read_text(encoding="utf-8"))
    return list(d["payloads"]) + list(d["benign_payloads"])

def client(cross):
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient
    from gatekeeper import Config, GatekeeperMiddleware
    async def echo(r): return PlainTextResponse("ok")
    a = Starlette(routes=[Route("/{path:path}", echo, methods=["GET","POST"])])
    a.add_middleware(GatekeeperMiddleware, config=Config(rate_limit=0, inspect_cross_carrier=cross))
    return TestClient(a)

def blocked(cl, it):
    r = cl.post(it["target"], content=it["body"].encode("utf-8"), headers={"content-type": it["content_type"]})
    if r.status_code not in (200,403): raise RuntimeError(f"{it['id']}: {r.status_code}")
    return r.status_code == 403

def evaluate_mode(items, cross):
    r = M()
    c = client(cross)
    for it in items:
        b = blocked(c, it)
        if it["expect"] == "attack":
            r.attacks_total += 1
            if b: r.attacks_blocked += 1
            else: r.missed.append(it["id"])
        else:
            r.benign_total += 1
            if b:
                r.benign_blocked += 1
                if it.get("known_fp"): r.documented_fp += 1
                else: r.false_positives.append(it["id"])
    return r

def evaluate():
    it = load()
    d = evaluate_mode(it, False)
    c_ = evaluate_mode(it, True)
    return {"default": {"attacks_total": d.attacks_total, "attacks_blocked": d.attacks_blocked, "benign_total": d.benign_total, "benign_blocked": d.benign_blocked, "documented_fp": d.documented_fp, "missed": d.missed, "false_positives": d.false_positives}, "cross": {"attacks_total": c_.attacks_total, "attacks_blocked": c_.attacks_blocked, "benign_total": c_.benign_total, "benign_blocked": c_.benign_blocked, "documented_fp": c_.documented_fp, "missed": c_.missed, "false_positives": c_.false_positives}}

def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--write-report", action="store_true")
    p.add_argument("--check", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--min", type=float, default=DEFAULT_MIN)
    p.add_argument("--max-fp", type=float, default=DEFAULT_MAX_FP)
    a = p.parse_args(argv)
    rep = evaluate()
    D = rep["default"]
    C = rep["cross"]
    gain = C["attacks_blocked"] - D["attacks_blocked"]
    lines = [
        "| Por defecto | {0}/{1} | {2}/{3} | {4} |".format(
            D["attacks_blocked"], D["attacks_total"],
            D["benign_blocked"], D["benign_total"],
            D["benign_blocked"] - D["documented_fp"]),
        "| Cruzado | {0}/{1} | {2}/{3} | {4} |".format(
            C["attacks_blocked"], C["attacks_total"],
            C["benign_blocked"], C["benign_total"],
            C["benign_blocked"] - C["documented_fp"]),
        f"Ataques adicionales bloqueados solo en modo cruzado: {gain}",
    ]
    if a.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
    else:
        print("\n".join(lines))
    if a.write_report:
        REPORT_FILE.write_text("\n".join(lines), encoding="utf-8")
    if a.check:
        if C["attacks_blocked"] / C["attacks_total"] < a.min: print("FALLO", file=sys.stderr); return 1
        if C["benign_blocked"] / C["benign_total"] > a.max_fp: print("FALLO", file=sys.stderr); return 1
        if D["benign_blocked"] / D["benign_total"] > a.max_fp: print("FALLO", file=sys.stderr); return 1
        print("OK", file=sys.stderr)
    return 0

if __name__ == "__main__": raise SystemExit(main())