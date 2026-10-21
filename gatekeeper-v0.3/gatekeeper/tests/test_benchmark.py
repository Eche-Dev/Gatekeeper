"""El benchmark debe poder ejecutarse siempre: si se rompe, se entera CI."""

import importlib.util
import sys
from pathlib import Path

_BENCH = Path(__file__).resolve().parents[1] / "benchmarks" / "latency.py"
_spec = importlib.util.spec_from_file_location("gk_latency", _BENCH)
latency = importlib.util.module_from_spec(_spec)
sys.modules["gk_latency"] = latency  # dataclasses lo exige al resolver anotaciones
_spec.loader.exec_module(latency)


def test_benchmark_runs_and_reports_all_scenarios():
    data = latency.run_benchmark(iterations=5, rounds=2)
    assert len(data["results"]) == len(latency.scenarios())
    for row in data["results"]:
        assert row["median_us"] > 0


def test_middleware_adds_work_but_does_not_explode():
    """Solo comprueba que el middleware se ejecuta por completo en el camino limpio."""
    data = latency.run_benchmark(iterations=5, rounds=1)
    names = [row["scenario"] for row in data["results"]]
    assert "sin middleware (base)" in names
    assert "request atacante (bloqueado con 403)" in names
