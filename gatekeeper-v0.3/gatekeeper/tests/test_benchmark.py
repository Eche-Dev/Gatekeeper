"""El benchmark debe poder ejecutarse siempre: si se rompe, se entera CI.

Y el guard de latencia (`--check`) tiene que ser CREÍBLE en los dos sentidos:
pasar con el código actual y FALLAR ante una regresión. Un guard que nunca
rompe un pipeline es un adorno.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

_BENCH = Path(__file__).resolve().parents[1] / "benchmarks" / "latency.py"
_spec = importlib.util.spec_from_file_location("gk_latency", _BENCH)
latency = importlib.util.module_from_spec(_spec)
sys.modules["gk_latency"] = latency  # dataclasses lo exige al resolver anotaciones
_spec.loader.exec_module(latency)


def test_benchmark_runs_and_reports_all_scenarios():
    data = latency.run_benchmark(iterations=5, rounds=2)
    assert len(data["results"]) == len(latency.scenarios())
    for row in data["results"]:
        assert row["p50_us"] > 0


def test_middleware_adds_work_but_does_not_explode():
    """Solo comprueba que el middleware se ejecuta por completo en el camino limpio."""
    data = latency.run_benchmark(iterations=5, rounds=1)
    names = [row["scenario"] for row in data["results"]]
    assert "sin middleware (base)" in names
    assert "request atacante (bloqueado con 403)" in names


# ------------------------------------------------------- percentiles


def test_percentile_es_el_vecino_mas_cercano():
    """Vecino más cercano sobre el índice, que es lo que se usa para latencia:
    el percentil es una Muestra real, no un promedio entre dos."""
    muestras = [float(n) for n in range(1, 101)]  # 1..100
    assert latency.percentile(muestras, 0) == 1.0
    assert latency.percentile(muestras, 100) == 100.0
    assert latency.percentile(muestras, 95) == 95.0
    # el 50 cae en el índice 49 o 50 según el redondeo; los dos son válidos y
    # ambos son muestras reales del conjunto
    assert latency.percentile(muestras, 50) in (50.0, 51.0)
    # ningún percentil devuelve un valor inventado: siempre es una muestra
    for pct in range(0, 101, 7):
        assert latency.percentile(muestras, pct) in muestras


def test_percentile_no_explota_con_una_sola_muestra():
    assert latency.percentile([42.0], 99) == 42.0
    assert latency.percentile([], 50) == 0.0


def test_la_cola_es_mayor_que_la_mediana():
    """La razón de ser de B5: la media escondía la cola. Si p95 == p50 en un
    benchmark de un event loop, no estamos midiendo la distribución real."""
    samples = [10.0] * 900 + [500.0] * 100  # 10 % de peticiones lentas
    p50 = latency.percentile(samples, 50)
    p95 = latency.percentile(samples, 95)
    p99 = latency.percentile(samples, 99)
    assert p50 == 10.0, "la mediana es el camino rápido"
    assert p95 == 500.0, "el 10 % de la cola debe verse en p95"
    assert p99 == 500.0


def test_el_informe_expone_p50_p95_y_p99_por_escenario():
    data = latency.run_benchmark(iterations=20, rounds=1)
    for row in data["results"]:
        assert row["p50_us"] <= row["p95_us"] <= row["p99_us"] <= row["max_us"]
        assert row["samples"] == 20


def test_overhead_se_calcula_contra_la_base_en_el_mismo_percentil():
    data = latency.run_benchmark(iterations=20, rounds=1)
    base, inspeccion = data["results"][0], data["results"][2]
    assert base["scenario"] == "sin middleware (base)"
    # el overhead de p50 debe ser p50 - p50 de la base (no mezclar percentiles)
    assert inspeccion["overhead_p50_us"] == pytest.approx(
        inspeccion["p50_us"] - base["p50_us"], abs=0.02
    )
    assert inspeccion["overhead_p95_us"] == pytest.approx(
        inspeccion["p95_us"] - base["p95_us"], abs=0.02
    )


# ------------------------------------------------------- el guard


def test_el_guard_pasa_con_el_codigo_actual():
    data = latency.run_benchmark(iterations=60, rounds=2)
    ok, fallos = latency.check(data)
    assert ok, f"el guard falló con el código sin cambios: {fallos}"


def test_el_guard_falla_ante_una_regresion(monkeypatch, capsys):
    """La mitad importante: el guard tiene que ROMPER el build cuando toca."""
    monkeypatch.setitem(latency.CHECK_BUDGET_US, "completo (inspección + rate limit)", 0.01)
    data = latency.run_benchmark(iterations=20, rounds=1)
    ok, fallos = latency.check(data)
    assert not ok, "un presupuesto de 0.01 µs debe fallar siempre"
    assert fallos and "supera el presupuesto" in fallos[0]
    assert "REGRESIÓN" in capsys.readouterr().out


def test_el_guard_es_puro_sobre_los_datos():
    """`check` no vuelve a medir: evalúa lo que se le pasa. Así el veredicto es
    determinista y el ruido se filtra una sola vez, en `run_benchmark`."""
    data = latency.run_benchmark(iterations=20, rounds=1, repeats=1)
    fila = next(r for r in data["results"] if r["scenario"] == "completo (inspección + rate limit)")
    original = dict(fila)
    latency.check(data)
    assert fila == original, "check() no debe modificar los datos que evalúa"


def test_repeats_filtra_el_ruido_del_sistema():
    """Con repeats>1 el p95 de un escenario con presupuesto es el MEJOR de
    varias mediciones: una pausa del GC no puede declararse regresión."""
    data = latency.run_benchmark(iterations=40, rounds=1, repeats=3)
    fila = next(r for r in data["results"] if r["scenario"] == "completo (inspección + rate limit)")
    assert fila["p95_repeats"] == 3, "debe registrar que el p95 se filtró"
    # el p95 filtrado nunca es peor que el p50 (una mediana es un percentil real)
    assert fila["p95_us"] >= fila["p50_us"]


def test_todo_escenario_con_presupuesto_tiene_escenario_real():
    """Un presupuesto que apunta a un nombre de escenario inexistente sería un
    guard que nunca revisa nada."""
    nombres = {nombre for nombre, _, _ in latency.scenarios()}
    for nombre in latency.CHECK_BUDGET_US:
        assert nombre in nombres, f"el presupuesto '{nombre}' no corresponde a ningún escenario"
