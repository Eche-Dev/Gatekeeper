"""El benchmark debe poder ejecutarse siempre: si se rompe, se entera CI.

Y el comparador `--baseline` tiene que ser CREÍBLE en los dos sentidos:
aprobar una medición que no ha cambiado y detectar una que sí. Un comparador
que nunca señala nada es un adorno.
"""

import importlib.util
import json
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
    el percentil es una muestra real, no un promedio entre dos."""
    muestras = [float(n) for n in range(1, 101)]  # 1..100
    assert latency.percentile(muestras, 0) == 1.0
    assert latency.percentile(muestras, 100) == 100.0
    assert latency.percentile(muestras, 95) == 95.0
    # el 50 cae en el índice 49 o 50 según el redondeo; los dos son válidos
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
    # repeats=1 para que el overhead sea directamente p50 - p50 de la base
    # (con repeats>1 se sustituye por la mediana de varias rondas).
    data = latency.run_benchmark(iterations=20, rounds=1, repeats=1)
    base, inspeccion = data["results"][0], data["results"][2]
    assert base["scenario"] == "sin middleware (base)"
    assert inspeccion["overhead_p50_us"] == pytest.approx(
        inspeccion["p50_us"] - base["p50_us"], abs=0.02
    )
    assert inspeccion["overhead_p95_us"] == pytest.approx(
        inspeccion["p95_us"] - base["p95_us"], abs=0.02
    )


def test_repeats_filtra_el_ruido_del_sistema():
    """Con repeats>1 el overhead es la MEDIANA de varias mediciones: una pausa
    del GC afecta una ronda y la mediana la ignora; una regresión las afecta a
    todas y la mediana la conserva."""
    data = latency.run_benchmark(iterations=40, rounds=1, repeats=3)
    fila = next(r for r in data["results"] if r["scenario"] == "completo (inspección + rate limit)")
    assert fila["overhead_repeats"] == 3


# ------------------------------------------ el comparador --baseline


def _medicion_falsa(overheads: dict[str, float]) -> dict:
    """Una medición sintética con los overheads dados (no mide nada)."""
    return {
        "results": [
            {"scenario": "sin middleware (base)", "p50_us": 12.0, "overhead_p50_us": 0.0}
        ] + [
            {"scenario": nombre, "p50_us": 12.0 + overhead, "overhead_p50_us": overhead}
            for nombre, overhead in overheads.items()
        ]
    }


def test_el_comparador_aprueba_lo_que_no_cambio():
    antes = _medicion_falsa({"completo (inspección + rate limit)": 100.0})
    ahora = _medicion_falsa({"completo (inspección + rate limit)": 105.0})
    ok, fallos = latency.comparar(antes, ahora)
    assert ok, f"un +5 % no es una regresión: {fallos}"


def test_el_comparador_detecta_una_regresion_real():
    antes = _medicion_falsa({"completo (inspección + rate limit)": 100.0})
    ahora = _medicion_falsa({"completo (inspección + rate limit)": 180.0})
    ok, fallos = latency.comparar(antes, ahora, margen=0.25)
    assert not ok, "un +80 % tiene que ser una regresión"
    assert fallos and "overhead subió" in fallos[0]


def test_el_comparador_respeta_el_margen():
    antes = _medicion_falsa({"escenario": 100.0})
    ahora = _medicion_falsa({"escenario": 130.0})
    assert latency.comparar(antes, ahora, margen=0.50)[0], "con margen 50 % un +30 % pasa"
    assert not latency.comparar(antes, ahora, margen=0.10)[0], "con margen 10 % un +30 % falla"


def test_el_comparador_ignora_una_mejora():
    antes = _medicion_falsa({"escenario": 200.0})
    ahora = _medicion_falsa({"escenario": 100.0})
    ok, _ = latency.comparar(antes, ahora)
    assert ok, "mejorar nunca es una regresión"


def test_el_comparador_ignora_escenarios_nuevos_o_desconocidos():
    antes = _medicion_falsa({"escenario-a": 100.0})
    ahora = _medicion_falsa({"escenario-a": 100.0, "escenario-nuevo": 500.0})
    ok, _ = latency.comparar(antes, ahora)
    assert ok, "un escenario que no estaba en la base no se puede comparar"


def test_baseline_inexistente_falla_con_mensaje(tmp_path, capsys):
    assert latency.main(["--baseline", str(tmp_path / "nope.json"), "--iterations", "5",
                         "--rounds", "1"]) == 2
    assert "no existe" in capsys.readouterr().err


def test_save_y_baseline_redondean(tmp_path, capsys):
    """Guardar una medición y compararla consigo misma no debe inventar nada."""
    destino = tmp_path / "base.json"
    assert latency.main(["--iterations", "10", "--rounds", "1", "--save", str(destino),
                         "--baseline", str(destino)]) == 0
    assert destino.exists()
    datos = json.loads(destino.read_text(encoding="utf-8"))
    assert "results" in datos and datos["results"]


def test_no_hay_umbral_absoluto_en_el_codigo():
    """El guard de CI se descartó con datos: una máquina lenta produce un
    overhead mayor que una regresión real, así que un umbral fijo en µs solo
    podía dar falsos positivos. Si alguien reintroduce ese presupuesto, este
    test lo señala."""
    fuente = Path(latency.__file__).read_text(encoding="utf-8")
    assert "CHECK_BUDGET_US" not in fuente, "el umbral absoluto se descartó a propósito"
    assert "CHECK_OVERHEAD_US" not in fuente, "el umbral de overhead tampoco era fiable"
    assert "--check" not in fuente, "el veredicto es de quien ejecuta, no del pipeline"
