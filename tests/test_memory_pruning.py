import numpy as np
import pytest
from AfterImage import incStatDB


def test_incstatdb_prune_inactive_retention():
    # Inicializamos la DB con poda cada 500 registros y umbral w_eps = 1e-3
    db = incStatDB(limit=10000, prune_interval=500, w_eps=1e-3)

    # 1. Registramos 100 flujos en t = 0 con Lambda = 5.0 y peso activo inicial w = 1.0
    for i in range(100):
        s = db.register(ID=f"stale_host_{i}", Lambda=5.0, init_time=0.0)
        s.w = 1.0

    assert len(db.HT) == 100

    # 2. Pasamos a t = 10.0 segundos y registramos un flujo activo con tráfico real
    active_s = db.register(ID="active_host", Lambda=5.0, init_time=10.0)
    active_s.w = 1.0
    assert len(db.HT) == 101

    # 3. Forzamos la poda manual en t = 10.0
    pruned_count = db.prune_inactive(cur_time=10.0)

    # Los 100 flujos antiguos con decaimiento 2^(-5*10) se purgan; el activo permanece
    assert pruned_count == 100
    assert len(db.HT) == 1
    assert "active_host_5.0" in db.HT


def test_incstatdb_emergency_pruning_on_limit():
    # Límite estricto de 50 entradas
    db = incStatDB(limit=50, prune_interval=None, w_eps=1e-3)

    # Llenamos con 50 flujos en t = 0 con peso activo
    for i in range(50):
        s = db.register(ID=f"host_{i}", Lambda=5.0, init_time=0.0)
        s.w = 1.0

    assert len(db.HT) == 50

    # En t = 5.0 segundos registramos el flujo número 51.
    # Debe activarse la poda de emergencia al detectar que las 50 anteriores decayeron
    new_inc = db.register(ID="new_host", Lambda=5.0, init_time=5.0)

    assert new_inc is not None
    assert len(db.HT) == 1
    assert "new_host_5.0" in db.HT