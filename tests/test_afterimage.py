import math
import sys
from pathlib import Path
import pytest
import numpy as np

# Inclusión de la raíz del repo para resolución de módulos legacy/raíz
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import AfterImage
from AfterImage import incStat, incStatDB


def test_afterimage_module_exports():
    """Comprueba que las clases del motor incremental estén disponibles."""
    assert hasattr(AfterImage, "incStat")
    assert hasattr(AfterImage, "incStatDB")
    assert hasattr(AfterImage, "incStat_cov")


def test_incstat_exponential_decay():
    """Valida el decaimiento temporal gamma = 2^(-lambda * dt)."""
    decay_lambda = 0.1
    t0 = 1000.0
    t1 = 1010.0  # dt = 10s -> factor gamma = 2^(-1) = 0.5

    stat = incStat(decay_lambda, "stream_test", init_time=t0)
    stat.insert(100.0, t0)

    # Inserción tras salto temporal dt=10s
    stat.insert(100.0, t1)

    # w esperado: (1.0 * 0.5) + 1.0 = 1.5
    expected_weight = (1.0 * (2.0 ** (-decay_lambda * 10.0))) + 1.0
    assert pytest.approx(stat.w, rel=1e-4) == expected_weight


def test_incstat_1d_statistics():
    """Valida la consistencia de media y varianza amortiguada."""
    stat = incStat(0.01, "stream_1d", init_time=0.0)
    values = [10.0, 20.0, 30.0, 40.0, 50.0]

    for i, val in enumerate(values):
        stat.insert(val, float(i * 0.1))

    mean_val = stat.mean()
    var_val = stat.var()

    assert mean_val > 0.0
    assert var_val >= 0.0
    assert pytest.approx(stat.std(), rel=1e-4) == math.sqrt(var_val)


def test_incstatdb_initialization():
    """Comprueba que la base de datos de estadísticas se inicialice correctamente."""
    db = incStatDB(limit=100)
    assert db.limit == 100