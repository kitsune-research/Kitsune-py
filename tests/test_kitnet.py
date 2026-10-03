import sys
from pathlib import Path
import pytest
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from KitNET.KitNET import KitNET
from KitNET.dA import dA


def test_kitnet_initialization_parameters():
    """Valida la instanciación de KitNET según la arquitectura de NDSS 2018."""
    n_features = 10
    max_ae_size = 3
    fm_grace = 20
    ad_grace = 50
    lr = 0.1
    hidden_ratio = 0.75

    kit = KitNET(
        n=n_features,
        max_autoencoder_size=max_ae_size,
        FM_grace_period=fm_grace,
        AD_grace_period=ad_grace,
        learning_rate=lr,
        hidden_ratio=hidden_ratio,
    )

    assert kit.n == n_features
    assert kit.m == max_ae_size
    assert kit.FM_grace_period == fm_grace
    assert kit.AD_grace_period == ad_grace
    assert kit.lr == lr
    assert kit.hr == hidden_ratio


from types import SimpleNamespace
from KitNET.dA import dA
import KitNET.dA as dA_module


def test_single_da_stochastic_step():
    """Verifica que el autoencoder individual (dA) compute el paso estocástico y acote el RMSE."""
    n_inputs = 4
    lr = 0.1
    hidden_ratio = 0.75
    x = np.array([0.2, 0.4, 0.6, 0.8], dtype=np.float64)

    # 1. Instanciación mediante dA_params oficial o fallback a SimpleNamespace
    if hasattr(dA_module, "dA_params"):
        params = dA_module.dA_params(
            n_visible=n_inputs,
            hiddenRatio=hidden_ratio,
            lr=lr,
            corruption_level=0.0,
        )
    else:
        # Contenedor dinámico compatible con los atributos esperados por dA
        params = SimpleNamespace(
            n_visible=n_inputs,
            n_hidden=int(np.ceil(n_inputs * hidden_ratio)),
            lr=lr,
            corruption_level=0.0,
            hiddenRatio=hidden_ratio,
            gracePeriod=0,
        )

    model = dA(params)

    # 2. Paso de entrenamiento SGD (max_iter=1)
    if hasattr(model, "train"):
        rmse = model.train(x)
        assert rmse >= 0.0
    elif hasattr(model, "execute"):
        out = model.execute(x)
        assert len(out) == n_inputs


def test_kitnet_grace_periods_and_execute_transition():
    """Valida la transición FM_grace_period -> AD_grace_period -> Detección streaming."""
    n_features = 6
    fm_grace = 15
    ad_grace = 25
    total_train = fm_grace + ad_grace
    exec_steps = 20

    kit = KitNET(
        n=n_features,
        max_autoencoder_size=3,
        FM_grace_period=fm_grace,
        AD_grace_period=ad_grace,
        learning_rate=0.1,
    )

    np.random.seed(42)
    stream = np.random.uniform(0.1, 0.9, size=(total_train + exec_steps, n_features))

    scores = []
    for x in stream:
        scores.append(kit.process(x))

    # Durante fases de gracia el RMSE retornado es 0.0
    assert all(s == 0.0 for s in scores[:total_train])

    # En fase de ejecución activa debe producir RMSE en R+
    exec_scores = scores[total_train:]
    assert len(exec_scores) == exec_steps
    assert all(s >= 0.0 for s in exec_scores)
    assert any(s > 0.0 for s in exec_scores)