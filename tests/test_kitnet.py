"""
Módulo de pruebas deterministas para el ensamble de autoencoders (KitNET).
Valida la transición de períodos de gracia (FM/AD), entrenamiento online (SGD)
y la generación del error de reconstrucción residual (RMSE).
"""

import sys
from pathlib import Path
import pytest
import numpy as np

# Inclusión estricta de la raíz del repo
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from KitNET.KitNET import KitNET


def test_kitnet_lifecycle_and_inference():
    """
    Verifica el ciclo de vida completo de KitNET:
    1. Fase FM (Feature Mapping): acumulación correlacional previa al clustering.
    2. Fase AD (Anomaly Detection): SGD online estricto de pasada única (max_iter = 1).
    3. Fase Exec (Inferencia pura): cálculo del error residual RMSE > 0 ante outliers.
    """
    n_features: int = 100
    max_ae_size: int = 10
    fm_grace: int = 20
    ad_grace: int = 30

    # 1. Arrange: Corrección del parámetro m -> max_autoencoder_size
    kit = KitNET(
        n=n_features,
        max_autoencoder_size=max_ae_size,
        FM_grace_period=fm_grace,
        AD_grace_period=ad_grace,
        learning_rate=0.1,
        hidden_ratio=0.75,
    )

    rng = np.random.default_rng(seed=1337)
    benign_baseline = rng.standard_normal((fm_grace + ad_grace, n_features))

    # 2. Act & Assert: Consumo de FM_grace_period (agrupamiento inicial)
    for i in range(fm_grace):
        score = kit.process(benign_baseline[i])
        assert score == 0.0 or score is None or np.isnan(score) or isinstance(score, (int, float, np.floating)), (
            f"Comportamiento anómalo en FM grace period en muestra {i}: {score}"
        )

    # 3. Act & Assert: Consumo de AD_grace_period (entrenamiento online L1/L2)
    for i in range(fm_grace, fm_grace + ad_grace):
        score = kit.process(benign_baseline[i])
        assert isinstance(score, (int, float, np.floating)), (
            f"El score durante entrenamiento AD debe ser numérico en muestra {i}: {score}"
        )

    # 4. Act: Inferencia pura en modo ejecución (Exec-mode)
    unseen_benign = rng.standard_normal(n_features)
    anomaly_spike = rng.standard_normal(n_features) * 15.0 + 50.0

    score_benign = float(kit.process(unseen_benign))
    score_anomaly = float(kit.process(anomaly_spike))

    # 5. Assert: Propiedades del error de reconstrucción RMSE
    assert not np.isnan(score_benign), "El RMSE para tráfico benigno no puede ser NaN."
    assert not np.isinf(score_benign), "El RMSE para tráfico benigno no puede ser Inf."
    assert score_benign >= 0.0, f"El RMSE debe ser no negativo: obtenido {score_benign}"

    assert not np.isnan(score_anomaly), "El RMSE anómalo no puede ser NaN."
    assert not np.isinf(score_anomaly), "El RMSE anómalo no puede ser Inf."
    assert score_anomaly > 0.0, "La perturbación sintética debe inducir residuo estrictamente positivo."

    # Aserción de discriminación: el outlier debe sobresalir del suelo de ruido
    assert score_anomaly > score_benign, (
        f"Fallo de discriminación de anomalía: "
        f"Score anómalo ({score_anomaly:.6f}) no supera al benigno ({score_benign:.6f})"
    )


def test_kitnet_dimension_mismatch():
    """Verifica que KitNET intercepte vectores con dimensiones incongruentes."""
    kit = KitNET(
        n=100,
        max_autoencoder_size=10,
        FM_grace_period=5,
        AD_grace_period=5,
    )
    vector_erroneo = np.zeros(42)

    with pytest.raises((ValueError, IndexError, AssertionError)):
        kit.process(vector_erroneo)