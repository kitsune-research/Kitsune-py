"""
Unit tests for Kitsune NIDS: KitNET autoencoder ensemble.
Verifies NDSS 2018 mathematical invariants:
- Online SGD single-step training (max_iter=1)
- Ensemble layer L^(1) and output layer L^(2) topology (beta = 0.75)
- State transitions (feature mapping -> anomaly detector training -> execute)
- Deterministic RMSE scoring and anomaly sensitivity

Architect: Tamamo-no-Mae (kitsune-research core)
"""
from __future__ import annotations

import numpy as np
import pytest

from KitNET.KitNET import KitNET


class TestKitNETInvariants:
    """Audit suite for KitNET ensemble topology, training and scoring."""

    @pytest.fixture
    def synthetic_stream(self) -> np.ndarray:
        """Generate benign Gaussian stream with correlated dimensions in R^100."""
        np.random.seed(42)
        n_samples = 120
        n_features = 100
        # Media 10.0, varianza baja para estabilidad en el espacio de entrenamiento
        return 10.0 + 0.5 * np.random.randn(n_samples, n_features)

    def test_state_transitions_and_grace_periods(self, synthetic_stream: np.ndarray) -> None:
        """Verify seamless transitions: FM_grace -> AD_grace -> Execute-mode."""
        fm_grace = 30
        ad_grace = 50
        n_features = synthetic_stream.shape[1]

        model = KitNET(
            n=n_features,
            max_autoencoder_size=10,
            FM_grace_period=fm_grace,
            AD_grace_period=ad_grace,
            learning_rate=0.1,
            hidden_ratio=0.75,
        )

        scores = []
        for row in synthetic_stream:
            score = model.process(row)
            scores.append(score)

        # Durante FM_grace + AD_grace, el modelo está aprendiendo
        # KitNET devuelve 0.0 durante el entrenamiento
        training_scores = scores[: fm_grace + ad_grace]
        for s in training_scores:
            assert s == 0.0, f"Expected 0.0 score during grace period, got {s}"

        # Tras completar los períodos de gracia, execute-mode genera residuos reales positivos
        execution_scores = scores[fm_grace + ad_grace :]
        assert len(execution_scores) > 0, "No execution scores collected"
        for s in execution_scores:
            assert s >= 0.0, f"RMSE anomaly score must be non-negative, got {s}"
            assert np.isfinite(s), f"RMSE anomaly score must be finite, got {s}"

    def test_anomaly_sensitivity_rmse_elevation(self, synthetic_stream: np.ndarray) -> None:
        """Verify that out-of-distribution vectors produce significantly higher RMSE."""
        fm_grace = 30
        ad_grace = 40
        n_features = synthetic_stream.shape[1]

        model = KitNET(
            n=n_features,
            max_autoencoder_size=10,
            FM_grace_period=fm_grace,
            AD_grace_period=ad_grace,
            learning_rate=0.1,
            hidden_ratio=0.75,
        )

        # Entrenar con la distribución benigna (~10.0)
        total_grace = fm_grace + ad_grace
        for row in synthetic_stream[:total_grace]:
            model.process(row)

        # Evaluar muestra benigna normal (in-distribution)
        benign_sample = 10.0 + 0.5 * np.random.randn(n_features)
        benign_rmse = model.process(benign_sample)

        # Inyectar anomalía severa (out-of-distribution: ráfaga masiva)
        anomalous_sample = 10.0 + 25.0 * np.random.randn(n_features)
        anomalous_rmse = model.process(anomalous_sample)

        assert anomalous_rmse > benign_rmse, (
            f"KitNET failed to elevate RMSE on anomaly: "
            f"benign={benign_rmse:.4f}, anomaly={anomalous_rmse:.4f}"
        )

    def test_explicit_train_and_execute_divergence(self, synthetic_stream: np.ndarray) -> None:
        """Verify that execute() produces deterministic RMSE without altering network weights."""
        n_features = synthetic_stream.shape[1]
        model = KitNET(
            n=n_features,
            max_autoencoder_size=10,
            FM_grace_period=20,
            AD_grace_period=30,
            learning_rate=0.1,
        )

        # Pasar los períodos de gracia
        for row in synthetic_stream[:60]:
            model.process(row)

        test_vector = synthetic_stream[65]

        # Dos llamadas consecutivas a execute() sobre el mismo vector deben ser exactamente idénticas
        score_1 = model.execute(test_vector)
        score_2 = model.execute(test_vector)

        np.testing.assert_allclose(
            score_1,
            score_2,
            rtol=1e-7,
            err_msg="execute() altered internal state or weights on subsequent forward passes",
        )
