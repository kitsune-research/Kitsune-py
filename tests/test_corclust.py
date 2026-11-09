"""
Unit tests for Kitsune NIDS: corClust incremental hierarchical correlation clustering.
Verifies NDSS 2018 mathematical invariants:
- Online Pearson correlation matrix update (Eq. 9 & 10)
- Bounded cluster size constraint: max(|c_i|) <= m (strictly m <= 10)
- Disjoint and complete feature space partitioning (Eq. 7)

Architect: Tamamo-no-Mae (kitsune-research core)
"""
from __future__ import annotations

import numpy as np
import pytest

from KitNET.corClust import corClust


class TestCorClustInvariants:
    """Audit suite for corClust correlation distance and cluster bounding."""

    @pytest.fixture
    def synthetic_stream(self) -> np.ndarray:
        """Generate synthetic R^100 vectors with correlated sub-blocks."""
        np.random.seed(42)
        n_samples = 150
        n_features = 100

        # Crear 10 señales base para forzar correlaciones por bloques
        base_signals = np.random.randn(n_samples, 10)
        data = np.zeros((n_samples, n_features), dtype=np.float64)

        for i in range(n_features):
            block_idx = i // 10
            noise = np.random.randn(n_samples) * 0.05
            data[:, i] = base_signals[:, block_idx] + noise

        return data

    def test_cluster_size_strictly_bounded_by_m(self, synthetic_stream: np.ndarray) -> None:
        """Verify that cluster(m) guarantees max(|c_i|) <= m (NDSS 2018 invariant: m <= 10)."""
        n_features = synthetic_stream.shape[1]
        clusterer = corClust(n=n_features)

        for row in synthetic_stream:
            clusterer.update(row)

        for m_bound in [10, 7, 5]:
            # Invocación posicional para respetar la firma de corClust.py
            clusters = clusterer.cluster(m_bound)

            assert len(clusters) > 0, "Clustering returned empty cluster list"
            for idx, c in enumerate(clusters):
                assert len(c) <= m_bound, f"Cluster {idx} violated bound: {len(c)} > {m_bound}"
                assert len(c) >= 1, f"Cluster {idx} contains zero features"

    def test_complete_and_disjoint_partitioning(self, synthetic_stream: np.ndarray) -> None:
        """Verify that all n features are partitioned into mutually disjoint subsets."""
        n_features = synthetic_stream.shape[1]
        clusterer = corClust(n=n_features)

        for row in synthetic_stream:
            clusterer.update(row)

        # Invocación posicional del límite superior canónico m=10
        clusters = clusterer.cluster(10)

        flattened_features = []
        for c in clusters:
            flattened_features.extend(c)

        # 1. Partición completa: contiene exactamente todas las dimensiones 0..n-1
        assert sorted(flattened_features) == list(range(n_features)), "Feature partitioning is incomplete"

        # 2. Partición disjunta: cero solapamiento entre autoencoders
        assert len(flattened_features) == len(set(flattened_features)), "Detected overlapping features across clusters"

    def test_correlation_matrix_properties(self, synthetic_stream: np.ndarray) -> None:
        """Verify that the correlation distance matrix D has zero diagonal and valid distance bounds."""
        n_features = synthetic_stream.shape[1]
        clusterer = corClust(n=n_features)

        for row in synthetic_stream:
            clusterer.update(row)

        dist_matrix = clusterer.corrDist()

        # Diagonal idénticamente cero (distancia de un vector consigo mismo es 0)
        np.testing.assert_allclose(np.diag(dist_matrix), 0.0, atol=1e-5, err_msg="Diagonal of D is non-zero")

        # Simetría D_ij == D_ji
        np.testing.assert_allclose(dist_matrix, dist_matrix.T, atol=1e-5, err_msg="Distance matrix D is asymmetric")

        # Distancia finita y acotada en [0, 2]
        assert np.isfinite(dist_matrix).all(), "Distance matrix contains NaN or Inf"
        assert (dist_matrix >= -1e-5).all(), "Distance matrix contains negative values"
        assert (dist_matrix <= 2.0 + 1e-5).all(), "Correlation distance exceeded theoretical maximum of 2.0"
