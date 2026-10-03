import sys
from pathlib import Path
import pytest
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from KitNET.corClust import corClust


def test_corclust_initialization():
    """Valida la instanciación del agrupamiento correlacional."""
    n_features = 10
    cc = corClust(n_features)
    assert cc.n == n_features


def test_corclust_clustering_size_bound():
    """Comprueba que el dendrograma agrupe las características respetando la cota m."""
    n_features = 12
    max_cluster_size = 4
    cc = corClust(n_features)

    np.random.seed(1337)
    for _ in range(40):
        dummy_vector = np.random.randn(n_features)
        cc.update(dummy_vector)

    clusters = cc.cluster(max_cluster_size)

    # Cada cluster debe ser <= max_cluster_size
    for cluster in clusters:
        assert len(cluster) <= max_cluster_size
        assert len(cluster) > 0

    # Todas las dimensiones deben quedar asignadas exactamente una vez
    flat = [feat for cl in clusters for feat in cl]
    assert len(flat) == n_features
    assert set(flat) == set(range(n_features))