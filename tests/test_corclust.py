"""
Módulo de pruebas deterministas para el agrupador jerárquico incremental (corClust).
Valida la convergencia de la matriz de distancias D y la cota dimensional m <= 10.
"""

import sys
from pathlib import Path
import pytest
import numpy as np

# Inclusión determinista de rutas locales (raíz, submódulo KitNET y src modular)
REPO_ROOT = Path(__file__).resolve().parent.parent
KITNET_DIR = REPO_ROOT / "KitNET"
SRC_DIR = REPO_ROOT / "src"

for path_entry in (REPO_ROOT, KITNET_DIR, SRC_DIR):
    if path_entry.exists() and str(path_entry) not in sys.path:
        sys.path.insert(0, str(path_entry))

# Resolución agnóstica de importación para soportar layouts legacy y empaquetados modernos
try:
    from KitNET.corClust import corClust
except ModuleNotFoundError:
    try:
        from kitsune.corClust import corClust
    except ModuleNotFoundError:
        from corClust import corClust


def test_corclust_cota_rigida():
    """
    Aserta que corClust particiona el espacio de características R^100 garantizando:
    1. Ningún subespacio excede la cota de complejidad m <= 10.
    2. La unión de subespacios preserva la totalidad de dimensiones (n = 100).
    3. Ninguna dimensión queda huérfana o duplicada en el mapeo resultante.
    """
    m_limit: int = 10
    n_features: int = 100
    n_warmup_samples: int = 50

    # 1. Arrange: Inicialización de la matriz de distancias
    clusterer = corClust(n_features)

    # 2. Inyección controlada de tráfico para evitar división por cero en residuos
    # Semilla fija para garantizar reproducibilidad exacta en CI
    rng = np.random.default_rng(seed=42)
    for _ in range(n_warmup_samples):
        synthetic_vector = rng.standard_normal(n_features)
        clusterer.update(synthetic_vector)

    # 3. Act: Ejecución del agrupamiento jerárquico aglomerativo sobre D
    mapping = clusterer.cluster(m_limit)

    # 4. Assert: Validación estructural y matemática
    assert isinstance(mapping, list), "El mapeo de características debe ser una lista de subespacios."
    assert len(mapping) > 0, "El mapeo devuelto no puede estar vacío."

    mapped_dimensions = []
    for idx, cluster_indices in enumerate(mapping):
        # Verificación estricta de la cota m <= 10 (Sección IV-C y IV-E)
        assert len(cluster_indices) <= m_limit, (
            f"Violación de cota en cluster {idx}: contiene {len(cluster_indices)} "
            f"dimensiones (máximo permitido: {m_limit})."
        )
        assert len(cluster_indices) > 0, f"El cluster {idx} está vacío."
        mapped_dimensions.extend(cluster_indices)

    # Comprobación de cobertura exacta: 100 dimensiones asignadas sin solapamiento
    assert len(mapped_dimensions) == n_features, (
        f"Inconsistencia en número de dimensiones: se mapearon {len(mapped_dimensions)} "
        f"de las {n_features} esperadas."
    )
    assert len(set(mapped_dimensions)) == n_features, (
        "Existen dimensiones duplicadas o solapadas entre diferentes autoencoders."
    )


def test_corclust_dimensiones_invalidas():
    """Valida que el agrupador rechace vectores con dimensiones discrepantes."""
    clusterer = corClust(n=100)
    vector_invalido = np.zeros(50)

    # Debe arrojar excepción al no coincidir con el n configurado
    with pytest.raises((ValueError, IndexError, AssertionError)):
        clusterer.update(vector_invalido)