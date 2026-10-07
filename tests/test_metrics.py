import pytest
import numpy as np
from metrics import compute_roc_metrics


def test_compute_roc_metrics_perfect_separation():
    # 10.000 paquetes benignos bajos, 5.000 paquetes maliciosos altos
    y_true = np.array([0] * 10000 + [1] * 5000)
    y_scores = np.concatenate([
        np.random.normal(loc=0.1, scale=0.02, size=10000),
        np.random.normal(loc=0.9, scale=0.05, size=5000)
    ])
    
    res = compute_roc_metrics(y_true, y_scores)
    assert res["n_packets"] == 15000
    assert res["n_pos"] == 5000
    assert res["n_neg"] == 10000
    assert res["auc"] == pytest.approx(1.0, abs=1e-4)
    assert res["tpr_at_fpr_001"] == pytest.approx(1.0, abs=1e-3)
    assert res["fnr_at_fpr_001"] == pytest.approx(0.0, abs=1e-3)
    assert res["eer"] == pytest.approx(0.0, abs=1e-3)


def test_compute_roc_metrics_input_validation():
    with pytest.raises(ValueError, match="identical length"):
        compute_roc_metrics(np.array([0, 1]), np.array([0.5]))
        
    with pytest.raises(ValueError, match="both benign"):
        compute_roc_metrics(np.array([0, 0, 0]), np.array([0.1, 0.2, 0.3]))