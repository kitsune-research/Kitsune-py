import numpy as np
import pytest
from threshold import (
    calculate_lognormal_threshold,
    evaluate_detection_profile,
    fit_lognormal_baseline,
)


def test_fit_lognormal_baseline_numerical_stability():
    np.random.seed(1337)
    true_mu = -2.0
    true_sigma = 0.5
    raw_samples = np.random.lognormal(mean=true_mu, sigma=true_sigma, size=3000)
    
    # Inyectamos una perturbación numérica masiva simulando el artefacto de SGD
    raw_samples[250] = 750.0
    
    mu_est, sigma_est = fit_lognormal_baseline(raw_samples, burn_in=1000)
    assert pytest.approx(true_mu, abs=0.08) == mu_est
    assert pytest.approx(true_sigma, abs=0.08) == sigma_est


def test_calculate_lognormal_threshold_fpr_calibration():
    np.random.seed(42)
    mu = -2.0425
    sigma = 0.5005
    k_target = 3.0902  # Cuantil normal para FPR = 0.001
    tau = calculate_lognormal_threshold(mu, sigma, k=k_target)
    
    benign_eval = np.random.lognormal(mean=mu, sigma=sigma, size=50000)
    empirical_fpr = np.mean(benign_eval > tau)
    
    # Debe converger rigurosamente en torno al límite de NDSS 2018
    assert 0.0005 <= empirical_fpr <= 0.0020


def test_evaluate_detection_profile_snr_separation():
    scores = np.array([0.1, 0.12, 0.15, 0.4, 0.55, 11.2944])
    tau = 0.58
    
    res = evaluate_detection_profile(scores, threshold=tau)
    assert res["total_packets"] == 6
    assert res["alert_count"] == 1
    assert res["max_score"] == 11.2944
    assert res["snr_vs_threshold"] > 19.0