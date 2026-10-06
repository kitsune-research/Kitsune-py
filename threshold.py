"""
Kitsune Dynamic Thresholding & Statistical Anomaly Scoring Engine.

Implements the log-normal tail estimation described in NDSS 2018 (Section IV-D).
Translates continuous reconstruction RMSE signals into calibrated binary alerts
while remaining resilient to early SGD numerical transients.
"""

from typing import Tuple, Dict, Any
import numpy as np


def fit_lognormal_baseline(
    scores: np.ndarray,
    burn_in: int = 1000,
    eps: float = 1e-12
) -> Tuple[float, float]:
    """
    Fits a log-normal distribution to the post-convergence benign RMSE scores.

    Parameters
    ----------
    scores : np.ndarray
        1D array of RMSE scores observed during benign/training execution.
    burn_in : int
        Number of initial samples to discard to avoid SGD convergence spikes
        (e.g., artifact at packet #2543).
    eps : float
        Small numerical floor to prevent log(0).

    Returns
    -------
    mu_log : float
        Mean of the log-transformed scores.
    sigma_log : float
        Standard deviation of the log-transformed scores.
    """
    valid_scores = np.asarray(scores, dtype=np.float64)
    if len(valid_scores) <= burn_in:
        raise ValueError(
            f"Insufficient samples ({len(valid_scores)}) to discard burn-in ({burn_in})."
        )
    
    clean_segment = valid_scores[burn_in:]
    clean_segment = np.clip(clean_segment, eps, None)
    
    log_scores = np.log(clean_segment)
    mu_log = float(np.mean(log_scores))
    sigma_log = float(np.std(log_scores))
    
    return mu_log, sigma_log


def calculate_lognormal_threshold(
    mu_log: float,
    sigma_log: float,
    k: float = 3.0902
) -> float:
    """
    Calculates analytical anomaly threshold tau:
        tau = exp(mu_log + k * sigma_log)

    Parameters
    ----------
    mu_log : float
        Mean of ln(RMSE) from benign baseline.
    sigma_log : float
        Standard deviation of ln(RMSE) from benign baseline.
    k : float
        Parametric sensitivity factor (default: 3.0902 for FPR <= 0.001).

    Returns
    -------
    tau : float
        Dynamic alert threshold in RMSE units.
    """
    if sigma_log < 0:
        raise ValueError("sigma_log must be non-negative.")
    return float(np.exp(mu_log + k * sigma_log))


def evaluate_detection_profile(
    scores: np.ndarray,
    threshold: float
) -> Dict[str, Any]:
    """
    Evaluates streaming scores against a calibrated threshold.

    Returns summary metrics including alert count, peak-to-threshold ratio (SNR),
    and anomaly boolean mask.
    """
    scores_arr = np.asarray(scores, dtype=np.float64)
    anomalies = scores_arr > threshold
    total_packets = len(scores_arr)
    alert_count = int(np.sum(anomalies))
    max_score = float(np.max(scores_arr)) if total_packets > 0 else 0.0
    
    snr_ratio = (max_score / threshold) if threshold > 0 else 0.0
    
    return {
        "threshold": threshold,
        "total_packets": total_packets,
        "alert_count": alert_count,
        "alert_rate": float(alert_count / total_packets) if total_packets > 0 else 0.0,
        "max_score": max_score,
        "snr_vs_threshold": snr_ratio,
        "anomalies": anomalies
    }