"""
Kitsune Evaluation & Forensic Metrics Engine.

Implements benchmark evaluation metrics described in NDSS 2018 (Section V-C):
- Confusion Matrix (TP, FP, TN, FN)
- TPR (True Positive Rate / Recall) and FNR (False Negative Rate) constrained at FPR <= 0.001
- Equal Error Rate (EER) and Area Under the ROC Curve (AUC)
"""

from typing import Dict, Any
import numpy as np


def _integrate_trapezoid(y: np.ndarray, x: np.ndarray) -> float:
    """
    Computes numerical integral via trapezoidal rule with NumPy 1.x and 2.x support.
    """
    if hasattr(np, "trapezoid"):
        return float(np.trapezoid(y, x))
    return float(np.trapz(y, x))


def compute_roc_metrics(
    y_true: np.ndarray,
    y_scores: np.ndarray
) -> Dict[str, Any]:
    """
    Computes streaming ROC curve arrays and summary metrics without external heavy dependencies.
    """
    y_true = np.asarray(y_true, dtype=np.int32)
    y_scores = np.asarray(y_scores, dtype=np.float64)
    
    if len(y_true) != len(y_scores):
        raise ValueError("y_true and y_scores must have identical length.")
    
    n_pos = int(np.sum(y_true == 1))
    n_neg = int(np.sum(y_true == 0))
    
    if n_pos == 0 or n_neg == 0:
        raise ValueError("Evaluation requires both benign (0) and malicious (1) instances.")
    
    # Ordenar scores descendentemente
    desc_indices = np.argsort(y_scores)[::-1]
    y_sorted = y_true[desc_indices]
    scores_sorted = y_scores[desc_indices]
    
    # Sumas acumuladas para TP y FP
    tps = np.cumsum(y_sorted == 1)
    fps = np.cumsum(y_sorted == 0)
    
    tpr_arr = tps / n_pos
    fpr_arr = fps / n_neg
    fnr_arr = 1.0 - tpr_arr
    
    # AUC mediante regla trapezoidal compatible con NumPy 2.x
    fpr_full = np.concatenate(([0.0], fpr_arr, [1.0]))
    tpr_full = np.concatenate(([0.0], tpr_arr, [1.0]))
    auc = _integrate_trapezoid(tpr_full, fpr_full)
    
    # 1. Métrica NDSS: TPR y FNR a FPR <= 0.001
    target_mask = np.where(fpr_arr <= 0.001)[0]
    if len(target_mask) > 0:
        idx_target = target_mask[-1]
        tpr_at_fpr_target = float(tpr_arr[idx_target])
        fnr_at_fpr_target = float(fnr_arr[idx_target])
        thresh_at_target = float(scores_sorted[idx_target])
    else:
        tpr_at_fpr_target = 0.0
        fnr_at_fpr_target = 1.0
        thresh_at_target = float(scores_sorted[0])
        
    # 2. Métrica NDSS: Equal Error Rate (EER)
    diff = np.abs(fpr_arr - fnr_arr)
    eer_idx = int(np.argmin(diff))
    eer = float((fpr_arr[eer_idx] + fnr_arr[eer_idx]) / 2.0)
    eer_thresh = float(scores_sorted[eer_idx])
    
    return {
        "n_packets": len(y_true),
        "n_pos": n_pos,
        "n_neg": n_neg,
        "auc": auc,
        "eer": eer,
        "eer_threshold": eer_thresh,
        "tpr_at_fpr_001": tpr_at_fpr_target,
        "fnr_at_fpr_001": fnr_at_fpr_target,
        "thresh_at_fpr_001": thresh_at_target
    }