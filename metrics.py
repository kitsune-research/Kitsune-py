"""
Kitsune Evaluation & Forensic Metrics Engine.

Implements benchmark evaluation metrics described in NDSS 2018 (Section V-C & Fig. 9):
- Confusion Matrix & Operational Operating Points
- TPR / FNR constrained at Zero False Positives (FPR = 0)
- TPR / FNR constrained at High-Confidence Threshold (FPR <= 0.001)
- Equal Error Rate (EER) via exact intersection
- Area Under the ROC Curve (AUC) via trapezoidal rule (NumPy 2.x resilient)

Architect: Tamamo-no-Mae (kitsune-research core)
"""

from __future__ import annotations

from typing import Any, Dict
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

    Args:
        y_true: Ground truth binary labels (0 = benign, 1 = malicious/anomaly).
        y_scores: Anomaly reconstruction scores (RMSE residue from KitNET).

    Returns:
        Dictionary containing AUC, EER, and operational operating points (FPR=0, FPR<=0.001).
    """
    y_true = np.asarray(y_true, dtype=np.int32)
    y_scores = np.asarray(y_scores, dtype=np.float64)

    if len(y_true) != len(y_scores):
        raise ValueError("y_true and y_scores must have identical length.")

    n_pos = int(np.sum(y_true == 1))
    n_neg = int(np.sum(y_true == 0))

    if n_pos == 0 or n_neg == 0:
        raise ValueError("Evaluation requires both benign (0) and malicious (1) instances.")

    # 1. Ordenar scores de mayor a menor (mayor residuo = mayor anomalía)
    desc_indices = np.argsort(y_scores)[::-1]
    y_sorted = y_true[desc_indices]
    scores_sorted = y_scores[desc_indices]

    # 2. Sumas acumuladas discretas para TP y FP
    tps = np.cumsum(y_sorted == 1)
    fps = np.cumsum(y_sorted == 0)

    tpr_arr = tps / n_pos
    fpr_arr = fps / n_neg
    fnr_arr = 1.0 - tpr_arr

    # 3. AUC mediante regla trapezoidal
    # Asegurar frontera formal [0, 0] y [1, 1]
    fpr_curve = np.concatenate(([0.0], fpr_arr))
    tpr_curve = np.concatenate(([0.0], tpr_arr))
    auc = _integrate_trapezoid(tpr_curve, fpr_curve)

    # 4. Métrica NDSS: Punto de corte en FPR = 0 (Separación pura sobre el suelo de ruido)
    zero_fpr_mask = np.where(fpr_arr == 0.0)[0]
    if len(zero_fpr_mask) > 0:
        idx_zero = zero_fpr_mask[-1]
        tpr_at_fpr_0 = float(tpr_arr[idx_zero])
        fnr_at_fpr_0 = float(fnr_arr[idx_zero])
        thresh_at_fpr_0 = float(scores_sorted[idx_zero])
        tp_at_fpr_0 = int(tps[idx_zero])
    else:
        tpr_at_fpr_0 = 0.0
        fnr_at_fpr_0 = 1.0
        thresh_at_fpr_0 = float(scores_sorted[0])
        tp_at_fpr_0 = 0

    # 5. Métrica NDSS: Punto de corte en FPR <= 0.001 (Alta certeza / bajo FP)
    target_mask = np.where(fpr_arr <= 0.001)[0]
    if len(target_mask) > 0:
        idx_target = target_mask[-1]
        tpr_at_fpr_001 = float(tpr_arr[idx_target])
        fnr_at_fpr_001 = float(fnr_arr[idx_target])
        thresh_at_fpr_001 = float(scores_sorted[idx_target])
        tp_at_fpr_001 = int(tps[idx_target])
    else:
        tpr_at_fpr_001 = 0.0
        fnr_at_fpr_001 = 1.0
        thresh_at_fpr_001 = float(scores_sorted[0])
        tp_at_fpr_001 = 0

    # 6. Métrica NDSS: Equal Error Rate (EER donde FPR ≈ FNR)
    diff = np.abs(fpr_arr - fnr_arr)
    eer_idx = int(np.argmin(diff))
    eer = float((fpr_arr[eer_idx] + fnr_arr[eer_idx]) / 2.0)
    eer_thresh = float(scores_sorted[eer_idx])

    return {
        "n_packets": len(y_true),
        "n_pos": n_pos,
        "n_neg": n_neg,
        "auc": float(auc),
        "eer": eer,
        "eer_threshold": eer_thresh,
        # Métricas a FPR = 0 (Paper Fig. 9 - Top)
        "tpr_at_fpr_0": tpr_at_fpr_0,
        "fnr_at_fpr_0": fnr_at_fpr_0,
        "thresh_at_fpr_0": thresh_at_fpr_0,
        "tp_at_fpr_0": tp_at_fpr_0,
        # Métricas a FPR <= 0.001 (Paper Fig. 9 - Middle)
        "tpr_at_fpr_001": tpr_at_fpr_001,
        "fnr_at_fpr_001": fnr_at_fpr_001,
        "thresh_at_fpr_001": thresh_at_fpr_001,
        "tp_at_fpr_001": tp_at_fpr_001,
    }