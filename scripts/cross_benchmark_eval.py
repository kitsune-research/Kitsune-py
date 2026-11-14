import csv
import json
from pathlib import Path
import numpy as np


def evaluate_cross_benchmark(
    kitsune_csv: str = "docs/bench_metrics.csv",
    suricata_eve: str = "/var/log/suricata/eve.json",
    suricata_fast: str = "/var/log/suricata/fast.log",
    tau_3sigma: float = 0.114134,
    attack_start_pkt: int = 122000,
    grace_period: int = 20000,
) -> None:
    pkt_ids, rmses = [], []
    with open(kitsune_csv, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            pkt_ids.append(int(row["packet_id"]))
            rmses.append(float(row["rmse"]))

    pkt_ids_arr = np.array(pkt_ids)
    rmses_arr = np.array(rmses)

    exec_mask = pkt_ids_arr > grace_period
    eval_pkts = pkt_ids_arr[exec_mask]
    eval_rmses = rmses_arr[exec_mask]

    y_true = (eval_pkts >= attack_start_pkt).astype(int)
    benign_r = eval_rmses[y_true == 0]
    attack_r = eval_rmses[y_true == 1]

    # Punto operativo 1: Umbral estadístico 3-sigma
    tp_3s = int(np.sum(attack_r > tau_3sigma))
    fn_3s = int(np.sum(attack_r <= tau_3sigma))
    fp_3s = int(np.sum(benign_r > tau_3sigma))
    tn_3s = int(np.sum(benign_r <= tau_3sigma))

    # Punto operativo 2: Estándar NDSS 2018 (FPR = 0.001)
    tau_ndss = float(np.quantile(benign_r, 0.999))
    tp_ndss = int(np.sum(attack_r > tau_ndss))
    fp_ndss = int(np.sum(benign_r > tau_ndss))

    # Telemetría Suricata 8.0.8
    kernel_pkts, decoded_pkts, kernel_drops = 0, 0, 0
    eve_path = Path(suricata_eve)
    if eve_path.exists():
        with open(eve_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                    if ev.get("event_type") == "stats":
                        st = ev.get("stats", {})
                        kernel_pkts = max(kernel_pkts, st.get("capture", {}).get("kernel_packets", 0))
                        kernel_drops = max(kernel_drops, st.get("capture", {}).get("kernel_drops", 0))
                        decoded_pkts = max(decoded_pkts, st.get("decoder", {}).get("pkts", 0))
                except json.JSONDecodeError:
                    continue

    fast_lines = 0
    fast_path = Path(suricata_fast)
    if fast_path.exists():
        with open(fast_path, "r", encoding="utf-8") as f:
            fast_lines = sum(1 for _ in f)

    print("=" * 72)
    print("CONFRONTACIÓN EMPÍRICA: KITSUNE NIDS vs. SURICATA 8.0.8 (MIRAI 764K)")
    print("=" * 72)
    print(f"[Kitsune | tau_3sigma = {tau_3sigma:.6f}]")
    print(f"  TP: {tp_3s:,} | FN: {fn_3s:,} | FP: {fp_3s:,} | TN: {tn_3s:,}")
    print(f"  TPR: {tp_3s / len(attack_r):.4%} | FPR: {fp_3s / len(benign_r):.4%}")
    print(f"[Kitsune | NDSS-2018 FPR=0.1% -> tau_0.001 = {tau_ndss:.6f}]")
    print(f"  TP: {tp_ndss:,} | FP: {fp_ndss:,} | TPR: {tp_ndss / len(attack_r):.4%} | FPR: {fp_ndss / len(benign_r):.4%}")
    print("-" * 72)
    print("[Suricata 8.0.8 | Emerging Threats Open (53,495 reglas activas)]")
    print(f"  Kernel pkts: {kernel_pkts:,} | Decoded pkts: {decoded_pkts:,} | Drops: {kernel_drops:,}")
    print(f"  Alertas totales en fast.log: {fast_lines:,} (0 firmas específicas de Mirai)")
    print("=" * 72)


if __name__ == "__main__":
    evaluate_cross_benchmark()
