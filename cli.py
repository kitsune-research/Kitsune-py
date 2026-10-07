import argparse
import os
from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np

from Kitsune import Kitsune
from metrics import compute_roc_metrics


def run_pipeline(
    path: str,
    packet_limit: int,
    max_autoencoder_size: int,
    fm_grace: int,
    ad_grace: int,
    output_csv: str,
    output_plot: str,
) -> None:
    if not os.path.exists(path):
        print(f"[!] Error: El archivo no existe: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Inicializando Kitsune sobre: {path}")
    print(
        f"[*] Parámetros: max_ae={max_autoencoder_size}, FMgrace={fm_grace}, ADgrace={ad_grace}"
    )

    K = Kitsune(
        file_path=path,
        limit=packet_limit,
        max_autoencoder_size=max_autoencoder_size,
        FM_grace_period=fm_grace,
        AD_grace_period=ad_grace,
    )

    rmse_scores = []
    count = 0
    print("[*] Procesando paquetes...")

    while True:
        rmse = K.proc_next_packet()
        if rmse == -1:
            break
        rmse_scores.append(rmse)
        count += 1
        if count % 1000 == 0:
            print(f"    Procesados {count} paquetes...")

    print(f"[+] Finalizado. Total de paquetes analizados: {len(rmse_scores)}")

    if output_csv:
        np.savetxt(
            output_csv, rmse_scores, delimiter=",", header="rmse", comments=""
        )
        print(f"[+] Scores guardados en: {output_csv}")

    if output_plot:
        plt.figure(figsize=(10, 4))
        plt.plot(
            rmse_scores, label="RMSE Score", color="crimson", linewidth=0.8
        )
        plt.axvline(
            x=fm_grace + ad_grace,
            color="gray",
            linestyle="--",
            label="Fin de entrenamiento",
        )
        plt.title("Kitsune NIDS - Puntuación de Anomalía (RMSE)")
        plt.xlabel("Índice de Paquete")
        plt.ylabel("RMSE")
        plt.legend(loc="upper right")
        plt.grid(True, linestyle=":", alpha=0.6)
        plt.tight_layout()
        plt.savefig(output_plot, dpi=300)
        plt.close()
        print(f"[+] Gráfica exportada a: {output_plot}")


def run_eval(args: argparse.Namespace) -> None:
    """Executes forensic evaluation following NDSS 2018 Section V-C criteria."""
    scores_file = Path(args.scores)
    labels_file = Path(args.labels)

    if not scores_file.exists():
        print(
            f"[-] Error: Scores file '{scores_file}' not found.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not labels_file.exists():
        print(
            f"[-] Error: Labels file '{labels_file}' not found.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[*] Loading anomaly scores from: {scores_file}")
    y_scores = np.loadtxt(scores_file, delimiter=",", dtype=np.float64)

    print(f"[*] Loading ground truth labels from: {labels_file}")
    y_true = np.loadtxt(labels_file, delimiter=",", dtype=np.int32)

    try:
        report = compute_roc_metrics(y_true, y_scores)
    except ValueError as err:
        print(f"[-] Evaluation Error: {err}", file=sys.stderr)
        sys.exit(1)

    # Reporte Forense Estructurado (NDSS 2018 Sec. V-C)
    print("\n" + "=" * 62)
    print(" KITSUNE NIDS: FORENSIC EVALUATION REPORT (NDSS 2018 Sec. V-C)")
    print("=" * 62)
    print(f" Total evaluated packets : {report['n_packets']:,}")
    print(f" Benign baseline (0)     : {report['n_neg']:,}")
    print(f" Malicious instances (1) : {report['n_pos']:,}")
    print("-" * 62)
    print(f" ROC Area Under Curve (AUC)     : {report['auc']:.4f}")
    print(
        f" Equal Error Rate (EER)         : {report['eer']:.4f} "
        f"(at tau = {report['eer_threshold']:.4f})"
    )
    print(
        f" True Positive Rate (FPR<=0.001): {report['tpr_at_fpr_001']*100:.2f}% "
        f"(at tau = {report['thresh_at_fpr_001']:.4f})"
    )
    print(
        f" False Negative Rate (FNR)      : {report['fnr_at_fpr_001']*100:.2f}%"
    )
    print("=" * 62 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="kitsune",
        description="Kitsune NIDS: Detección de anomalías de red no supervisada",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando demo
    demo_parser = subparsers.add_parser(
        "demo", help="Ejecuta una demostración sobre el tráfico de prueba"
    )
    demo_parser.add_argument(
        "--limit",
        type=int,
        default=15000,
        help="Límite de paquetes a procesar (default: 15000)",
    )

    # Subcomando run
    run_parser = subparsers.add_parser(
        "run", help="Analiza un archivo PCAP o TSV"
    )
    run_parser.add_argument("file", help="Ruta al archivo .pcap o .tsv")
    run_parser.add_argument(
        "--limit", type=int, default=100000, help="Límite de paquetes"
    )
    run_parser.add_argument(
        "--max-ae",
        type=int,
        default=10,
        help="Tamaño máximo de autoencoder (KitNET)",
    )
    run_parser.add_argument(
        "--fm-grace",
        type=int,
        default=5000,
        help="Periodo de gracia Feature Mapping",
    )
    run_parser.add_argument(
        "--ad-grace",
        type=int,
        default=50000,
        help="Periodo de gracia Anomaly Detection",
    )
    run_parser.add_argument(
        "--csv",
        type=str,
        default="anomaly_scores.csv",
        help="Archivo CSV de salida",
    )
    run_parser.add_argument(
        "--plot",
        type=str,
        default="anomaly_plot.png",
        help="Archivo PNG de salida",
    )

    # Subcomando eval (NDSS 2018 Sec. V-C)
    eval_parser = subparsers.add_parser(
        "eval",
        help="Evaluate anomaly scores against ground truth labels (NDSS 2018 Sec. V-C)",
    )
    eval_parser.add_argument(
        "--scores",
        required=True,
        help="Path to CSV containing continuous RMSE anomaly scores",
    )
    eval_parser.add_argument(
        "--labels",
        required=True,
        help="Path to CSV containing binary ground truth labels (0=benign, 1=malicious)",
    )

    args = parser.parse_args()

    if args.command == "demo":
        target = (
            "mirai.pcap.tsv" if os.path.exists("mirai.pcap.tsv") else "mirai.pcap"
        )
        run_pipeline(
            path=target,
            packet_limit=args.limit,
            max_autoencoder_size=10,
            fm_grace=500,
            ad_grace=1500,
            output_csv="demo_scores.csv",
            output_plot="demo_plot.png",
        )
    elif args.command == "run":
        run_pipeline(
            path=args.file,
            packet_limit=args.limit,
            max_autoencoder_size=args.max_ae,
            fm_grace=args.fm_grace,
            ad_grace=args.ad_grace,
            output_csv=args.csv,
            output_plot=args.plot,
        )
    elif args.command == "eval":
        run_eval(args)


if __name__ == "__main__":
    main()