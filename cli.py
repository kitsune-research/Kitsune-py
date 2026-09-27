import argparse
import sys
import os
import numpy as np
import matplotlib.pyplot as plt
from Kitsune import Kitsune

def run_pipeline(path, packet_limit, max_autoencoder_size, fm_grace, ad_grace, output_csv, output_plot):
    if not os.path.exists(path):
        print(f"[!] Error: El archivo no existe: {path}")
        sys.exit(1)

    print(f"[*] Inicializando Kitsune sobre: {path}")
    print(f"[*] Parámetros: max_ae={max_autoencoder_size}, FMgrace={fm_grace}, ADgrace={ad_grace}")

    K = Kitsune(
        file_path=path,
        limit=packet_limit,
        max_autoencoder_size=max_autoencoder_size,
        FM_grace_period=fm_grace,
        AD_grace_period=ad_grace
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
        np.savetxt(output_csv, rmse_scores, delimiter=",", header="rmse", comments="")
        print(f"[+] Scores guardados en: {output_csv}")

    if output_plot:
        plt.figure(figsize=(10, 4))
        plt.plot(rmse_scores, label="RMSE Score", color="crimson", linewidth=0.8)
        plt.axvline(x=fm_grace + ad_grace, color="gray", linestyle="--", label="Fin de entrenamiento")
        plt.title("Kitsune NIDS - Puntuación de Anomalía (RMSE)")
        plt.xlabel("Índice de Paquete")
        plt.ylabel("RMSE")
        plt.legend(loc="upper right")
        plt.grid(True, linestyle=":", alpha=0.6)
        plt.tight_layout()
        plt.savefig(output_plot, dpi=300)
        plt.close()
        print(f"[+] Gráfica exportada a: {output_plot}")

def main():
    parser = argparse.ArgumentParser(
        prog="kitsune",
        description="Kitsune NIDS: Detección de anomalías de red no supervisada"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando demo
    demo_parser = subparsers.add_parser("demo", help="Ejecuta una demostración sobre el tráfico de prueba")
    demo_parser.add_argument("--limit", type=int, default=15000, help="Límite de paquetes a procesar (default: 15000)")

    # Subcomando run
    run_parser = subparsers.add_parser("run", help="Analiza un archivo PCAP o TSV")
    run_parser.add_argument("file", help="Ruta al archivo .pcap o .tsv")
    run_parser.add_argument("--limit", type=int, default=100000, help="Límite de paquetes")
    run_parser.add_argument("--max-ae", type=int, default=10, help="Tamaño máximo de autoencoder (KitNET)")
    run_parser.add_argument("--fm-grace", type=int, default=5000, help="Periodo de gracia Feature Mapping")
    run_parser.add_argument("--ad-grace", type=int, default=50000, help="Periodo de gracia Anomaly Detection")
    run_parser.add_argument("--csv", type=str, default="anomaly_scores.csv", help="Archivo CSV de salida")
    run_parser.add_argument("--plot", type=str, default="anomaly_plot.png", help="Archivo PNG de salida")

    args = parser.parse_args()

    if args.command == "demo":
        target = "mirai.pcap.tsv" if os.path.exists("mirai.pcap.tsv") else "mirai.pcap"
        run_pipeline(
            path=target,
            packet_limit=args.limit,
            max_autoencoder_size=10,
            fm_grace=500,
            ad_grace=1500,
            output_csv="demo_scores.csv",
            output_plot="demo_plot.png"
        )
    elif args.command == "run":
        run_pipeline(
            path=args.file,
            packet_limit=args.limit,
            max_autoencoder_size=args.max_ae,
            fm_grace=args.fm_grace,
            ad_grace=args.ad_grace,
            output_csv=args.csv,
            output_plot=args.plot
        )

if __name__ == "__main__":
    main()