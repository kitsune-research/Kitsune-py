import csv
import matplotlib.pyplot as plt
import numpy as np

def analyze_telemetry(csv_path="docs/bench_metrics.csv"):
    print(f"[*] Leyendo telemetría desde {csv_path}...")
    packet_ids = []
    rmses = []
    latencies = []

    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            packet_ids.append(int(row["packet_id"]))
            rmses.append(float(row["rmse"]))
            latencies.append(float(row["latency_us"]))

    packet_ids = np.array(packet_ids)
    rmses = np.array(rmses)
    latencies = np.array(latencies)

    # Filtrar fase de entrenamiento (primeros 20k paquetes) vs ejecución
    benign_rmse = rmses[20000:100000]
    threshold_max = np.max(benign_rmse)
    threshold_lognormal = np.mean(benign_rmse) + 3 * np.std(benign_rmse)

    print("\n" + "="*50)
    print("REPORTE TELEMÉTRICO - KITSUNE NIDS (HITO 3)")
    print("="*50)
    print(f"Total paquetes:        {len(packet_ids):,}")
    print(f"Latencia media:        {np.mean(latencies):.2f} µs ({1e6/np.mean(latencies):.2f} pps)")
    print(f"Latencia percentil 99: {np.percentile(latencies, 99):.2f} µs")
    print(f"RMSE medio (benigno):  {np.mean(benign_rmse):.6f}")
    print(f"Umbral tau (Max Benign): {threshold_max:.6f}")
    print(f"Umbral tau (3-Sigma):    {threshold_lognormal:.6f}")
    print(f"RMSE máximo (ataque):  {np.max(rmses):.6f}")
    print("="*50)

    # Gráfica de detección
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), sharex=True)

    # Plot 1: Curva de RMSE y detección de anomalías
    ax1.plot(packet_ids[::50], rmses[::50], color="#d9534f", lw=0.8, label="KitNET RMSE")
    ax1.axhline(threshold_lognormal, color="#0275d8", linestyle="--", label=r"Umbral $\tau$ ($3\sigma$)")
    ax1.axvline(20000, color="gray", linestyle=":", label="Fin de Entrenamiento")
    ax1.set_ylabel("RMSE Anomaly Score")
    ax1.set_title("Kitsune NIDS: Detección de Anomalías sobre Mirai Botnet")
    ax1.grid(True, alpha=0.3)
    ax1.legend(loc="upper left")

    # Plot 2: Perfil de Latencia por paquete
    ax2.plot(packet_ids[::50], latencies[::50] / 1000.0, color="#5cb85c", lw=0.6, label="Latencia (ms)")
    ax2.set_xlabel("Número de Paquete")
    ax2.set_ylabel("Latencia (ms)")
    ax2.set_title(r"Perfil de Latencia por Paquete (AfterImage $\mathcal{O}(1)$ + KitNET $\mathcal{O}(k^2)$)")
    ax2.grid(True, alpha=0.3)
    ax2.legend(loc="upper left")

    out_fig = "docs/mirai_benchmark_plot.png"
    plt.tight_layout()
    plt.savefig(out_fig, dpi=300)
    print(f"[+] Gráfico guardado exitosamente en {out_fig}")

if __name__ == "__main__":
    analyze_telemetry()