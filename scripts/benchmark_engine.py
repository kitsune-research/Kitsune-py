"""
Harness de telemetría y profiling de latencia para Kitsune NIDS (Hito 3).
Mide latencia por paquete (AfterImage O(1) + KitNET O(k^2)) y throughput efectivo.
"""
import time
import csv
import sys
from pathlib import Path
from Kitsune import Kitsune

def run_benchmark(pcap_path: str, max_packets: int = 100000, max_ae_size: int = 10):
    pcap_file = Path(pcap_path)
    if not pcap_file.exists():
        print(f"[-] Error: Archivo no encontrado en {pcap_path}")
        sys.exit(1)

    print(f"[*] Inicializando Kitsune NIDS (m={max_ae_size}) sobre {pcap_path}...")
    # FM_grace_period y AD_grace_period ajustados para la fase de perfilado
    k = Kitsune(str(pcap_file), limit=max_packets, max_autoencoder_size=max_ae_size)
    
    records = []
    packet_id = 0
    t_start_total = time.perf_counter()

    print(f"[*] Procesando hasta {max_packets} paquetes para profiling de latencia...")
    try:
        while True:
            t0 = time.perf_counter_ns()
            rmse = k.proc_next_packet()
            t1 = time.perf_counter_ns()

            if rmse == -1:
                break

            latency_us = (t1 - t0) / 1000.0
            records.append((packet_id, rmse, latency_us))
            packet_id += 1

            if packet_id % 10000 == 0:
                print(f"    -> Procesados {packet_id} paquetes | Última latencia: {latency_us:.2f} µs")

    except KeyboardInterrupt:
        print("\n[!] Profiling interrumpido por el usuario.")

    t_total = time.perf_counter() - t_start_total
    throughput = packet_id / t_total if t_total > 0 else 0

    print(f"[+] Benchmarking completado:")
    print(f"    - Paquetes analizados: {packet_id}")
    print(f"    - Tiempo total: {t_total:.2f} s")
    print(f"    - Throughput sostenido: {throughput:.2f} pps")

    out_csv = Path("docs/bench_metrics.csv")
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["packet_id", "rmse", "latency_us"])
        writer.writerows(records)

    print(f"[+] Telemetría guardada en {out_csv}")

if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "dataset/mirai.pcap"
    run_benchmark(pcap, max_packets=800000, max_ae_size=10)
