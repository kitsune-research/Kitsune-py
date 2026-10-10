"""Script generador de micro-traza sintética OS Scan (NDSS 2018, Tabla III).

Emula tráfico RTP benigno de cámaras IP y una ráfaga de escaneo Nmap (TCP SYN/NULL/XMAS)
para validar la elevación del error RMSE en KitNET sin requerir datasets masivos.
"""

from __future__ import annotations

from pathlib import Path
from scapy.all import IP, TCP, UDP, Raw, wrpcap


def build_os_scan_pcap(
    output_path: Path,
    n_benign: int = 1500,
    n_attack: int = 400,
) -> Path:
    packets = []
    base_time = 1700000000.0  # Epoch base determinista
    cur_time = base_time

    # 1. Tráfico Benigno: Simulación de flujo RTP/UDP (Cámara 192.168.1.10 -> NVR 192.168.1.2)
    # Tasa ~200 pkts/s (inter-arrival ~0.005s), tamaño de payload constante (~1200 bytes)
    for _ in range(n_benign):
        cur_time += 0.005
        pkt = (
            IP(src="192.168.1.10", dst="192.168.1.2")
            / UDP(sport=5004, dport=5004)
            / Raw(load=b"\x80\xe0\x00\x01" + b"\xaa" * 1196)
        )
        pkt.time = cur_time
        packets.append(pkt)

    # 2. Vector de Ataque: Sondas de fingerprinting de Nmap (Atacante 192.168.1.100 -> Cámara)
    # Patrones con ráfagas de flags inusuales, puertos variables y alta tasa instantánea
    scan_ports = [80, 443, 554, 8080, 21, 22, 23, 25, 110, 143]
    flags_sequence = ["S", "", "FPU", "F", "SF", "A"]  # SYN, NULL, XMAS, FIN, SYN-FIN, ACK

    for i in range(n_attack):
        cur_time += 0.0008  # Ráfaga rápida
        target_port = scan_ports[i % len(scan_ports)]
        tcp_flag = flags_sequence[i % len(flags_sequence)]

        scan_pkt = (
            IP(src="192.168.1.100", dst="192.168.1.10")
            / TCP(sport=40000 + (i % 5000), dport=target_port, flags=tcp_flag)
        )
        scan_pkt.time = cur_time
        packets.append(scan_pkt)

        # Respuesta RST/ACK desde la víctima simulando puerto cerrado
        if tcp_flag != "":
            cur_time += 0.0001
            resp_pkt = (
                IP(src="192.168.1.10", dst="192.168.1.100")
                / TCP(sport=target_port, dport=40000 + (i % 5000), flags="RA")
            )
            resp_pkt.time = cur_time
            packets.append(resp_pkt)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return output_path


if __name__ == "__main__":
    target = Path("data/samples/os_scan_micro.pcap")
    build_os_scan_pcap(target)
    print(f"Micro-traza OS Scan generada exitosamente en: {target}")