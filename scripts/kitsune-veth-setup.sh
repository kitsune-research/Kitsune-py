#!/usr/bin/env bash
echo "[*] Creando el par de interfaces veth (veth-inj <-> veth-nids)..."
sudo ip link add veth-inj type veth peer name veth-nids

echo "[*] Levantando el enlace..."
sudo ip link set veth-inj up
sudo ip link set veth-nids up

echo "[*] Desactivando TCP Segmentation / Generic Receive Offloading..."
sudo ethtool -K veth-inj tso off gro off lro off 2>/dev/null
sudo ethtool -K veth-nids tso off gro off lro off 2>/dev/null

echo "[*] Configurando el extremo NIDS en modo promiscuo..."
sudo ip link set veth-nids promisc on

echo "[+] Bus L2 operativo."
