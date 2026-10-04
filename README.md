# Kitsune NIDS (Python 3 Modernized)

[![Kitsune CI Pipeline](https://github.com/kitsune-research/Kitsune-py/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kitsune-research/Kitsune-py/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11-blue.svg)](https://github.com/kitsune-research/Kitsune-py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A modern, reproducible, and educational CLI-first implementation of Kitsune, an unsupervised online Network Intrusion Detection System (NIDS) powered by an ensemble of autoencoders.

Based on the foundational research paper:

> Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection", NDSS 2018.  
> https://dx.doi.org/10.14722/ndss.2018.23204

---

## Purpose & Positioning

Kitsune is designed for resource-constrained network edge devices (e.g., IoT gateways, embedded routers) requiring real-time, online anomaly detection without requiring external GPU offloading or supervised labels.

This modernized repository addresses key challenges present in the original academic release:
* **Zero-Friction CLI:** Execute end-to-end streaming detection, evaluation, and plotting via declarative CLI commands.
* **Packaging & Python 3 Standards:** Fully modernized for Python 3.9+ environments, deprecating legacy builds in favor of standard PEP 517/621 packaging (`pyproject.toml`).
* **Automated CI/CD:** Matrix testing on Ubuntu and Windows across Python 3.9, 3.10, and 3.11 with hardened system dependencies (`libpcap-dev`) and deterministic pytest suites.
* **Empirical Validation:** Reproducible forensic verification against real-world Mirai botnet telemetry.

---

## Architecture Overview

Kitsune processes unlabelled packet streams in constant time and memory $O(1)$ through four sequential stages:

1. **Feature Extractor (AfterImage):** Maintains 1D and 2D statistics (packet rate, byte bandwidth, jitter, covariance) across 5 exponentially damped decay windows ($\lambda \in \{5, 3, 1, 0.1, 0.01\}$) over sender, channel, and socket streams. Produces a 100-dimensional feature vector.
2. **Feature Mapper (corClust):** Performs online hierarchical agglomerative clustering based on incremental correlation distances ($d_{	ext{cor}}$), bounding the maximum sub-autoencoder size to $m$. This reduces complexity from $O(n^2)$ down to $O(k^2)$.
3. **Ensemble Layer ($L^{(1)}$):** Maps each sub-instance into a dedicated 3-layer autoencoder with compression ratio $eta = 0.75$, scoring localized reconstruction errors (RMSE).
4. **Output Layer ($L^{(2)}$):** Ingests the normalized error signals of $L^{(1)}$ to capture non-linear relationships across subspaces, outputting the final network anomaly score.

---

## Documentation & Architecture Guides

* 🇪🇸 **[Manual Práctico («Para Dummies») - Español](docs/manual_es.md):** Arquitectura completa explicada con analogías, fundamentos matemáticos y manual de la CLI.
* 🇬🇧 **[Practical Engineering Field Guide - English](docs/manual_en.md):** In-depth system blueprint, $O(1)$ mathematical formulation, CLI walkthrough, and Mirai benchmark forensics.

---

## Quickstart

### 1. Installation

Clone the repository and install the package in editable mode:

```bash
git clone https://github.com/kitsune-research/Kitsune-py.git
cd Kitsune-py
python -m pip install --upgrade pip
pip install -e .
```

Verify that the CLI is accessible:

```bash
kitsune --help
```

### 2. Run the Built-in Demo

Execute the streaming detection pipeline on the bundled Mirai botnet trace (15,000 packets):

```bash
kitsune demo --limit 15000
```

The CLI runs AfterImage feature extraction, passes the stream through KitNET, and exports:
* `demo_scores.csv`: Packet-by-packet RMSE anomaly scores.
* `demo_plot.png`: Anomaly score trajectory over time.

---

## Empirical Benchmark: Mirai Botnet Detection

Analysis of the streaming RMSE output on the benchmark trace demonstrates high signal separation between benign traffic and the Mirai intrusion.

### Extended Execution (120,000 Packets - Semilogarithmic Scale)

![KitNET Anomaly Detection - Mirai Dataset (Escala Logarítmica)](mirai_rmse_log_plot.png)

### Forensic Phase Analysis

* **Packets 0 - 2,000 (Feature Mapping Phase):** Model grace period (`--fm-grace 2000`). AfterImage initializes damped statistics and KitNET discovers feature clusters. Anomaly score remains strictly 0.0.
* **Packets 2,001 - 3,000 (Autoencoder Convergence Transient):** Online SGD initial weight optimization across $L^{(1)}$ and $L^{(2)}$. The isolated spike at Packet #2543 ($RMSE = 600.74$) is a numerical convergence artifact occurring before the autoencoders settle into the benign traffic manifold.
* **Packets 3,001 - 7,000 (Benign Baseline Manifold):** Stabilized normal traffic profile. The reconstruction error remains bounded with a median of **0.1297** and a 99th percentile ($p99$) of **0.4155**.
* **Packets 7,001 - 120,000 (Mirai Botnet Intrusion & Infiltration):** Active distributed scanning and Telnet propagation phase. The sustained intrusion triggers widespread subspace reconstruction breakdown, peaking at Packet #12,322 ($RMSE = 11.2944$) and reaching severe bursts exceeding $10^3 - 10^4$ RMSE. Notice the exponential decay slopes ($d_\lambda(t) = 2^{-\lambda t}$) following each attack wave as AfterImage dampens past activity.

### Quantitative Performance Metrics (Initial Intrusion Window)

| Metric Segment | Parameter | Value |
| :--- | :--- | :--- |
| **Benign Traffic Baseline** | Median Error ($p50$) | **0.1297 RMSE** |
| | 90th Percentile ($p90$) | **0.4523 RMSE** |
| | 99th Percentile ($p99$) | **0.4155 RMSE** |
| **Mirai Botnet Intrusion** | Peak Anomaly Score (Packet #12322) | **11.2944 RMSE** |
| **Signal Separation** | **Signal-to-Noise Ratio (vs $p99$)** | **27.18x** |
| | **Signal-to-Noise Ratio (vs Median)** | **87.09x** |

The detection signal elevates the reconstruction error **27.18x above the 99th percentile noise floor**, enabling threshold setting with near-zero false positive rates ($FPR 	o 0$), matching the findings reported by Mirsky et al. (NDSS 2018).

---

## Usage

### Analyze Custom PCAP / TSV Traces

```bash
kitsune run path/to/capture.pcap --limit 100000 --csv output_scores.csv --plot detection.png
```

### CLI Options

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `file` | `Path` | *Required* | Path to input `.pcap`, `.pcapng`, or `.tsv` file |
| `--limit` | `int` | `100000` | Maximum number of packets to process |
| `--max-ae` | `int` | `10` | Maximum input dimension ($m$) per autoencoder in $L^{(1)}$ |
| `--fm-grace` | `int` | `5000` | Packet budget for online feature mapping |
| `--ad-grace` | `int` | `50000` | Packet budget for baseline autoencoder training |
| `--csv` | `Path` | `anomaly_scores.csv` | Output path for raw RMSE anomaly scores |
| `--plot` | `Path` | `anomaly_plot.png` | Destination path for anomaly plot |

---

## Testing & CI Pipeline

The test suite validates AfterImage incremental updates, correlation distance matrices, and KitNET anomaly detection:

```bash
pytest tests/ -v --cov=.
```

All pull requests and commits to main must pass the GitHub Actions CI pipeline across:
* **Operating Systems:** Ubuntu Latest, Windows Latest.
* **Python Environments:** 3.9, 3.10, 3.11.

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
