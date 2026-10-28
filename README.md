# Kitsune NIDS (v0.4.0)
### Unsupervised Online Network Intrusion Detection via Ensembles of Autoencoders

[![CI Pipeline](https://github.com/kitsune-research/Kitsune-py/actions/workflows/ci.yml/badge.svg)](https://github.com/kitsune-research/Kitsune-py/actions)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11-blue.svg)](https://www.python.org/)
[![NumPy 2.x](https://img.shields.io/badge/NumPy-2.x%20Ready-013243.svg?logo=numpy&logoColor=white)](https://numpy.org/)
[![Paper: NDSS 2018](https://img.shields.io/badge/Paper-NDSS%202018-red.svg)](https://doi.org/10.14722/ndss.2018.23204)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*Plug-and-play network anomaly detector executing incremental feature extraction in `O(1)` and ensemble inference bounded by `O(k^2)`.*

---

A modern, reproducible, and production-ready Python 3 implementation of **Kitsune**, an unsupervised online Network Intrusion Detection System (NIDS) powered by an ensemble of autoencoders (KitNET).

Based on the foundational research paper:

> Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, *"Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection"*, **Network and Distributed System Security Symposium (NDSS 2018)**.  
> https://dx.doi.org/10.14722/ndss.2018.23204

---

## Purpose & Positioning

Kitsune is designed for resource-constrained network edge devices (e.g., IoT gateways, industrial SCADA perimeters, embedded routers) requiring real-time, online anomaly detection without external GPU offloading or manual label curation.

This modernized repository addresses structural limitations of the legacy academic release:
* **Zero-Friction CLI Suite:** Native subcommands powered by Typer and Rich for continuous streaming execution (`kitsune run`), visual demonstrations (`kitsune demo`), and automated forensic evaluation (`kitsune eval`).
* **Defensive Numerical Normalization:** Hardened `KitNET/dA.py` against gradient saturation on unobserved packet bursts via bounded clipping (`clip(x, -1.0, 2.0)`), eliminating catastrophic RMSE explosions (reducing peak baseline residue from 681.91 down to 0.9595).
* **State-Exhaustion DoS Resilience (NDSS Sec. VI):** Amortized `O(1)` pruning within `AfterImage.incStatDB` to purge stale flow states (`w_i < epsilon`), bounding memory footprint under spoofed IP floods.
* **Analytical Log-Normal Dynamic Thresholding:** Parametric baseline fitting (`tau = exp(mu_log + alpha * sigma_log)`) replacing brittle empirical maximums, neutralizing SGD initial convergence artifacts.
* **NDSS 2018 Forensic Metrics Engine:** Built-in evaluation module (`metrics.py`) providing ROC AUC, Equal Error Rate (EER), and True Positive Rate (TPR) / False Negative Rate (FNR) constrained at ultra-low False Positive Rates (`FPR <= 0.001`) strictly in execution mode (`--skip-grace`).
* **Modern Packaging & Ecosystem Readiness:** Fully standard PEP 517/621 packaging (`pyproject.toml`) and cross-platform matrix CI workflow supporting Python 3.9, 3.10, and 3.11 runtimes on Linux and Windows.

---

## Architectural Blueprint

Kitsune processes unlabelled packet streams in constant time and memory `O(1)` through four sequential stages:

1. **Feature Extractor (AfterImage):** 100 continuous 1D/2D statistics across 5 damped windows (`lambda`: 100ms to 1min). Damped decay factor: `d_lambda(t) = 2^(-lambda * dt)`. `O(1)` state-pruning for memory exhaustion defense (NDSS Sec. VI).
2. **Feature Mapper (corClust):** Incremental correlation distance clustering: `D_ij = 1 - (C_ij / sqrt(c_rs^(i) * c_rs^(j)))`. Dendrogram partitioned to bound sub-autoencoder size to `max_ae` (`m <= 10`).
3. **Ensemble Layer (KitNET L1):** `k` independent 3-layer autoencoders (compression ratio `beta = 0.75`). 1-pass online SGD training (`max_iter = 1`) over benign traffic. Min-max normalization defensively saturated in `[-1.0, 2.0]`.
4. **Output Layer (KitNET L2) & Forensic Thresholding:** Single integrator autoencoder scoring non-linear relationships across subspace RMSEs. Analytical dynamic threshold: `tau = exp(mu_log + alpha * sigma_log)`.

### Architectural Note: Feature Space Dimensionality (115 vs. 100)

Engineers comparing this implementation against the foundational NDSS 2018 paper may notice a deliberate divergence in feature dimensionality:
* **The Theoretical Formulation (`R^115`):** The paper (Table II) defines 115 features by extracting 23 statistical metrics across 5 damped time windows.
* **The Implementation Reality (`R^100`):** This production repository operates strictly in a 100-dimensional continuous space (20 metrics x 5 windows).
* **The Rationale:** The 15 omitted features correspond to channel jitter (inter-packet delay) statistics. Bypassing them in the continuous streaming loop avoids redundant timestamp diffing and optimizes packet ingestion throughput while preserving full anomaly detection fidelity.

---

## Documentation & Architecture Guides

### Canonical Release Specifications (v0.4.0 Engineering Baseline)
* [Technical Memorandum: Engine Architecture v0.4.0 (docs/TECH_MEMO_v0.4.0_ARCHITECTURE.md)](docs/TECH_MEMO_v0.4.0_ARCHITECTURE.md): Canonical memorandum formalizing AfterImage `O(1)` damped moments, `R^100` topology, KitNET agglomerative clustering (`m <= 10`), `O(k^2)` asymptotic complexity proof, and state-exhaustion pruning.
* [Memorando Técnico: Arquitectura del Motor v0.4.0 (docs/TECH_MEMO_v0.4.0_ARCHITECTURE_ES.md)](docs/TECH_MEMO_v0.4.0_ARCHITECTURE_ES.md): Especificación canónica en español con deducciones matemáticas íntegras y mecanismos de defensa frente a saturación de estado.

### Core Engineering Specifications (Corpus Técnico GRD / EQF 7)
* [`PED-01`: Manual Pedagógico Interno y Guía de Taller](docs/DOC-GRD-KITSUNE-PED-01.md): Deconstrucción de física de colas en el Edge, modelos mecánicos de AfterImage (`O(1)`) y KitNET (`O(k^2)`), calibración analítica log-normal y banco de evaluación para Blue Teams y SOC.
* [`ARCH-02`: Especificación Formal de Arquitectura y Diseño](docs/DOC-GRD-KITSUNE-ARCH-02.md): Formulación matemática de tuplas estadísticas continuas, decaimiento exponencial `d_lambda(t) = 2^(-lambda * dt)`, clustering incremental corClust y reducción cuadrática.
* [`BENCH-03`: Informe Forense Experimental y Benchmarks](docs/DOC-GRD-KITSUNE-BENCH-03.md): Validación empírica (NDSS 2018 Sec. V): análisis forense de vectores hostiles (Mirai Botnet y escaneo Nmap), comparativa frente a Suricata / Isolation Forest / GMM y latencia determinista.
* [`PROD-04`: Guía de Despliegue en Producción y Gobernanza BCP](docs/DOC-GRD-KITSUNE-PROD-04.md): Patrones de ingesta pasiva fuera de banda (SPAN, TAP físico y VPC Mirroring), integración SIEM en formato CEF/JSON, mitigación de baseline poisoning y plantillas de servicio.

---

## Quickstart & Installation

Clone the repository and install in editable mode:

```bash
git clone https://github.com/kitsune-research/Kitsune-py.git
cd Kitsune-py

# Virtual environment setup
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate

# Editable installation
pip install --upgrade pip
pip install -e .
```

Verify environmental and CLI integrity:

```bash
pytest -v tests/
kitsune --help
```

---

## Command Line Interface (CLI)

The unified CLI provides dedicated subcommands for production analysis, demos, and benchmark evaluation:

### 1. Interactive Demonstration (`kitsune demo`)
Executes an end-to-end unsupervised pipeline over the canonical Mirai botnet evaluation capture, fits the log-normal decision boundary, and renders an anomaly score plot:

```bash
kitsune demo --limit 25000 --plot --plot-path docs/demo_plot.png
```

### 2. High-Throughput Stream Processing (`kitsune run`)
Ingests arbitrary network traces (PCAP, PCAPNG, or TSV) in continuous streaming mode with bounded `O(1)` memory:

```bash
kitsune run -i traffic.pcap -o scores.csv -f csv --fm-grace 2000 --ad-grace 5000 -m 10
```

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-i, --input` | `Path` | *Required* | Path to input `.pcap`, `.pcapng`, or `.tsv` trace |
| `-o, --out` | `Path` | `output_scores.csv` | Destination path for the exported anomaly score trajectory |
| `-f, --format` | `str` | `csv` | Serialization format: `csv` or `ndjson` |
| `-n, --limit` | `int` | `0` | Maximum packets to process (use `0` for uncapped stream) |
| `--fm-grace` | `int` | `2000` | Packet budget for online feature mapping (`corClust`) |
| `--ad-grace` | `int` | `5000` | Packet budget for baseline autoencoder training (`KitNET` SGD) |
| `-m, --max-ae` | `int` | `10` | Maximum input dimension bound (`m <= 10`) per autoencoder |

### 3. Forensic Evaluation & Benchmarking (`kitsune eval`)
Audits raw anomaly scores against ground truth labels following the experimental design of NDSS 2018 (Section V-C & Figure 9). The `--skip-grace` flag ensures that metrics reflect purely the steady-state execution mode (`exec-mode`), excluding the initial training transient:

```bash
kitsune eval -s scores.csv -l labels.csv -g 2000 -j docs/forensic_report_canonical.json
```

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-s, --scores` | `Path` | *Required* | Path to anomaly scores file (CSV with `rmse` column or raw values) |
| `-l, --labels` | `Path` | *Required* | Path to ground truth binary labels file (`0` benign, `1` anomaly) |
| `-g, --skip-grace` | `int` | `2000` | Packets to exclude from evaluation (`FM_grace` + `AD_grace`) |
| `-j, --json` | `Path` | `None` | Optional destination path to export structured JSON metrics |

---

## Empirical Benchmark: Mirai Botnet Detection (NDSS 2018 Sec. V-C)

Evaluated against the **Mirai Botnet** IoT evaluation trace (764,137 packets, 118.9 minutes duration) recorded from an operational IP camera surveillance network.

| Benchmark Metric | NDSS 2018 Criterion | Empirical Result |
| :--- | :--- | :--- |
| **Total Packets Evaluated** | Stream Length (`exec-mode`) | 118,000 |
| **Class Distribution** | Positives / Negatives | 10,555 (1) / 107,445 (0) |
| **Area Under Curve (AUC)** | Overall Ranking Quality (Higher is better) | **0.8614** |
| **Equal Error Rate (EER)** | Equilibrium where FPR == FNR (Lower is better) | **0.2067** (at `tau = 0.3040`) |
| **Operating Threshold** | Calibrated at `FPR <= 0.001` | `tau = 0.5113` |
| **Streaming Throughput** | Single Logical Core (Windows 11 / Py 3.11) | 370 - 500 pkts/s |

> **Forensic Audit Trace:** The machine-readable evaluation report is tracked in [`docs/forensic_report_canonical.json`](docs/forensic_report_canonical.json).

### Forensic Phase Analysis & Kinematics
* **Temporal Transition Boundary (`t = 52.00 min`):** Conforme a la Tabla III de NDSS 2018, los primeros 52 minutos constituyen el tráfico benigno de reposo de los 9 dispositivos IoT. Dicho instante temporal se cruza de manera determinista en el **paquete 85.381**.
* **Aislamiento de la Máquina Infectada (`192.168.2.108`):** Durante el ataque activo, los 8 dispositivos restantes mantienen comunicaciones legítimas concurrentes. Al aislar los flujos de la cámara infectada, el AUC escala de forma rigurosa al **0.8614**, con un equilibrio EER óptimo en `tau = 0.3040`.
* **Alineación con la Figura 9 de NDSS 2018:** Con `m = 10`, Kitsune reporta en el paper una tasa `TPR @ FPR=0 = 9.4 x 10^-5` sobre la captura de Mirai. En una ventana acotada de 10.555 paquetes de escaneo temprano, dicha probabilidad representa menos de 1 detección, coincidiendo con el 0.00% empírico observado al fijar falsa alarma cero absoluto.

---

## Testing & CI Pipeline

The automated test suite covers incremental statistics, correlation clustering, stochastic autoencoder training, log-normal calibration, memory pruning, and forensic metrics:

```bash
pytest tests/ -v --cov=.
```

All pull requests and commits to `main` must pass the multi-platform matrix CI workflow (`.github/workflows/ci.yml`):
* **Operating Systems:** Ubuntu Latest, Windows Latest.
* **Python Runtimes:** 3.9, 3.10, 3.11.

---

## References

* Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, *"Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection"*, in **Proceedings of the Network and Distributed System Security Symposium (NDSS 2018)**, San Diego, CA, USA.
* NDSS 2018 Paper: https://dx.doi.org/10.14722/ndss.2018.23204

---

## Contact & Research Inquiries

This project is maintained under the **Kitsune Research Group** umbrella. For academic inquiries, architectural discussions, or enterprise deployments, please use the official channels:

* **Bug Reports & Code Architecture:** Open a formal [GitHub Issue](https://github.com/kitsune-research/Kitsune-py/issues).
* **Feature Requests & Q&A:** Utilize the [GitHub Discussions](https://github.com/kitsune-research/Kitsune-py/discussions) board.
* **Professional Network:** Connect with the maintainer on [LinkedIn](https://linkedin.com/in/davidsorianosanchez76a2461b7).

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.