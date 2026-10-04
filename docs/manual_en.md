# Kitsune NIDS: The Practical Engineering Field Guide ("For Dummies")

**Technical Direction:** Tamamo-no-Mae & paradiselord-dev  
**Ecosystem:** `kitsune-research / Kitsune-py` (Python 3.9 – 3.11)  
**Foundational Research:** Network and Distributed Systems Security (NDSS) Symposium 2018 (Y. Mirsky et al.)

---

## 1. The Core Analogy: What is Kitsune, and Why Without GPUs?

Picture an international airport customs checkpoint processing 50,000 travelers per minute. 

A conventional Deep Learning approach would deploy fifty security inspectors armed with heavy GPU clusters to take full 3D body scans of every person, querying massive databases of known terrorists. If an attacker invents a completely novel evasion technique (a **zero-day intrusion**), they pass through unnoticed because their signature does not exist in the training set. Furthermore, latency explodes and the line stalls.

**Kitsune flips the paradigm:**
1. **It does not look for bad actors; it learns how normal travelers walk.**
2. **Zero packet buffering in RAM:** It processes the packet crossing the interface in nanoseconds and discards it immediately (strictly **$O(1)$ constant time and memory**).
3. **An Ensemble of Deforming Mirrors (Autoencoders):** Imagine localized mirrors trained to reconstruct benign traffic profiles. When legitimate traffic flows, the mirror reconstructs the image almost perfectly (reconstruction error near zero). When the **Mirai botnet** saturates the network with distributed Telnet scans, the autoencoders fail to reconstruct the unseen feature subspace. The resulting spike in Root Mean Squared Error ($RMSE$) triggers an anomaly alert.

Crucially, the entire pipeline executes on low-cost edge hardware, such as a single-core Raspberry Pi or an enterprise edge router, operating directly at wire-speed.

---

## 2. Architectural Blueprint: Four Engines Under the Hood

Kitsune processes unlabelled packet streams sequentially through four modular stages:

```
[ Raw Network Packet ]
          │
          ▼
┌──────────────────────────────────────┐
│  1. AfterImage (Feature Extraction)  │  ──► Damped exponential decay windows (100ms - 1m)
└──────────────────────────────────────┘      Yields a normalized 100D behavioral vector in O(1)
          │
          ▼
┌──────────────────────────────────────┐
│  2. corClust (Feature Mapper)        │  ──► Online hierarchical correlation clustering
└──────────────────────────────────────┘      Partitions 100 features into k subsets (size ≤ 10)
          │
          ▼
┌──────────────────────────────────────┐
│  3. Ensemble Layer L^(1)             │  ──► k localized 3-layer Autoencoders (SGD)
└──────────────────────────────────────┘      Outputs localized RMSE vectors z ∈ R^k
          │
          ▼
┌──────────────────────────────────────┐
│  4. Output Layer L^(2) (Voting)      │  ──► Master Autoencoder modeling ensemble dynamics
└──────────────────────────────────────┘      Emits unified Network Anomaly Score (RMSE)
```

### Engine 1: AfterImage (Damped Incremental Statistics)
Storing raw packet histories in sliding windows requires $O(n)$ memory and compute, quickly exhausting hardware buffers. AfterImage solves this by updating continuous 1D and 2D statistics with an exponential decay factor:

$$d_{\lambda}(t) = 2^{-\lambda t}$$

Where $\lambda$ determines how rapidly past packet dynamics fade ($\lambda \in \{5, 3, 1, 0.1, 0.01\}$, spanning 100ms, 500ms, 1.5s, 10s, and 1 minute). By maintaining lightweight tuples $(w, LS, SS)$ (weight, linear sum, and squared sum), AfterImage computes in constant time $O(1)$:
* Packet arrival rates and byte volume.
* Transmission jitter (inter-packet arrival delay deltas).
* Covariance and Pearson correlation coefficients across IP channels and TCP/UDP sockets.

This produces an incremental 100-dimensional behavioral vector per packet with zero disk or buffer bloat.

### Engine 2: corClust (Subspace Decomposition via $O(k^2)$)
A single monolithic autoencoder over 100 features scales quadratically: $O(n^2)$, consuming excessive CPU cycles. `corClust` overcomes this: during the feature-mapping grace period (`FM_grace_period`), it measures feature inter-dependencies using incremental correlation distance:

$$d_{	ext{cor}}(u, v) = 1 - rac{(u - ar{u}) \cdot (v - ar{v})}{\|u - ar{u}\|_2 \|v - ar{v}\|_2}$$

It executes agglomerative hierarchical clustering to group co-dependent features into compact subsets of maximum size $m \le 10$. This collapses ensemble complexity to $O(k^2)$, yielding up to a **$5	imes$ acceleration** in packet processing throughput.

### Engine 3: Ensemble Layer $L^{(1)}$ (Localized Inspectors)
Each subset of features feeds a dedicated 3-layer autoencoder with compression bottleneck ratio $eta = 0.75$. Each autoencoder learns exclusively on benign traffic using single-pass Stochastic Gradient Descent (SGD) with `max_iter = 1`. Each network outputs its localized reconstruction error:

$$	ext{RMSE}(x, y) = \sqrt{rac{\sum_{i=1}^{n} (x_i - y_i)^2}{n}}$$

### Engine 4: Output Layer $L^{(2)}$ (The Master Evaluator)
A top-level autoencoder receives the normalized RMSE signals from all ensemble members. If multiple autoencoders experience simultaneous reconstruction degradation, the output layer detects a structural breakdown in inter-feature correlation, elevating the final network anomaly score.

---

## 3. Command-Line Interface (CLI): Quickstart

The modernized implementation introduces a zero-friction CLI packaged under PEP 517/621 (`pyproject.toml`):

### 1. Installation
```bash
git clone https://github.com/kitsune-research/Kitsune-py.git
cd Kitsune-py
python -m pip install --upgrade pip
pip install -e .
```

Verify command availability:
```bash
kitsune --help
```

### 2. Built-in Verification Demo
Run detection against the bundled Mirai botnet trace (15,000 packets):
```bash
kitsune demo --limit 15000
```
Outputs:
* `demo_scores.csv`: Per-packet RMSE anomaly scores.
* `demo_plot.png`: High-resolution anomaly timeline visualization.

### 3. Custom PCAP Ingestion
```bash
kitsune run suspicious_traffic.pcap --limit 100000 --fm-grace 5000 --ad-grace 20000 --csv output.csv --plot detection.png
```

---

## 4. Empirical Forensics: Mirai Botnet Benchmark

Benchmarking the modernized pipeline against real-world Mirai botnet telemetry demonstrates stark mathematical separation:

| Metric Segment | Statistical Parameter | Observed Value | Operational Interpretation |
| :--- | :--- | :--- | :--- |
| **Benign Baseline (Post-Grace)** | Median ($p50$) | **0.1297 RMSE** | Normal network state; model reconstruction is stable. |
| | 99th Percentile ($p99$) | **0.4155 RMSE** | Upper noise floor; 99% of benign packets stay below this line. |
| **Mirai Botnet Intrusion** | Peak Score (Pkt #12,322) | **11.2944 RMSE** | High-volume Telnet brute-force scan collapses autoencoder subspaces. |
| **Signal-to-Noise Ratio (SNR)** | Elevation over $p99$ | **27.18x** | Anomaly peak exceeds the 99th percentile noise floor by 27x. |
| | Elevation over Median | **87.09x** | Anomaly peak exceeds normal baseline median by 87x. |

### Demystifying the Packet #2543 Spike
In preliminary runs, an isolated spike occurs at Packet #2543 ($RMSE = 600.74$). Algorithmic inspection confirms this is **not an intrusion**, but an **SGD convergence transient** occurring immediately after the expiration of the feature-mapping grace period (`FM_grace_period = 2000`). Once the initial weights settle, the baseline stabilizes at $RMSE pprox 0.13$. The true Mirai infiltration begins around Packet 7,000, peaking at Packet #12,322.

---

## 5. Engineering Standards & Quality Assurance

* **Deterministic Testing:**
  ```bash
  pytest tests/ -v --cov=.
  ```
* **Multi-Platform CI/CD:**
  Automated GitHub Actions matrix verifying 6 parallel jobs across:
  - Operating Systems: Ubuntu Latest, Windows Latest.
  - Python Versions: 3.9, 3.10, and 3.11.
  - Networking Libraries: Hardened with `libpcap-dev`.
* **Repository Governance:** Protected `main` branch requiring passing CI status checks before merge.
