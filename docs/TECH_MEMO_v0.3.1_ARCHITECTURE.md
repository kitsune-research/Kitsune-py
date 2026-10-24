# TECHNICAL MEMORANDUM: KITSUNE NIDS ENGINE ARCHITECTURE (v0.3.1)
**Document ID:** TM-KIT-031-ARCH-EN  
**Status:** Canonical / Approved Internal  
**Target Release:** v0.3.1  
**Reference Paper:** Mirsky et al., *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*, NDSS 2018.  
**Classification:** Internal Engineering Reference / R&D Specification  

---

## 1. Executive Summary & Scope

This technical memorandum formalizes the mathematical and software architecture of the **Kitsune NIDS** engine implemented in the `v0.3.1` production branch (`src/kitsune`). It deterministically specifies asymptotic bounds, real-time feature extraction pipelines, and mitigation mechanisms against state-exhaustion Denial-of-Service (DoS) attacks.

The system decouples packet stream analysis into two strictly bounded sequential stages:
1. **AfterImage:** Real-time incremental feature extraction over damped exponential windows operating in strict $\mathcal{O}(1)$ time complexity.
2. **KitNET:** Unsupervised incremental correlation clustering ($m \le 10$) and autoencoder ensemble inference bounded by $\mathcal{O}(k^2)$ asymptotic complexity.

---

## 2. AfterImage: Damped Incremental Feature Extraction ($\mathbb{R}^{100}$)

### 2.1. Mathematical Formulation of Temporal Decay
To avoid the spatial and temporal penalty $\mathcal{O}(n)$ inherent to discrete sliding windows, AfterImage computes statistical moments using continuous exponential decay as a function of elapsed time $\Delta t = t_{\mathrm{cur}} - t_{\mathrm{last}}$.

The continuous decay kernel is defined as:
$$d_\lambda(\Delta t) = 2^{-\lambda \cdot \Delta t}$$

where $\lambda > 0$ represents the decay factor calibrated across five operational time scales:
* $\lambda = 5.0 \implies \tau_{1/2} \approx 100\,\mathrm{ms}$ (Volumetric bursts and L4 transport floods).
* $\lambda = 3.0 \implies \tau_{1/2} \approx 500\,\mathrm{ms}$ (TCP handshake dynamics).
* $\lambda = 1.0 \implies \tau_{1/2} \approx 1.5\,\mathrm{s}$ (Flow control cadences).
* $\lambda = 0.1 \implies \tau_{1/2} \approx 10\,\mathrm{s}$ (Sustained sessions and data exfiltration).
* $\lambda = 0.01 \implies \tau_{1/2} \approx 60\,\mathrm{s}$ (Stationary baseline and periodic C2 beacons).

### 2.2. Incremental Update Equations in $\mathcal{O}(1)$
For each observed packet, AfterImage updates a 1D incremental statistic tuple $\mathrm{IS}_{1\mathrm{D}} = (w, \mathrm{LS}, \mathrm{SS})$ and a 2D cross-statistic tuple $\mathrm{IS}_{2\mathrm{D}} = (\mathrm{IS}_i, \mathrm{IS}_j, \mathrm{SR}_{ij})$:

1. **Decay execution:**
   $$\gamma = d_\lambda(t_{\mathrm{cur}} - t_{\mathrm{last}})$$
   $$w \leftarrow \gamma \cdot w, \quad \mathrm{LS} \leftarrow \gamma \cdot \mathrm{LS}, \quad \mathrm{SS} \leftarrow \gamma \cdot \mathrm{SS}, \quad \mathrm{SR}_{ij} \leftarrow \gamma \cdot \mathrm{SR}_{ij}$$

2. **Observation insertion ($x = \text{packet size}$):**
   $$w \leftarrow w + 1$$
   $$\mathrm{LS} \leftarrow \mathrm{LS} + x$$
   $$\mathrm{SS} \leftarrow \mathrm{SS} + x^2$$
   $$\mathrm{SR}_{ij} \leftarrow \mathrm{SR}_{ij} + (x_i - \mu_i)(x_j - \mu_j)$$

3. **Moment evaluation:**
   * Mean: $\mu = \frac{\mathrm{LS}}{w}$
   * Variance & Standard Deviation: $\sigma^2 = \left| \frac{\mathrm{SS}}{w} - \left(\frac{\mathrm{LS}}{w}\right)^2 \right|, \quad \sigma = \sqrt{\sigma^2}$
   * Cross-Stream Covariance: $\mathrm{Cov}_{ij} = \frac{\mathrm{SR}_{ij}}{w_i + w_j}$
   * Pearson Correlation Coefficient: $\rho_{ij} = \frac{\mathrm{Cov}_{ij}}{\sigma_i \cdot \sigma_j}$

### 2.3. Output Feature Space Partitioning ($\mathbb{R}^{100}$)
Production release `v0.3.1` intentionally omits inter-packet arrival jitter to eliminate microsecond timer polling overheads on low-power host CPUs. The feature vector extracts 20 numerical moments across 4 topological channels across all 5 decay factors $\lambda$:

$$\vec{x} \in \mathbb{R}^{100} = \big[ \vec{f}_{\lambda=5.0} \,\|\, \vec{f}_{\lambda=3.0} \,\|\, \vec{f}_{\lambda=1.0} \,\|\, \vec{f}_{\lambda=0.1} \,\|\, \vec{f}_{\lambda=0.01} \big]$$

Per time window $\lambda$, the 20 dimensions are structured as follows:
* **Host Emitter (`SrcMAC-IP`):** $w, \mu, \sigma$ (3)
* **L3 Sender (`SrcIP`):** $w, \mu, \sigma$ (3)
* **Unidirectional Conversation (`Channel` IP $\to$ IP):** $w, \mu, \sigma$ (3)
* **Unidirectional Session (`Socket` IP:Port $\to$ IP:Port):** $w, \mu, \sigma$ (3)
* **Bidirectional Conversation (`Channel` L3 Rx/Tx):** $\|S_i, S_j\|, R_{S_i,S_j}, \mathrm{Cov}, \rho$ (4)
* **Bidirectional Session (`Socket` L4 Rx/Tx):** $\|S_i, S_j\|, R_{S_i,S_j}, \mathrm{Cov}, \rho$ (4)

For non-transport payloads (e.g., ICMP, ARP), Socket features are deterministically zeroed ($0.0$), guaranteeing tensor shape stability.

---

## 3. KitNET: Unsupervised Anomaly Detection & Complexity Bounds

### 3.1. Incremental Hierarchical Clustering (corClust)
During the initial `FM_grace_period`, the Feature Mapper incrementally populates a correlation distance matrix $D \in \mathbb{R}^{n \times n}$:

$$D_{ij} = 1 - \frac{C_{ij}}{\sqrt{c_{rs}^{(i)}} \sqrt{c_{rs}^{(j)}}}$$

Upon concluding `FM_grace_period`, an agglomerative clustering tree is formed and traversed under a **strict cluster size ceiling of $m \le 10$**. If any cluster exceeds $m$, it is iteratively bisected, yielding $k$ disjoint sub-instances $\vec{v}_1, \dots, \vec{v}_k$.

### 3.2. Ensemble Topology and Complexity Proof
KitNET divides inference across two non-monolithic neural layers:
1. **Ensemble Layer $L^{(1)}$:** $k$ three-layer autoencoders ($d_{\mathrm{in}} \le m$, compressed hidden layer $\lceil \beta \cdot d_{\mathrm{in}} \rceil$ with $\beta = 0.75$). Each autoencoder reconstructs its assigned sub-instance $\vec{v}_i$ and produces an intermediate error metric $\mathrm{RMSE}_i \in [0, 1]$.
2. **Output Layer $L^{(2)}$:** A single autoencoder processing the intermediate vector $\vec{z} = [\mathrm{RMSE}_1, \dots, \mathrm{RMSE}_k]^T \in \mathbb{R}^k$ with hidden layer $\lceil \beta \cdot k \rceil$, modeling normal cross-subspace error correlations.

#### Asymptotic Complexity Analysis:
* A monolithic feedforward autoencoder over input dimension $n$ exhibits activation complexity:
  $$\mathcal{O}(n \cdot \beta n) = \mathcal{O}(n^2)$$
* In KitNET, maintaining the bound $m \le 10$ as a constant:
  $$\mathcal{O}(L^{(1)}) = \sum_{i=1}^k \mathcal{O}(m_i^2) \le \mathcal{O}(k \cdot m^2) = \mathcal{O}(k)$$
  $$\mathcal{O}(L^{(2)}) = \mathcal{O}(k \cdot \beta k) = \mathcal{O}(k^2)$$
  $$\text{Total Complexity} = \mathcal{O}(k \cdot m^2 + k^2) \equiv \mathcal{O}(k^2)$$

Because $k \ll n$ in practical network traffic partitions, this ensemble formulation achieves a speedup factor of at least $5\times$ over monolithic architectures on equivalent feature spaces.

### 3.3. Online Optimization and Decision Boundary
* **Optimizer:** Single-pass Stochastic Gradient Descent (SGD) with `max_iter = 1` during `AD_grace_period`. Instances are discarded immediately following weight adjustment.
* **Anomaly Score:** Reconstruction Root Mean Squared Error (RMSE) emitted by layer $L^{(2)}$:
  $$\mathrm{score} = \mathrm{RMSE}(\vec{z}, \hat{\vec{z}}) = \sqrt{\frac{1}{k} \sum_{j=1}^k (z_j - \hat{z}_j)^2}$$
* **Thresholding ($\tau$):** Parameterized log-normal fit over benign phase residues:
  $$\ln(\mathrm{RMSE}) \sim \mathcal{N}(\mu_{\ln}, \sigma_{\ln}^2) \implies \tau = \exp(\mu_{\ln} + \alpha \cdot \sigma_{\ln})$$

---

## 4. Adversarial Hardening and Memory Bounding (NDSS Sec. VI)

### 4.1. Mitigation of State-Exhaustion DoS Attacks
An adversary spoofing random MAC and IP headers can attempt to force infinite instantiation of entries within AfterImage's hash tables (`incStatDB`), causing memory exhaustion.

**Architectural Countermeasures:**
1. **Exponential Weight Decay Pruning:** Since $d_\lambda(\Delta t) \to 0$ rapidly for active windows ($\lambda \ge 0.1$), transient spoofed flows decay toward negligible weight $w \approx 0$ within seconds of inactivity.
2. **Garbage Collection Sweep:** A periodic asynchronous cleaner purges table entries where $w < \epsilon$ ($\epsilon = 10^{-3}$), bounding the physical memory consumption well within resource-constrained hardware limits.

### 4.2. Baseline Contamination Protection
To prevent slow-rate training poisoning during `AD_grace_period`, the engine supports execution in pre-filtering mode: any observation exhibiting an abnormal provisional error is excluded from SGD backpropagation, maintaining the integrity of the normal manifold.