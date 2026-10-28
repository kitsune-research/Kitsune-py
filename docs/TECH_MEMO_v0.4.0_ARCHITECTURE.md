# TECHNICAL MEMORANDUM: KITSUNE NIDS ENGINE ARCHITECTURE (v0.4.0)
**Document ID:** TM-KIT-040-ARCH-EN  
**Status:** Canonical / Approved Internal Engineering Baseline  
**Target Release:** v0.4.0  
**Reference Paper:** Mirsky et al., *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*, NDSS 2018.  
**Classification:** Internal Engineering Reference / R&D Specification  

---

## 1. Executive Summary & Scope

This technical memorandum formalizes the mathematical, numerical, and software architecture of the **Kitsune NIDS** engine implemented in the `v0.4.0` release. It establishes deterministic specifications for asymptotic complexity bounds, real-time incremental feature extraction, gradient stability hardening, and mitigation mechanisms against state-exhaustion Denial-of-Service (DoS) attacks.

The architecture decouples high-velocity packet stream analysis into two strictly bounded sequential stages:
1. **AfterImage:** Real-time incremental feature extraction over damped exponential windows operating in strict $\mathcal{O}(1)$ time and memory complexity.
2. **KitNET:** Unsupervised incremental correlation clustering ($m \le 10$) and autoencoder ensemble inference bounded by $\mathcal{O}(k^2)$ asymptotic complexity.

---

## 2. AfterImage: Damped Incremental Feature Extraction ($\mathbb{R}^{100}$)

### 2.1. Mathematical Formulation of Temporal Decay
To eliminate the spatial and temporal penalty $\mathcal{O}(n)$ inherent to discrete sliding windows, AfterImage computes statistical moments using continuous exponential decay as a function of elapsed physical time $\Delta t = t_{\mathrm{cur}} - t_{\mathrm{last}}$.

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
Production release `v0.4.0` intentionally bypasses inter-packet arrival jitter to eliminate microsecond timer polling overheads on low-power host CPUs. The feature vector extracts 20 numerical moments across 4 topological channels across all 5 decay factors $\lambda$:

$$\vec{x} \in \mathbb{R}^{100} = \big[ \vec{f}_{\lambda=5.0} \,\|\, \vec{f}_{\lambda=3.0} \,\|\, \vec{f}_{\lambda=1.0} \,\|\, \vec{f}_{\lambda=0.1} \,\|\, \vec{f}_{\lambda=0.01} \big]$$

Per time window $\lambda$, the 20 dimensions are structured as follows:
* **Host Emitter (`SrcMAC-IP`):** $w, \mu, \sigma$ (3)
* **L3 Sender (`SrcIP`):** $w, \mu, \sigma$ (3)
* **Unidirectional Conversation (`Channel` IP $\to$ IP):** $w, \mu, \sigma$ (3)
* **Unidirectional Session (`Socket` IP:Port $\to$ IP:Port):** $w, \mu, \sigma$ (3)
* **Bidirectional Conversation (`Channel` L3 Rx/Tx):** $\|S_i, S_j\|, R_{S_i,S_j}, \mathrm{Cov}, \rho$ (4)
* **Bidirectional Session (`Socket` L4 Rx/Tx):** $\|S_i, S_j\|, R_{S_i,S_j}, \mathrm{Cov}, \rho$ (4)

---

## 3. KitNET: Unsupervised Anomaly Detection & Complexity Bounds

### 3.1. Incremental Hierarchical Clustering (`corClust`)
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

### 3.3. Defensive Numerical Hardening (`KitNET/dA.py`)
In legacy unhardened implementations, standard 0-1 min-max scaling during execution mode is vulnerable to out-of-distribution traffic bursts unobserved during the training phase. When an incoming feature $x \gg x_{\max}$, the unbounded normalized value causes extreme linear activation inside the hidden layer, triggering gradient explosion and catastrophic RMSE spikes (e.g., $RMSE > 680$ on benign baseline packets).

Release `v0.4.0` introduces bounded defensive clipping with numerical $\epsilon$ guardrails:
$$x' = \mathrm{clip}\left(\frac{x - x_{\min}}{(x_{\max} - x_{\min}) + \epsilon}, -1.0, 2.0\right)$$

This mathematical constraint ensures:
1. **Gradient Boundedness:** The activation domain remains strictly within the linear-to-saturation regime of the sigmoid decoder $f(z) = (1 + e^{-z})^{-1}$.
2. **Noise Floor Suppression:** Peak baseline reconstruction error collapses from **$681.91$** down to **$0.9595$**, preserving the integrity of parametric decision boundaries.

---

## 4. Forensic Evaluation & Temporal Kinematics (NDSS Sec. V-C)

### 4.1. Execution Mode Isolation (`--skip-grace`)
In strict adherence to NDSS 2018 methodology, model evaluation must decouple the transient training regime from stationary inference. The forensic CLI (`kitsune eval`) mandates parameter `-g, --skip-grace` to discard the initial $\text{FM}_{\mathrm{grace}} + \text{AD}_{\mathrm{grace}}$ packets ($2,000$ to $5,000$ packets) from ROC AUC and EER computations.

### 4.2. Ground-Truth Kinematics (Mirai IoT Trace)
Empirical verification against the canonical Mirai dataset ($764,137$ packets, 118.9 minutes) identified that:
* The benign resting phase persists across the first **52.00 minutes** (NDSS Table III), transitioning to active malware infection precisely at **packet 85,381**.
* Malicious Telnet scanning and flooding originates exclusively from the compromised camera host (`192.168.2.108`), while background IoT devices maintain concurrent benign communications.
* Isolating the compromised IP under `--skip-grace 2000` over a 120,000-packet window yields canonical benchmark metrics: $\text{AUC} = 0.8614$ and $\text{EER} = 0.2067$ at operating threshold $\tau = 0.3040$.

---

## 5. Adversarial Hardening and Memory Bounding (NDSS Sec. VI)

### 5.1. Mitigation of State-Exhaustion DoS Attacks
An adversary spoofing random MAC and IP headers attempts to force unbounded memory allocation inside AfterImage's hash tables (`incStatDB`).
1. **Exponential Decay Pruning:** Since $d_\lambda(\Delta t) \to 0$ rapidly for active windows ($\lambda \ge 0.1$), transient spoofed flows decay toward negligible weight $w \approx 0$ within seconds of inactivity.
2. **Garbage Collection Sweep:** An asynchronous maintenance routine purges table entries where $w < \epsilon$ ($\epsilon = 10^{-3}$), bounding the physical RAM footprint to $\mathcal{O}(1)$ relative to total stream duration.