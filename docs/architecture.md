# Kitsune NIDS: Mathematical Foundations and Execution Architecture

> 🇪🇸 *[Versión en español disponible en architecture_es.md](architecture_es.md)*

This document formalizes the architecture of the Kitsune Network Intrusion Detection System (NIDS), detailing online streaming feature extraction with **AfterImage**, feature space decomposition via **KitNET**, and asymptotic complexity bounds designed for resource-constrained edge devices without GPU acceleration.

---

## 1. Asymptotic Computational Complexity: Ensemble Decomposition

Traditional deep-learning-based anomaly detectors typically deploy a monolithic three-layer autoencoder over a feature vector $\vec{x} \in \mathbb{R}^n$ with a hidden compression ratio $\beta \in (0, 1]$.

### 1.1. Monolithic Autoencoder: Quadratic Complexity
In a fully connected architecture with layers $l^{(1)}, l^{(2)}, l^{(3)}$ where $\vert{}l^{(1)}\vert{} = n$, $\vert{}l^{(2)}\vert{} = \lceil \beta n \rceil$, and $\vert{}l^{(3)}\vert{} = n$, computing the activations involves dense matrix-vector multiplications:

$$\mathcal{O}(\vert{}l^{(1)}\vert{} \cdot \vert{}l^{(2)}\vert{} + \vert{}l^{(2)}\vert{} \cdot \vert{}l^{(3)}\vert{}) = \mathcal{O}(n \cdot \beta n + \beta n \cdot n) = \mathcal{O}(n^2) \quad \text{(Equation 12)}$$

For Kitsune's canonical feature space ($n = 115$ continuous statistics, $\beta = 0.75$), a monolithic network requires approximately $2 \cdot 115 \cdot 87 \approx 20,010$ floating-point operations per packet. On high-throughput edge routers handling tens of thousands of packets per second, this computational burden inevitably causes queue exhaustion and packet dropping.

### 1.2. KitNET Ensemble Partitioning: $\mathcal{O}(k^2)$ Complexity
KitNET circumvents this bottleneck by projecting $\vec{x} \in \mathbb{R}^n$ into an ordered set of $k$ disjoint sub-instances:

$$v = \{\vec{v}_1, \vec{v}_2, \dots, \vec{v}_k\}, \quad \sum_{i=1}^k \dim(\vec{v}_i) = n, \quad \dim(\vec{v}_i) \le m$$

where $m$ is the upper bound parameter ($m \le 10$).

The architecture is decoupled into two processing stages:
1. **Ensemble Layer ($L^{(1)}$):** Consists of $k$ independent three-layer autoencoders $\{\theta_1, \dots, \theta_k\}$, where each $\theta_i$ reconstructs its assigned subspace $\vec{v}_i$. The cumulative execution complexity is:
   $$\mathcal{O}\left(\sum_{i=1}^k \dim(\vec{v}_i)^2\right) \le \mathcal{O}(k \cdot m^2)$$
2. **Output Layer ($L^{(2)}$):** A single autoencoder $\theta_0$ that takes the 0-1 normalized RMSE reconstruction error signals $\vec{z} \in [0, 1]^k$ as input. Its execution complexity is $\mathcal{O}(k \cdot \lceil \beta k \rceil) = \mathcal{O}(k^2)$.

The overall complexity for forward propagation and single-step Stochastic Gradient Descent (SGD) training is:

$$\mathcal{O}(k \cdot m^2 + k^2) = \mathcal{O}(k^2) \quad \text{(Equation 13)}$$

Because $m \le 10$ acts as a constant bound:
* **Optimal Case ($k = \lceil n/m \rceil$):** When $n = 115$ and $m = 10$, $k \approx 12$ autoencoders are instantiated. Multiplications drop to $\approx 1,920$ in $L^{(1)}$ and $\approx 216$ in $L^{(2)}$, speeding up packet processing by nearly an order of magnitude compared to a monolithic model.
* **Empirical Throughput:** Benchmarks demonstrate that KitNET increases single-core processing rates from $\approx 1,000$ packets/s ($k=1$) to $\approx 5,400$ packets/s ($k=35$) on an ARM Cortex-A53 (Raspberry Pi 3B @ 1.2 GHz), exceeding $37,000$ packets/s on commodity x86-64 CPUs.

---

## 2. Real-Time Streaming Feature Extraction: AfterImage

AfterImage maintains continuous traffic statistics across five damped exponential decay windows:

$$\lambda \in \{5, 3, 1, 0.1, 0.01\}$$

corresponding to temporal horizons of approximately 100 ms, 500 ms, 1.5 s, 10 s, and 60 s.

### 2.1. Continuous Exponential Decay
To eliminate packet buffering in memory ($\mathcal{O}(N)$), historical observations decay continuously as a function of elapsed time since the previous update on that channel:

$$d_\lambda(t) = 2^{-\lambda t}, \quad t = t_{\text{cur}} - T_{\text{last}} \quad \text{(Equation 6)}$$

### 2.2. Incremental Damped Updates ($\mathcal{O}(1)$)
Each monitored flow maintains an incremental statistic tuple:

$$IS_{i,\lambda} := \left(w, LS, SS, SR_{ij}, T_{\text{last}}\right)$$

where $w$ is the decayed weight, $LS$ is the linear sum, $SS$ is the squared sum, and $SR_{ij}$ is the sum of residual products across bidirectional streams. When a new packet metric $x_{\text{cur}}$ arrives at $t_{\text{cur}}$:

1. Decay factor computation: $\gamma = 2^{-\lambda (t_{\text{cur}} - T_{\text{last}})}$.
2. In-place tuple update in constant time and space $\mathcal{O}(1)$:
   $$w \leftarrow \gamma w + 1$$
   $$LS \leftarrow \gamma LS + x_{\text{cur}}$$
   $$SS \leftarrow \gamma SS + x_{\text{cur}}^2$$
   $$SR_{ij} \leftarrow \gamma SR_{ij} + (x_{\text{cur}}^{(i)} - \mu_i)(x_{\text{cur}}^{(j)} - \mu_j)$$
   $$T_{\text{last}} \leftarrow t_{\text{cur}}$$

Univariate (1D) and bivariate (2D) statistics are computed instantaneously:

$$\mu = \frac{LS}{w}, \quad \sigma = \sqrt{\max\left(0, \frac{SS}{w} - \mu^2\right)}, \quad \text{Cov}_{i,j} = \frac{SR_{ij}}{w_i + w_j}, \quad P_{i,j} = \frac{\text{Cov}_{i,j}}{\sigma_i \sigma_j}$$

---

## 3. Incremental Correlation Clustering and Feature Mapping

During `FM_grace_period`, the Feature Mapper summarizes cross-feature statistics to construct the correlation distance matrix $D \in \mathbb{R}^{n \times n}$:

$$D_{i,j} = 1 - \frac{C_{i,j}}{\sqrt{c_{rs}^{(i)}} \sqrt{c_{rs}^{(j)}}} \quad \text{(Equation 10)}$$

where $C_{i,j}$ represents the incremental residual covariance and $c_{rs}^{(i)}$ is the sum of squared residuals for feature $i$.

Once grace expires, agglomerative hierarchical clustering runs on $D$. Dendrogram links exceeding size $m$ are recursively severed until every cluster contains at most $m$ features. This groups correlated protocol behaviors into dedicated micro-autoencoders, isolating anomalous domain signals.

---

## 4. Defense Against State-Exhaustion DoS Attacks

In resource-constrained deployments, attackers may launch **State-Exhaustion DoS** attacks (NDSS 2018, Section VI) by injecting high-frequency packets with randomized IP addresses and ports to exhaust hash table memory.

### 4.1. Memory Bounds
A bidirectional network conversation monitored across all 5 decay windows consumes $\approx 1$ KB of RAM. A 1 MB memory cap accommodates $\approx 1,000$ concurrent active links.

### 4.2. $\mathcal{O}(1)$ Amortized Pruning
Because rapid decay scales ($\lambda \ge 1$) drop toward zero within milliseconds of channel inactivity, AfterImage implements passive memory reclamation:

$$\text{If } w_i < \epsilon \quad (\epsilon \approx 10^{-5}), \quad \text{evict } IS_{i,\lambda} \text{ from the hash map.}$$

Transient scanning bursts (such as port scans with spoofed source IPs) decay instantaneously and are purged without incurring table contention or degrading capture throughput.

---

## 5. Log-Normal Threshold Calibration

To operate autonomously with a bounded false positive rate ($FPR \le 0.001$), reconstruction RMSE scores during benign calibration (`AD_grace_period`) are fitted to a log-normal distribution:

$$\ln(s) \sim \mathcal{N}(\mu_{\log}, \sigma_{\log}^2)$$

Maximum Likelihood Estimation (MLE) over $N$ clean calibration instances yields:

$$\hat{\mu}_{\log} = \frac{1}{N} \sum_{i=1}^N \ln(s_i), \quad \hat{\sigma}_{\log} = \sqrt{\frac{1}{N} \sum_{i=1}^N \left(\ln(s_i) - \hat{\mu}_{\log}\right)^2}$$

The analytical detection cutoff $\tau$ at the $99.9\text{th}$ percentile ($Z_{0.999} \approx 3.0902$) is:

$$\tau = \exp\left(\hat{\mu}_{\log} + 3.0902 \cdot \hat{\sigma}_{\log}\right)$$

In execution mode, any packet satisfying $RMSE(x) > \tau$ triggers an immediate alert without manual threshold tuning.