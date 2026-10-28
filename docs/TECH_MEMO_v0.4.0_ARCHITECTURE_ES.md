# TECHNICAL MEMORANDUM: KITSUNE NIDS ENGINE ARCHITECTURE (v0.3.1)
**Document ID:** TM-KIT-031-ARCH  
**Status:** Canonical / Approved Internal  
**Target Release:** v0.3.1  
**Reference Paper:** Mirsky et al., *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*, NDSS 2018.  
**Classification:** Internal Engineering Reference / R&D Specification  

---

## 1. Executive Summary & Scope

El presente memorando formaliza la arquitectura matemática y de software del motor **Kitsune NIDS** implementado en la rama de producción `v0.3.1` (`src/kitsune`). Se documentan de manera determinista los invariantes asintóticos, la ingeniería de características en tiempo real y las garantías de mitigación frente a ataques de denegación de servicio por saturación de estado (*State-Exhaustion DoS*).

El sistema desacopla el análisis de tráfico en dos fases continuas y computacionalmente acotadas:
1. **AfterImage:** Extracción de características temporales amortiguadas en complejidad $\mathcal{O}(1)$.
2. **KitNET:** Agrupamiento correlacional incremental ($m \le 10$) y ensamble de autoencoders en complejidad $\mathcal{O}(k^2)$.

---

## 2. AfterImage: Extracción Incremental Amortiguada ($\mathbb{R}^{100}$)

### 2.1. Formulación del Decaimiento Temporal
Para evitar la complejidad espacial y temporal $\mathcal{O}(n)$ de una ventana deslizante discreta, AfterImage emplea acumuladores estadísticos con decaimiento exponencial continuo en función del tiempo transcurrido $\Delta t = t_{\mathrm{cur}} - t_{\mathrm{last}}$.

La función de decaimiento continuo se define como:
$$d_\lambda(\Delta t) = 2^{-\lambda \cdot \Delta t}$$

donde $\lambda > 0$ es el factor de amortiguamiento calibrado para 5 horizontes temporales operativos:
* $\lambda = 5.0 \implies \tau_{1/2} \approx 100\,\mathrm{ms}$ (Ráfagas volumétricas y DoS L4).
* $\lambda = 3.0 \implies \tau_{1/2} \approx 500\,\mathrm{ms}$ (Dinámica de handshake TCP).
* $\lambda = 1.0 \implies \tau_{1/2} \approx 1.5\,\mathrm{s}$ (Cadencia de flujos de control).
* $\lambda = 0.1 \implies \tau_{1/2} \approx 10\,\mathrm{s}$ (Comportamientos sostenidos y streaming).
* $\lambda = 0.01 \implies \tau_{1/2} \approx 60\,\mathrm{s}$ (Línea base estacionaria y balizas periódicas C2).

### 2.2. Ecuaciones de Actualización Incremental en $\mathcal{O}(1)$
Por cada flujo observado, el extractor actualiza una tupla de estado unidimensional $\mathrm{IS}_{1\mathrm{D}} = (w, \mathrm{LS}, \mathrm{SS})$ y bidimensional $\mathrm{IS}_{2\mathrm{D}} = (\mathrm{IS}_i, \mathrm{IS}_j, \mathrm{SR}_{ij})$:

1. **Aplicación del factor de decaimiento:**
   $$\gamma = d_\lambda(t_{\mathrm{cur}} - t_{\mathrm{last}})$$
   $$w \leftarrow \gamma \cdot w, \quad \mathrm{LS} \leftarrow \gamma \cdot \mathrm{LS}, \quad \mathrm{SS} \leftarrow \gamma \cdot \mathrm{SS}, \quad \mathrm{SR}_{ij} \leftarrow \gamma \cdot \mathrm{SR}_{ij}$$

2. **Ingestión de la nueva observación de tamaño de paquete $x$:**
   $$w \leftarrow w + 1$$
   $$\mathrm{LS} \leftarrow \mathrm{LS} + x$$
   $$\mathrm{SS} \leftarrow \mathrm{SS} + x^2$$
   $$\mathrm{SR}_{ij} \leftarrow \mathrm{SR}_{ij} + (x_i - \mu_i)(x_j - \mu_j)$$

3. **Cálculo de estadísticas instantáneas:**
   * Media: $\mu = \frac{\mathrm{LS}}{w}$
   * Varianza y Desviación Típica: $\sigma^2 = \left| \frac{\mathrm{SS}}{w} - \left(\frac{\mathrm{LS}}{w}\right)^2 \right|, \quad \sigma = \sqrt{\sigma^2}$
   * Covarianza Bidireccional: $\mathrm{Cov}_{ij} = \frac{\mathrm{SR}_{ij}}{w_i + w_j}$
   * Coeficiente de Correlación de Pearson: $\rho_{ij} = \frac{\mathrm{Cov}_{ij}}{\sigma_i \cdot \sigma_j}$

### 2.3. Partición del Vector de Salida ($\mathbb{R}^{100}$)
La implementación en `v0.3.1` omite deliberadamente las métricas de jitter inter-paquete para eliminar sobrecostes de reloj de alta precisión en procesadores de red de baja potencia. El vector se conforma con 20 características extraídas sobre 4 entidades topológicas a lo largo de las 5 ventanas $\lambda$:

$$\vec{x} \in \mathbb{R}^{100} = \big[ \vec{f}_{\lambda=5.0} \,\|\, \vec{f}_{\lambda=3.0} \,\|\, \vec{f}_{\lambda=1.0} \,\|\, \vec{f}_{\lambda=0.1} \,\|\, \vec{f}_{\lambda=0.01} \big]$$

Por cada ventana temporal, las 20 estadísticas son:
* **Host Emisor (`SrcMAC-IP`):** $w, \mu, \sigma$ (3)
* **Emisor L3 (`SrcIP`):** $w, \mu, \sigma$ (3)
* **Canal Unilateral (`Channel` IP $\to$ IP):** $w, \mu, \sigma$ (3)
* **Socket Unilateral (`Socket` IP:Port $\to$ IP:Port):** $w, \mu, \sigma$ (3)
* **Conversación Recíproca (`Channel` L3 Rx/Tx):** $\|S_i, S_j\|, R_{S_i,S_j}, \mathrm{Cov}, \rho$ (4)
* **Sesión Recíproca (`Socket` L4 Rx/Tx):** $\|S_i, S_j\|, R_{S_i,S_j}, \mathrm{Cov}, \rho$ (4)

Si la trama no transporta puertos L4 (ej. ICMP, ARP), los canales de socket se rellenan con $0.0$, manteniendo constante la dimensión del tensor de entrada.

---

## 3. KitNET: Detección No Supervisada y Acotación Asintótica

### 3.1. Agrupamiento Correlacional Jerárquico (corClust)
Durante el período de gracia inicial (`FM_grace_period`), el Feature Mapper actualiza de forma incremental la matriz de distancia de Pearson entre dimensiones continuas $D \in \mathbb{R}^{n \times n}$:

$$D_{ij} = 1 - \frac{C_{ij}}{\sqrt{c_{rs}^{(i)}} \sqrt{c_{rs}^{(j)}}}$$

Al concluir `FM_grace_period`, se ejecuta una partición jerárquica aglomerativa con una **cota estricta de tamaño máximo de cluster $m \le 10$**. Si un cluster excede $m$, se subdivide iterativamente hasta producir $k$ subespacios independientes $\vec{v}_1, \dots, \vec{v}_k$.

### 3.2. Arquitectura del Ensamble y Cotas de Complejidad
KitNET divide la inferencia en dos capas acopladas sin conexiones cruzadas densas:
1. **Capa Ensamble $L^{(1)}$:** $k$ micro-autoencoders de tres capas ($d_{\mathrm{in}} \le m$, capa oculta comprimida a $\lceil \beta \cdot d_{\mathrm{in}} \rceil$ con $\beta = 0.75$). Cada red procesa su subespacio local $\vec{v}_i$ y emite su residuo escalar $\mathrm{RMSE}_i \in [0, 1]$.
2. **Capa de Salida $L^{(2)}$:** Un único autoencoder que ingiere el vector de residuos $\vec{z} = [\mathrm{RMSE}_1, \dots, \mathrm{RMSE}_k]^T \in \mathbb{R}^k$ con capa interna $\lceil \beta \cdot k \rceil$, aprendiendo la correlación normal de los errores del ensamble.

#### Demostración Asintótica:
* Un autoencoder monolítico sobre $\mathbb{R}^n$ exhibe un coste de activación:
  $$\mathcal{O}(n \cdot \beta n) = \mathcal{O}(n^2)$$
* En KitNET, con $m \le 10$ constante:
  $$\mathcal{O}(L^{(1)}) = \sum_{i=1}^k \mathcal{O}(m_i^2) \le \mathcal{O}(k \cdot m^2) = \mathcal{O}(k)$$
  $$\mathcal{O}(L^{(2)}) = \mathcal{O}(k \cdot \beta k) = \mathcal{O}(k^2)$$
  $$\text{Complejidad Total} = \mathcal{O}(k \cdot m^2 + k^2) \equiv \mathcal{O}(k^2)$$

Como $k \le n$, en el caso típico $k \ll n$, el sistema reduce el consumo computacional por un factor superior a $5\times$ frente a redes densas estándar, permitiendo ejecución determinista en procesadores de red mononúcleo.

### 3.3. Aprendizaje Online y Función de Decisión
* **Optimizador:** Descenso de Gradiente Estocástico (SGD) de pasada única (`max_iter = 1`) durante `AD_grace_period`. Cada instancia se descarta inmediatamente tras actualizar pesos.
* **Métrica de Detección:** Error Cuadrático Medio de Reconstrucción de la capa $L^{(2)}$:
  $$\mathrm{score} = \mathrm{RMSE}(\vec{z}, \hat{\vec{z}}) = \sqrt{\frac{1}{k} \sum_{j=1}^k (z_j - \hat{z}_j)^2}$$
* **Corte Analítico ($\tau$):** Modelado log-normal del residuo durante régimen benigno:
  $$\ln(\mathrm{RMSE}) \sim \mathcal{N}(\mu_{\ln}, \sigma_{\ln}^2) \implies \tau = \exp(\mu_{\ln} + \alpha \cdot \sigma_{\ln})$$

---

## 4. Endurecimiento Adversarial y Gestión de Memoria (NDSS Sec. VI)

### 4.1. Mitigación de Ataques de Agotamiento de Estado (State-Exhaustion DoS)
Un adversario que transmita tráfico con direcciones IP/MAC sintetizadas aleatoriamente busca forzar la instanciación infinita de tuplas en las tablas hash de AfterImage (`incStatDB`), provocando la caída del sistema por falta de memoria RAM.

**Contramedida implementada:**
1. **Poda Periódica por Decaimiento Amortiguado:** Dado que $d_\lambda(\Delta t) \to 0$ rápidamente para $\lambda \ge 0.1$, los flujos efímeros generados por escaneos o flooding alcanzan un peso residual $w \approx 0$ tras escasos segundos sin actividad.
2. **Recolección de Basura de Flujo:** Un ciclo de mantenimiento desacoplado barre periódicamente las tablas hash y purga cualquier entrada con $w < \epsilon$ ($\epsilon = 10^{-3}$), manteniendo acotada la huella de memoria por debajo de los límites físicos del dispositivo.

### 4.2. Blindaje contra Envenenamiento de Línea Base
Para mitigar la contaminación de la distribución durante `AD_grace_period`, el motor soporta ejecución en modo de pre-filtrado: cualquier instancia que registre un residuo anómalo provisional no se retropropaga en los pesos sinápticos, impidiendo que ataques lentos (*low-and-slow*) corrompan el espacio latente.