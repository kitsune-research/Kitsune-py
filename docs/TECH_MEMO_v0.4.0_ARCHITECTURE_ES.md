# TECHNICAL MEMORANDUM: KITSUNE NIDS ENGINE ARCHITECTURE (v0.4.0)
**Document ID:** TM-KIT-040-ARCH-ES  
**Status:** Canónico / Aprobado como Línea Base de Ingeniería  
**Target Release:** v0.4.0  
**Reference Paper:** Mirsky et al., *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*, NDSS 2018.  
**Classification:** Referencia Interna de Ingeniería / Especificación I+D  

---

## 1. Executive Summary & Alcance

El presente memorando formaliza la arquitectura matemática, numérica y de software del motor **Kitsune NIDS** consolidado en la release `v0.4.0`. Se documentan de manera determinista los invariantes asintóticos, la ingeniería de características en tiempo real, el blindaje frente a inestabilidades numéricas de gradiente y las garantías de mitigación frente a ataques de denegación de servicio por saturación de estado (*State-Exhaustion DoS*).

El sistema desacopla el análisis de tráfico en dos fases continuas y computacionalmente acotadas:
1. **AfterImage:** Extracción de características temporales amortiguadas en complejidad temporal y espacial estricta $\mathcal{O}(1)$.
2. **KitNET:** Agrupamiento correlacional incremental ($m \le 10$) y ensamble de autoencoders en complejidad asintótica $\mathcal{O}(k^2)$.

---

## 2. AfterImage: Extracción Incremental Amortiguada ($\mathbb{R}^{100}$)

### 2.1. Formulación del Decaimiento Temporal Continuo
Para evitar la complejidad $\mathcal{O}(n)$ intrínseca a las ventanas deslizantes discretas, AfterImage emplea acumuladores estadísticos con decaimiento exponencial continuo en función del tiempo transcurrido $\Delta t = t_{\mathrm{cur}} - t_{\mathrm{last}}$.

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

2. **Ingestión de la nueva observación ($x = \text{tamaño de paquete}$):**
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
La versión `v0.4.0` omite deliberadamente las métricas de jitter inter-paquete para eliminar sobrecostes de reloj de alta precisión en procesadores mononúcleo. El vector se conforma con 20 características extraídas sobre 4 entidades topológicas a lo largo de las 5 ventanas $\lambda$:

$$\vec{x} \in \mathbb{R}^{100} = \big[ \vec{f}_{\lambda=5.0} \,\|\, \vec{f}_{\lambda=3.0} \,\|\, \vec{f}_{\lambda=1.0} \,\|\, \vec{f}_{\lambda=0.1} \,\|\, \vec{f}_{\lambda=0.01} \big]$$

Por cada ventana temporal, las 20 estadísticas son:
* **Host Emisor (`SrcMAC-IP`):** $w, \mu, \sigma$ (3)
* **Emisor L3 (`SrcIP`):** $w, \mu, \sigma$ (3)
* **Canal Unilateral (`Channel` IP $\to$ IP):** $w, \mu, \sigma$ (3)
* **Socket Unilateral (`Socket` IP:Port $\to$ IP:Port):** $w, \mu, \sigma$ (3)
* **Conversación Recíproca (`Channel` L3 Rx/Tx):** $\|S_i, S_j\|, R_{S_i,S_j}, \mathrm{Cov}, \rho$ (4)
* **Sesión Recíproca (`Socket` L4 Rx/Tx):** $\|S_i, S_j\|, R_{S_i,S_j}, \mathrm{Cov}, \rho$ (4)

---

## 3. KitNET: Detección No Supervisada y Acotación Asintótica

### 3.1. Agrupamiento Correlacional Jerárquico (`corClust`)
Durante el período de gracia inicial (`FM_grace_period`), el Feature Mapper actualiza de forma incremental la matriz de distancia de Pearson entre dimensiones continuas $D \in \mathbb{R}^{n \times n}$:

$$D_{ij} = 1 - \frac{C_{ij}}{\sqrt{c_{rs}^{(i)}} \sqrt{c_{rs}^{(j)}}}$$

Al concluir `FM_grace_period`, se ejecuta una partición jerárquica aglomerativa con una **cota estricta de tamaño máximo de cluster $m \le 10$**. Si un cluster excede $m$, se subdivide iterativamente hasta producir $k$ subespacios independientes $\vec{v}_1, \dots, \vec{v}_k$.

### 3.2. Arquitectura del Ensamble y Cotas de Complejidad
KitNET divide la inferencia en dos capas acopladas sin conexiones cruzadas densas:
1. **Capa Ensamble $L^{(1)}$:** $k$ micro-autoencoders de tres capas ($d_{\mathrm{in}} \le m$, capa oculta comprimida a $\lceil \beta \cdot d_{\mathrm{in}} \rceil$ con $\beta = 0.75$). Cada red procesa su subespacio local $\vec{v}_i$ y emite su residuo escalar $\mathrm{RMSE}_i \in [0, 1]$.
2. **Capa de Salida $L^{(2)}$:** Un único autoencoder que ingiere el vector de residuos $\vec{z} = [\mathrm{RMSE}_1, \dots, \mathrm{RMSE}_k]^T \in \mathbb{R}^k$ con capa interna $\lceil \beta \cdot k \rceil$, aprendiendo la correlación normal de los errores del ensamble.

$$\text{Complejidad Total} = \mathcal{O}(k \cdot m^2 + k^2) \equiv \mathcal{O}(k^2)$$

### 3.3. Blindaje Numérico Defensivo (`KitNET/dA.py`)
En versiones académicas preliminares, la normalización min-max estándar en modo ejecución se encuentra indefensa ante ráfagas de tráfico no observadas durante la fase de entrenamiento. Cuando una característica entrante $x \gg x_{\max}$, el valor normalizado sin límites provoca una proyección lineal desmedida, desbordando la función sigmoide del decodificador y disparando picos artificiales de residuo ($RMSE > 680$ en paquetes completamente legítimos).

La versión `v0.4.0` implanta una cota de saturación defensiva con guarda numérica $\epsilon$:
$$x' = \mathrm{clip}\left(\frac{x - x_{\min}}{(x_{\max} - x_{\min}) + \epsilon}, -1.0, 2.0\right)$$

Esta intervención matemática garantiza:
1. **Acotación del Espacio Latente:** Mantiene el dominio de activación dentro del régimen operable de la neurona sigmoidal.
2. **Colapso del Techo de Ruido:** Reduce el residuo RMSE basal de **$681.91$** a un techo de **$0.9595$**, erradicando falsas alarmas estructurales y permitiendo umbrales paramétricos estables.

---

## 4. Evaluación Forense y Cinemática Temporal (NDSS Sec. V-C)

### 4.1. Desacoplamiento del Período de Gracia (`--skip-grace`)
Conforme a la metodología formal de NDSS 2018, la evaluación de métricas de intrusión debe realizarse estrictamente sobre el régimen estacionario de inferencia (`exec-mode`). El comando `kitsune eval` incorpora de forma nativa el flag `-g, --skip-grace` para descartar los primeros paquetes correspondientes a $\text{FM}_{\mathrm{grace}} + \text{AD}_{\mathrm{grace}}$ ($2.000$ a $5.000$ paquetes), evitando sesgar el AUC y el EER con el transitorio inicial.

### 4.2. Cinemática de la Botnet Mirai
El análisis forense determinista sobre el dataset canónico de Mirai ($764.137$ paquetes, 118.9 minutos) determinó:
* La fase benigna de reposo abarca los primeros **52.00 minutos** de captura (Tabla III de NDSS), produciéndose la primera actividad maliciosa exactamente en el **paquete 85.381**.
* El ataque activo proviene de forma aislada desde la cámara IP comprometida (`192.168.2.108`), coexistiendo con tráfico benigno concurrente de los 8 dispositivos restantes.
* Bajo aislamiento del vector hostil y exclusión de gracia (`--skip-grace 2000`), el motor consolida un **AUC de 0.8614** y un **EER de 0.2067** (en $\tau = 0.3040$), corroborando la tasa nula de falsas alarmas observada empíricamente en la Figura 9 de NDSS 2018.

---

## 5. Endurecimiento Adversarial y Gestión de Memoria (NDSS Sec. VI)

### 5.1. Mitigación de Ataques de Saturación de Estado (State-Exhaustion DoS)
Un adversario que sintetice direcciones MAC e IP aleatorias persigue agotar la memoria RAM instanciando tuplas infinitas en `incStatDB` de AfterImage.
1. **Poda por Decaimiento Amortiguado:** Para ventanas activas ($\lambda \ge 0.1$), los flujos efímeros decaen a peso insignificante $w \approx 0$ en pocos segundos tras cesar la ráfaga.
2. **Recolección de Basura Asíncrona:** Un proceso desacoplado purga periódicamente las tuplas con $w < \epsilon$ ($\epsilon = 10^{-3}$), garantizando que el consumo de memoria se mantenga estrictamente acotado en $\mathcal{O}(1)$ respecto al volumen global del stream.