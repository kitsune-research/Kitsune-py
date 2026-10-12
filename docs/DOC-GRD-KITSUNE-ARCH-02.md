# Doc 2: Especificación Formal de Arquitectura y Diseño de Sistemas
### *Kitsune NIDS: Ingeniería de Ingesta Streaming, Ensamble KitNET y Calibración Estocástica en el Edge (Nivel Máster GRD / EQF 7)*

---

## Control del Documento y Metadatos de Ingeniería

* **Identificador de Especificación:** `DOC-GRD-KITSUNE-ARCH-02`[cite: 1]
* **Nivel de Clasificación Técnica:** Nivel MECES 3 / European Qualifications Framework Level 7 (Arquitectura de Ciberseguridad / Inferencia Distribuida)
* **Entidades y Repositorios:** Organización upstream `kitsune-research/Kitsune-py` y nodo de portafolio `paradiselord-dev/Kitsune-py`[cite: 1]
* **Base Teórica e Implementación:** Y. Mirsky et al., *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*, NDSS 2018[cite: 1, 2]
* **Pila Tecnológica:** Python 3.9+ / 3.11.9, NumPy 2.x, Scapy, Cython/C-extensions, empaquetado bajo estándar PEP 517/621 (`pyproject.toml`)[cite: 1]
* **Propósito:** Definir formalmente las ecuaciones estocásticas, las estructuras de datos en memoria $\mathcal{O}(1)$, la topología de la falange neuronal KitNET y los contratos de interfaz de software de la suite `src/kitsune`[cite: 1, 2].

---

## 1. Núcleo Matemático de AfterImage (Extracción Streaming en $\mathcal{O}(1)$)

AfterImage opera como un procesador de flujo continuo diseñado para transformar paquetes binarios crudos en representaciones paramétricas sin retener historial en memoria[cite: 2, 7].

```
Paquete Entrante (t_cur, x_cur)
               │
               ▼
┌────────────────────────────────────────────────────────┐
│     Búsqueda en Hash Table por Clave de Flujo          │
│     (SrcMAC-IP, SrcIP, Channel IP-IP, Socket)          │
└──────────────────────────────┬─────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────┐
│     Cálculo de Decaimiento Continuo en Hardware        │
│     γ = 2^(-λ · (t_cur - T_last))                      │
└──────────────────────────────┬─────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────┐
│     Actualización de Tupla Amortiguada IS_{i,λ}        │
│     w  = γ·w + 1                                       │
│     LS = γ·LS + x_cur                                  │
│     SS = γ·SS + (x_cur)²                               │
│     SR = γ·SR + residual_cross                         │
│     T_last = t_cur                                     │
└──────────────────────────────┬─────────────────────────┘
                               │
                               ▼
      Trama Descartada de RAM / Vector x ∈ ℝ¹¹⁵ a KitNET
```

### 1.1 Dinámica Temporal y Operador de Decaimiento Exponencial
Sea $S_i = \{x_1, x_2, \dots\}$ una secuencia infinita no acotada de observaciones (ej. tamaños de paquete o retardos temporales entre llegadas)[cite: 7]. Para priorizar el comportamiento reciente frente a eventos pasados sin utilizar colas FIFO, se define el operador de decaimiento continuo[cite: 7]:

$$d_\lambda(\Delta t) = 2^{-\lambda \Delta t}$$
[cite: 7]

Donde:
* $\Delta t = t_{\text{cur}} - T_{\text{last}} \ge 0$ es el tiempo físico transcurrido desde el último paquete observado en dicho canal[cite: 7, 8].
* $\lambda > 0$ es el factor de amortiguamiento (*decay factor*)[cite: 7].
* La base 2 se selecciona frente a $e$ para permitir desplazamientos y multiplicaciones eficientes a nivel de registros de bajo nivel en microprocesadores embebidos[cite: 7].

### 1.2 Formulación Univariada (1D) y Bivariada (2D) de la Tupla $IS_{i,\lambda}$
Para cada canal o entidad de red activa se mantiene en memoria una tupla invariante[cite: 7, 8]:

$$IS_{i,\lambda} := \left( w_i, LS_i, SS_i, SR_{ij}, T_{\text{last}}^{(i)} \right)$$
[cite: 7, 8]

* $w_i \in \mathbb{R}^+$: Conteo o peso amortiguado de paquetes[cite: 7, 8].
* $LS_i = \sum \gamma_k x_k$: Suma lineal amortiguada[cite: 7, 8].
* $SS_i = \sum \gamma_k x_k^2$: Suma cuadrática amortiguada[cite: 7, 8].
* $SR_{ij} = \sum \gamma_k (x_k^{(i)} - \mu_i)(x_k^{(j)} - \mu_j)$: Suma amortiguada de productos residuales cruzados entre los canales de transmisión ($S_i$) y recepción ($S_j$)[cite: 8].
* $T_{\text{last}}^{(i)} \in \mathbb{R}^+$: Marca de tiempo UNIX de la última actualización[cite: 7, 8].

#### Derivación de Estadísticas Instantáneas en $\mathcal{O}(1)$

| Dimensión | Métrica Extraída | Notación | Ecuación de Cómputo Directo |
| :--- | :--- | :--- | :--- |
| **1D** | Peso Amortiguado | $w_i$ | $w_i$ directo de la tupla[cite: 8] |
| **1D** | Media Instantánea | $\mu_{S_i}$ | $\frac{LS_i}{w_i}$[cite: 8] |
| **1D** | Varianza | $\sigma_{S_i}^2$ | $\max\left(0.0, \, \frac{SS_i}{w_i} - \left(\frac{LS_i}{w_i}\right)^2\right)$[cite: 8] |
| **1D** | Desviación Estándar | $\sigma_{S_i}$ | $\sqrt{\sigma_{S_i}^2}$[cite: 8] |
| **2D** | Magnitud de Flujo | $\Vert{}S_i, S_j\Vert{}$ | $\sqrt{\mu_{S_i}^2 + \mu_{S_j}^2}$[cite: 8] |
| **2D** | Radio de Dispersión | $R_{S_i, S_j}$ | $\sqrt{\sigma_{S_i}^2 + \sigma_{S_j}^2}$[cite: 8] |
| **2D** | Covarianza Aproximada | $Cov_{S_i, S_j}$ | $\frac{SR_{ij}}{w_i + w_j}$[cite: 8] |
| **2D** | Coeficiente de Correlación | $\rho_{S_i, S_j}$ | $\frac{Cov_{S_i, S_j}}{\sigma_{S_i} \cdot \sigma_{S_j}}$[cite: 8] |

### 1.3 Mapeo Multiescala y Extracción del Vector $\vec{x} \in \mathbb{R}^{115}$
AfterImage ejecuta simultáneamente cinco instancias de decaimiento temporal sobre cada canal observador[cite: 2, 8]:

$$\Lambda = \{\lambda_1=5, \, \lambda_2=3, \, \lambda_3=1, \, \lambda_4=0.1, \, \lambda_5=0.01\}$$
[cite: 8]

Estas tasas mapean respectivamente horizontes físicos de **100 ms, 500 ms, 1.5 s, 10 s y 60 s**[cite: 8]. En cada ventana temporal se calculan 23 características distribuidas jerárquicamente[cite: 8]:
1. **SrcMAC-IP (8 métricas):** Peso, media y desviación de tamaño saliente; y métricas 2D de host físico[cite: 8, 9].
2. **SrcIP (4 métricas):** Conteo y volumen univariado del emisor lógico[cite: 8, 9].
3. **Channel IP-IP (8 métricas):** Volumen bidireccional, covarianzas y retardos de llegada (*jitter*)[cite: 8, 9].
4. **Socket de Transporte (3 métricas):** Conexión activa Capa 4 (IP/Puerto origen contra IP/Puerto destino)[cite: 8, 9].

$$23 \text{ métricas por horizonte} \times 5 \text{ valores de } \lambda = \mathbf{115 \text{ dimensiones}}$$
$\vec{x} \in \mathbb{R}^{115}$[cite: 8]

*(Nota técnica: En subconjuntos sin capa de transporte TCP/UDP, los campos de socket se normalizan a cero, preservando la dimensión fija de 115 variables)[cite: 8].*

### 1.4 Mecanismo de Poda Pasiva y Resiliencia Anti-DoS de Estado
Frente a ataques volumétricos con suplantación de direcciones IP (*IP Spoofing*) concebidos para agotar la tabla de estados (*State-Exhaustion DoS*), AfterImage aplica poda determinista pasiva[cite: 7, 15]:
* Si un canal no recibe tráfico subsiguiente, su peso decae: $w(t) = w_0 \cdot 2^{-\lambda \Delta t}$[cite: 7, 8].
* Se establece un umbral de obsolescencia $\epsilon = 10^{-5}$[cite: 15].
* El recolector de memoria purga periódicamente la entrada de la tabla hash cuando se cumple la condición de desalojo[cite: 15]:

$$\text{Desalojar flujo } S_i \iff w_i < \epsilon$$
[cite: 15]

Esto garantiza una huella espacial confinada a **$\sim 1$ MB de RAM para 1.000 conversaciones activas concurrentes**, asegurando estabilidad en microcontroladores y SoCs industriales[cite: 15].

---

## 2. Topología Desacoplada de KitNET (Reducción $\mathcal{O}(k^2)$)

KitNET sustituye el enfoque de autoencoder monolítico por una arquitectura descentralizada de dos niveles: la **Capa de Ensamble ($L^{(1)}$)** y la **Capa de Salida ($L^{(2)}$)**[cite: 3, 9, 10].

```
                 Vector Entrante x ∈ ℝ¹¹⁵ (AfterImage)
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
   [ Período FM_grace_period ]               [ Período AD_grace_period ]
   Actualización incremental C_{i,j}         Entrenamiento SGD (max_iter = 1)
   Construcción de Dendrograma D             Ajuste de pesos en L(1) y L(2)
   Poda jerárquica con cota m ≤ 10           Congelación de pesos
              │                                         │
              └────────────────────┬────────────────────┘
                                   │
                                   ▼
             [ MODO DE EJECUCIÓN PURA (exec-mode) ]
             
    Subespacio v₁          Subespacio v₂          Subespacio vₖ
     (m ≤ 10 vars)          (m ≤ 10 vars)          (m ≤ 10 vars)
           │                      │                      │
     ┌─────┴──────┐         ┌─────┴──────┐         ┌─────┴──────┐
     │  Micro-AE₁ │         │  Micro-AE₂ │   ···   │  Micro-AEₖ │   CAPA L(1)
     │  (β = 0.75)│         │  (β = 0.75)│         │  (β = 0.75)│
     └─────┬──────┘         └─────┬──────┘         └─────┬──────┘
           │ RMSE₁                │ RMSE₂                │ RMSEₖ
           └──────────────┬───────┴──────────────────────┘
                          ▼
            Vector de Residuos z ∈ ℝᵏ (Normalizado [0, 1])
                          │
                  ┌───────┴───────┐
                  │ Autoencoder θ₀│                           CAPA L(2)
                  │ Capa de Salida│
                  └───────┬───────┘
                          ▼
                Score RMSE Global (s)
```

### 2.1 Mapeo Correlacional No Supervisado (`corClust`)
Durante los primeros paquetes de la red (`FM_grace_period`), el componente Feature Mapper recopila la estructura de covarianza entre dimensiones sin instanciar autoencoders[cite: 2, 8, 9].

#### Matriz de Distancia Correlacional Incremental
Para cada observación entrante $\vec{x}_t$, se actualizan los acumuladores de suma lineal ($c^{(i)}$), suma de residuos ($c_r^{(i)}$) y suma cuadrática de residuos ($c_{rs}^{(i)}$)[cite: 9]:

$$c_{rs}^{(i)} = \sum_{t=0}^{n_t} \left(x_t^{(i)} - \frac{c^{(i)}}{n_t}\right)^2$$
[cite: 9]

$$C_{i,j} = \sum_{t=0}^{n_t} \left(x_t^{(i)} - \frac{c^{(i)}}{n_t}\right)\left(x_t^{(j)} - \frac{c^{(j)}}{n_t}\right)$$
[cite: 9]

La matriz de distancia correlacional $D \in \mathbb{R}^{n \times n}$ se obtiene analíticamente en cualquier instante mediante[cite: 9]:

$$D_{i,j} = 1 - \frac{C_{i,j}}{\sqrt{c_{rs}^{(i)} \cdot c_{rs}^{(j)}}}$$
[cite: 9]

#### Algoritmo de Poda del Dendrograma
1. Se aplica agrupamiento jerárquico aglomerativo sobre $D$, enlazando iterativamente los pares de menor distancia correlacional hasta formar un único árbol binario[cite: 9].
2. Se evalúa el nodo raíz superior: si el número de variables contenidas excede la cota rígida $m$ ($m \le 10$), el enlace se fractura recursivamente[cite: 9, 11].
3. El proceso concluye cuando todas las ramas resultantes satisfacen la condición de acotación[cite: 9]:

$$\vert{}V_p\vert{} \le m \quad \forall p \in \{1, \dots, k\}, \quad \bigcup_{p=1}^k V_p = \{1, \dots, n\}, \quad V_p \cap V_q = \emptyset$$
[cite: 8, 9]

Se generan así $k$ subespacios disjuntos que mapean el vector original en micro-instancias $\vec{v}_1, \dots, \vec{v}_k$[cite: 8, 9].

### 2.2 Capa de Ensamble ($L^{(1)}$): Micro-Autoencoders Especializados
La Capa de Ensamble se define formalmente como[cite: 9]:

$$L^{(1)} = \{\theta_1, \theta_2, \dots, \theta_k\}$$
[cite: 9]

Cada micro-autoencoder $\theta_i$ se parametriza con una topología feed-forward simétrica de tres capas[cite: 4, 9]:
* **Capa Visible de Entrada:** $\vert{}l_1\vert{} = dim(\vec{v}_i) \le m$[cite: 9].
* **Capa Oculta (Cuello de Botella):** $\vert{}l_2\vert{} = \lceil \beta \cdot dim(\vec{v}_i) \rceil$, donde $\beta = 0.75$[cite: 9, 10].
* **Capa Visible de Salida:** $\vert{}l_3\vert{} = dim(\vec{v}_i)$[cite: 4, 9].

#### Función de Activación y Normalización Local
Las entradas a cada micro-autoencoder se proyectan en el rango $[0, 1]$ mediante seguimiento de mínimos y máximos locales acumulados durante el período de entrenamiento[cite: 10]:

$$\vec{v}_{i,\text{norm}} = \frac{\vec{v}_i - \vec{v}_{i,\min}}{\vec{v}_{i,\max} - \vec{v}_{i,\min} + \epsilon_{\text{div}}}$$
[cite: 10]

La propagación hacia adelante (*forward propagation*) utiliza la función sigmoide logística[cite: 4]:

$$f(z) = \frac{1}{1 + e^{-z}}$$
[cite: 4]

El error cuadrático medio local de reconstrucción para cada micro-autoencoder $\theta_i$ se expresa como[cite: 5, 9]:

$$RMSE_i(\vec{v}_{i,\text{norm}}, \hat{\vec{v}}_{i}) = \sqrt{\frac{1}{dim(\vec{v}_i)} \sum_{j=1}^{dim(\vec{v}_i)} \left(v_{i,\text{norm}}^{(j)} - \hat{v}_i^{(j)}\right)^2}$$
[cite: 5]

### 2.3 Capa de Salida ($L^{(2)}$): Árbitro Relacional No Lineal
La Capa de Salida está compuesta por un único autoencoder $\theta_0$ encargado de modelar las dependencias funcionales cruzadas entre las señales de error de la primera capa[cite: 9, 10]:

$$\vec{z} = \left[ RMSE_1, \, RMSE_2, \, \dots, \, RMSE_k \right]^T \in \mathbb{R}^k$$
[cite: 9, 10]

Topología de $\theta_0$[cite: 10]:
* **Entrada/Salida:** $k$ neuronas[cite: 10].
* **Capa Oculta:** $\lceil \beta \cdot k \rceil$ neuronas ($\beta = 0.75$)[cite: 9, 10].
* **Entrada Procesada:** $\vec{z}_{\text{norm}} \in [0, 1]^k$[cite: 10].

El error emitido por $\theta_0$ constituye el **score de anomalía global instantáneo ($s$)** del paquete[cite: 3, 10]:

$$s = RMSE\left(\vec{z}_{\text{norm}}, \, \hat{\vec{z}}\right) = \sqrt{\frac{1}{k} \sum_{i=1}^k \left(z_{\text{norm}}^{(i)} - \hat{z}^{(i)}\right)^2}$$
[cite: 5, 10]

### 2.4 Demostración Formal de Reducción Asintótica de Complejidad
Para un espacio de entrada con $n = 115$ características y ratio $\beta = 0.75$:

#### Autoencoder Monolítico Tradicional
$$\mathcal{C}_{\text{mono}} = \mathcal{O}(n \cdot \beta n + \beta n \cdot n) = \mathcal{O}\left(2\beta n^2\right) \approx \mathcal{O}(n^2)$$
[cite: 11]

Para $n = 115$, el número de operaciones de multiplicación y acumulación (MAC) por pasada excede las **19.800 operaciones**[cite: 11].

#### Ensamble KitNET
* Coste de la Capa de Ensamble $L^{(1)}$: $\sum_{i=1}^k \mathcal{O}\left(2\beta \cdot dim(\vec{v}_i)^2\right) \le k \cdot \mathcal{O}\left(2\beta m^2\right)$[cite: 11].
* Dado que $m \le 10$ es una constante rígida, $k \cdot m^2 = \mathcal{O}(k)$ (lineal respecto al número de subespacios)[cite: 11].
* Coste de la Capa de Salida $L^{(2)}$: $\mathcal{O}\left(2\beta k^2\right) = \mathcal{O}(k^2)$[cite: 11].

$$\mathcal{C}_{\text{KitNET}} = \mathcal{O}\left(k \cdot m^2 + k^2\right) = \mathcal{O}(k^2)$$
[cite: 11]

Con $k \approx 35$ clústeres típicos, las operaciones totales caen a aproximadamente **3.500 MACs**, reduciendo la carga de CPU por un factor superior a 5x y limitando la latencia en procesadores ARM a menos de $185\ \mu\text{s}$ por trama[cite: 11, 13, 15].

---

## 3. Motor Analítico de Umbral y Decisión

Kitsune rechaza el uso de máximos empíricos absolutos ($\max(s)$) debido a su susceptibilidad a picos espurios de convergencia durante el Descenso de Gradiente Estocástico (SGD)[cite: 5, 10]. En su lugar, parametriza analíticamente la distribución de los residuos benignos[cite: 10].

```
                DISTRIBUCIÓN DEL RESIDUO BENIGNO Y ZONA DE DISPARO
                
 f(s) ▲
      │      Moda Benigna (μ_log)
      │          ┌───────┐
      │         ┌┘       └┐
      │        ┌┘         └┐
      │       ┌┘           └┐
      │      ┌┘             └┐
      │    ┌─┘               └───┐               Zona de Intrusión (Alerta)
      │  ┌─┘                     └──────┐               │
      └──┴──────────────────────────────┴───────────────┼──────────►
      0                                                 τ           Score RMSE (s)
                                                  (FPR ≤ 0.001)
```

### 3.1 Modelado Paramétrico Log-Normal de Residuos Benignos
Dado que el score de reconstrucción es no negativo ($s \in [0, \infty)$) y exhibe asimetría positiva con cola extendida, se asume que la variable aleatoria $S$ bajo condiciones estacionarias sigue una distribución log-normal[cite: 10]:

$$S \sim \operatorname{Lognormal}\left(\mu_{\log}, \, \sigma_{\log}^2\right) \iff Y = \ln(S) \sim \mathcal{N}\left(\mu_{\log}, \, \sigma_{\log}^2\right)$$
[cite: 10]

### 3.2 Estimación de Máxima Verosimilitud (MLE) en Streaming
Durante la ventana estacionaria de tráfico benigno (`AD_grace_period`), una vez superadas las oscilaciones iniciales del SGD, se calculan los estimadores de máxima verosimilitud sobre las puntuaciones $s_1, \dots, s_N$[cite: 5, 10]:

$$\hat{\mu}_{\log} = \frac{1}{N} \sum_{i=1}^N \ln(s_i)$$

$$\hat{\sigma}_{\log}^2 = \frac{1}{N - 1} \sum_{i=1}^N \left(\ln(s_i) - \hat{\mu}_{\log}\right)^2, \quad \hat{\sigma}_{\log} = \sqrt{\hat{\sigma}_{\log}^2}$$

### 3.3 Formulación Analítica del Umbral $\tau$ y Vinculación con el Riesgo ($FPR \le 0.001$)
El umbral de corte se proyecta mediante la transformación exponencial inversa[cite: 10]:

$$\tau = \exp\left(\hat{\mu}_{\log} + k \cdot \hat{\sigma}_{\log}\right)$$
[cite: 10]

La tasa formal de falsas alarmas (*False Positive Rate*) se formula mediante la función de distribución acumulada de la normal estándar ($\Phi$)[cite: 10, 13]:

$$FPR = P(S > \tau) = P\left(\frac{\ln(S) - \hat{\mu}_{\log}}{\hat{\sigma}_{\log}} > k\right) = 1 - \Phi(k)$$
[cite: 10, 13]

Para cumplir con la cota de diseño de NDSS 2018 ($FPR \le 0.001 \implies 0.1\%$ de falsas alarmas toleradas en el cable)[cite: 13]:

$$\Phi(k) = 1 - 0.001 = 0.999 \implies k = \Phi^{-1}(0.999) \approx \mathbf{3.0902}$$
[cite: 13]

#### Regla de Decisión en Ejecución (`exec-mode`)
Para cada paquete entrante con residuo global $s$:

$$\operatorname{Veredicto}(s) = \begin{cases} \text{Benigno (Tráfico Ordinario)}, & \text{si } s \le \tau \\ \text{Anomalía (Alerta Perimetral)}, & \text{si } s > \tau \end{cases}$$
[cite: 6, 10]

---

## 4. Arquitectura de Software e Interfaces (Python 3.11)

El paquete está estructurado modularmente bajo `src/kitsune` cumpliendo con los lineamientos de tipado estricto y desacople funcional[cite: 1].

```
src/kitsune/
├── __init__.py
├── after_image.py     # Motor O(1) con tablas hash y decaimiento continuo
├── cor_clust.py       # Clustering jerárquico incremental y partición de grafo
├── autoencoder.py     # Micro-redes feed-forward (3 capas, sigmoid, backprop)
├── kitnet.py          # Orquestador del ensamble L(1) + L(2)
├── metrics.py         # Auditoría forense NDSS 2018 (ROC AUC, EER, TPR@FPR)
└── cli.py             # Entrypoint unificado ('kitsune demo', 'kitsune run')
```
*[cite: 1, 3, 10, 13]*

### 4.1 Contratos de Tipado e Interfaces de Módulos

```python
from dataclasses import dataclass
from typing import List, Tuple, Dict, Optional
import numpy as np
import numpy.typing as npt

@dataclass(slots=True)
class PacketMetadata:
    timestamp: float
    size: int
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str

class AfterImageInterface:
    def update_and_extract(self, meta: PacketMetadata) -> npt.NDArray[np.float64]:
        """Actualiza tuplas IS en O(1) y devuelve un vector de dimensión 115."""
        ...

class FeatureMapperInterface:
    def update(self, x: npt.NDArray[np.float64]) -> None:
        """Actualiza la matriz de correlación incremental C."""
        ...
        
    def cluster(self, max_size: int = 10) -> List[List[int]]:
        """Aplica clustering jerárquico y devuelve los subespacios v_1, ..., v_k."""
        ...

class KitNETInterface:
    def train(self, v: List[npt.NDArray[np.float64]]) -> float:
        """Pasa una instancia por L(1) y L(2) con SGD (max_iter = 1)."""
        ...
        
    def execute(self, v: List[npt.NDArray[np.float64]]) -> float:
        """Calcula el RMSE de L(2) sin actualizar pesos."""
        ...
```

### 4.2 Máquina de Estados del Ciclo de Vida

```
                      INICIALIZACIÓN DEL SISTEMA
                                  │
                                  ▼
           ┌──────────────────────────────────────────────┐
           │           FASE 1: FEATURE MAPPING            │
           │           (Paquetes: 0 → FM_grace)           │
           │  - AfterImage: Extracción activa             │
           │  - corClust: Actualización matriz D          │
           │  - KitNET: Inactivo (RMSE = 0.0)             │
           └──────────────────────┬───────────────────────┘
                                  │ Al alcanzar FM_grace:
                                  │ Se genera el dendrograma,
                                  │ se crean k micro-autoencoders
                                  ▼
           ┌──────────────────────────────────────────────┐
           │      FASE 2: ENTRENAMIENTO DE ANOMALÍAS      │
           │    (Paquetes: FM_grace → FM_grace + AD_grace)│
           │  - SGD activo en L(1) y L(2) (max_iter = 1)  │
           │  - Normalización local [0, 1]                │
           │  - Calibración MLE de μ_log y σ_log          │
           └──────────────────────┬───────────────────────┘
                                  │ Al alcanzar AD_grace:
                                  │ Se congelan los pesos neuronales,
                                  │ se fija el umbral analítico τ
                                  ▼
           ┌──────────────────────────────────────────────┐
           │        FASE 3: EJECUCIÓN PURA (EXEC-MODE)    │
           │        (Paquetes restantes en producción)    │
           │  - Inferencia estricta (Forward pass)        │
           │  - Comparación en tiempo real: ¿s > τ?       │
           │  - Emisión de alerta perimetral si excede    │
           └──────────────────────────────────────────────┘
```
*[cite: 6, 7, 8, 9, 10]*

---

## 5. Matriz de Parámetros de Diseño y Configuración

| Parámetro | Valor Estándar | Módulo | Justificación Operativa / Criterio de Selección |
| :--- | :--- | :--- | :--- |
| $\Lambda$ | $\{5, 3, 1, 0.1, 0.01\}$[cite: 8] | `AfterImage` | Captura espectro desde 100 ms (micro-bursts) hasta 1 min (flujos lentos)[cite: 8]. |
| $\epsilon$ | $10^{-5}$[cite: 15] | `AfterImage` | Umbral de desalojo para canales inactivos (mitigación State-Exhaustion)[cite: 15]. |
| $m$ | $10$[cite: 9, 11] | `corClust` | Cota máxima de variables por micro-autoencoder; balancea velocidad y correlación[cite: 9, 11]. |
| $\beta$ | $0.75$ ($3/4$)[cite: 9, 10] | `KitNET` | Factor de cuello de botella: fuerza compresión sin pérdida crítica de fidelidad[cite: 9, 10]. |
| `learning_rate` ($\eta$) | $0.1$ | `KitNET` | Tasa de paso en Descenso de Gradiente Estocástico (SGD) en streaming[cite: 4, 10]. |
| `max_iter` | $1$[cite: 5] | `KitNET` | Una única actualización por muestra entrante; garantiza operación online estricta[cite: 5]. |
| $k$ (umbral) | $3.0902$[cite: 13] | `Threshold` | Fijación matemática de la cota superior de falsos positivos: $FPR \le 0.001$[cite: 13]. |
| `FM_grace` | $2.000 - 5.000$[cite: 8, 12] | `Pipeline` | Paquetes benignos requeridos para estabilizar correlaciones multivariadas[cite: 8, 12]. |
| `AD_grace` | $10.000 - 50.000$[cite: 12] | `Pipeline` | Muestras benignas para convergencia estocástica de pesos en $L^{(1)}$ y $L^{(2)}$[cite: 5, 10, 12]. |

---

*Fin del documento técnico `DOC-GRD-KITSUNE-ARCH-02`. Especificación formal lista para integración en el repositorio central de documentación de arquitectura.*[cite: 1]