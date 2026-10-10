# Kitsune NIDS: Fundamentos Matemáticos y Arquitectura de Ejecución

Este documento formaliza la arquitectura del sistema de detección de intrusiones en red (NIDS) Kitsune, detallando la extracción de características en tiempo real con **AfterImage**, la descomposición de dimensionalidad con **KitNET** y las cotas de complejidad computacional y contención de memoria en hardware perimetral.

---

## 1. Complejidad Asintótica: Descomposición en Ensamble KitNET

La detección de anomalías tradicional basada en redes neuronales suele desplegar un autoencoder de tres capas sobre un vector de características $\vec{x} \in \mathbb{R}^n$ con ratio de compresión $\beta \in (0, 1]$ en la capa oculta.

### 1.1. Autoencoder Monolítico: Complejidad Cuadrática
En una arquitectura densa con capas $l^{(1)}, l^{(2)}, l^{(3)}$ donde $\vert{}l^{(1)}\vert{} = n$, $\vert{}l^{(2)}\vert{} = \lceil \beta n \rceil$ y $\vert{}l^{(3)}\vert{} = n$, la activación de una capa requiere la multiplicación de la matriz de pesos sinápticos por el vector de entrada:

$$\mathcal{O}(\vert{}l^{(1)}\vert{} \cdot \vert{}l^{(2)}\vert{} + \vert{}l^{(2)}\vert{} \cdot \vert{}l^{(3)}\vert{}) = \mathcal{O}(n \cdot \beta n + \beta n \cdot n) = \mathcal{O}(n^2) \quad \text{(Ecuación 12)}$$

Para el espacio canónico de Kitsune ($n = 115$ características continuas y $\beta = 0.75$), un modelo monolítico demanda aproximadamente $2 \cdot 115 \cdot 87 = 20.010$ operaciones de punto flotante por paquete. En enlaces de alta velocidad con decenas de miles de paquetes por segundo, este coste genera saturación de colas en CPUs embebidas.

### 1.2. Partición Jerárquica KitNET: Complejidad $\mathcal{O}(k^2)$
KitNET desacopla el espacio de características proyectando $\vec{x} \in \mathbb{R}^n$ en un conjunto ordenado de $k$ subinstancias disjuntas:

$$v = \{\vec{v}_1, \vec{v}_2, \dots, \vec{v}_k\}, \quad \sum_{i=1}^k \dim(\vec{v}_i) = n, \quad \dim(\vec{v}_i) \le m$$

donde $m$ es el hiperparámetro de cota superior ($m \le 10$).

La arquitectura se divide en dos niveles:
1. **Capa de Ensamble ($L^{(1)}$):** Compuesta por $k$ autoencoders independientes $\{\theta_1, \dots, \theta_k\}$, donde cada autoencoder $\theta_i$ reconstruye su subespacio $\vec{v}_i$. La complejidad de evaluar toda la capa es:
   $$\mathcal{O}\left(\sum_{i=1}^k \dim(\vec{v}_i)^2\right) \le \mathcal{O}(k \cdot m^2)$$
2. **Capa de Salida ($L^{(2)}$):** Un único autoencoder $\theta_0$ que toma como entrada el vector de errores RMSE de la capa anterior $\vec{z} \in [0, 1]^k$. Su complejidad de ejecución es $\mathcal{O}(k \cdot \lceil \beta k \rceil) = \mathcal{O}(k^2)$.

La complejidad agregada de inferencia y entrenamiento estocástico (SGD con paso unitario) es:

$$\mathcal{O}(k \cdot m^2 + k^2) = \mathcal{O}(k^2) \quad \text{(Ecuación 13)}$$

Dado que $m \le 10$ actúa como una constante fija del sistema, la complejidad depende exclusivamente del número de autoencoders $k$:
* **Caso óptimo ($k = \lceil n/m \rceil$):** Con $n = 115$ y $m = 10$, se generan $k \approx 12$ autoencoders. El número de multiplicaciones se reduce a $\approx 1.920$ en $L^{(1)}$ y $\approx 216$ en $L^{(2)}$, acelerando el procesamiento en casi un orden de magnitud frente al modelo monolítico.
* **Escalabilidad empírica:** En un único núcleo ARM Cortex-A53 (Raspberry Pi 3B a 1.2 GHz), KitNET incrementa la tasa de procesamiento de $\approx 1.000$ paquetes/s ($k=1$) a $\approx 5.400$ paquetes/s ($k=35$), y alcanza más de $37.000$ paquetes/s en procesadores x86-64.

---

## 2. Extracción de Características en Streaming $\mathcal{O}(1)$: AfterImage

AfterImage mantiene métricas estadísticas del tráfico de red sobre cinco ventanas de decaimiento temporal amortiguadas:

$$\lambda \in \{5, 3, 1, 0.1, 0.01\}$$

equivalentes a horizontes aproximados de 100 ms, 500 ms, 1.5 s, 10 s y 60 s.

### 2.1. Decaimiento Exponencial Continuo
Para evitar el almacenamiento de historiales de paquetes ($\mathcal{O}(N)$ en memoria), el peso de las observaciones decae continuamente en función del tiempo transcurrido desde el último evento registrado en el canal:

$$d_\lambda(t) = 2^{-\lambda t}, \quad t = t_{\text{cur}} - T_{\text{last}} \quad \text{(Ecuación 6)}$$

### 2.2. Actualización Incremental de Tuplas
Cada flujo se registra mediante la tupla incremental:

$$IS_{i,\lambda} := \left(w, LS, SS, SR_{ij}, T_{\text{last}}\right)$$

Donde $w$ es el peso amortiguado, $LS$ es la suma lineal, $SS$ la suma cuadrática y $SR_{ij}$ la suma de productos residuales cruzados para flujos bivariados. Al recibir una observación $x_{\text{cur}}$ en el tiempo $t_{\text{cur}}$:

1. Se computa el factor de amortiguación: $\gamma = 2^{-\lambda (t_{\text{cur}} - T_{\text{last}})}$.
2. Se actualiza la tupla en tiempo y espacio constante $\mathcal{O}(1)$:
   $$w \leftarrow \gamma w + 1$$
   $$LS \leftarrow \gamma LS + x_{\text{cur}}$$
   $$SS \leftarrow \gamma SS + x_{\text{cur}}^2$$
   $$SR_{ij} \leftarrow \gamma SR_{ij} + (x_{\text{cur}}^{(i)} - \mu_i)(x_{\text{cur}}^{(j)} - \mu_j)$$
   $$T_{\text{last}} \leftarrow t_{\text{cur}}$$

A partir de esta tupla, las estadísticas univariadas y bivariadas se obtienen directamente:

$$\mu = \frac{LS}{w}, \quad \sigma = \sqrt{\max\left(0, \frac{SS}{w} - \mu^2\right)}, \quad \text{Cov}_{i,j} = \frac{SR_{ij}}{w_i + w_j}, \quad P_{i,j} = \frac{\text{Cov}_{i,j}}{\sigma_i \sigma_j}$$

---

## 3. Matriz Correlacional Incremental y Mapeo de Subespacios

Durante el período `FM_grace_period`, AfterImage acumula estadísticas entre las características de entrada para construir la matriz de distancia de correlación $D \in \mathbb{R}^{n \times n}$:

$$D_{i,j} = 1 - \frac{C_{i,j}}{\sqrt{c_{rs}^{(i)}} \sqrt{c_{rs}^{(j)}}} \quad \text{(Ecuación 10)}$$

donde $C_{i,j}$ es la covarianza cruzada incremental de residuos y $c_{rs}^{(i)}$ es la suma cuadrática de residuos para la característica $i$.

Al expirar el período de gracia, se ejecuta un agrupamiento jerárquico aglomerativo sobre $D$. Las ramas del dendrograma cuya cardinalidad supera $m$ se dividen de forma recursiva hasta garantizar que ningún subconjunto contenga más de $m$ dimensiones. Este agrupamiento asigna características altamente correlacionadas al mismo autoencoder, permitiendo a cada red en $L^{(1)}$ modelar dependencias no lineales específicas del protocolo.

---

## 4. Resiliencia contra Vectores DoS de Agotamiento de Estado (State-Exhaustion)

Un vector de ataque crítico en entornos de borde es el **State-Exhaustion DoS** (NDSS 2018, Sección VI): un atacante inyecta flujos masivos de paquetes con direcciones IP y puertos aleatorios para forzar la instanciación infinita de tablas hash en el extractor de características.

### 4.1. Huella de Memoria Base
En la implementación de AfterImage, una conexión de red bidireccional monitorizada a través de las cinco ventanas temporales consume aproximadamente 1 KB de RAM. Un límite estricto de 1 MB de RAM es suficiente para mantener activas 1.000 conversaciones de red simultáneas.

### 4.2. Poda Amortizada en $\mathcal{O}(1)$
Dado que las escalas temporales más rápidas ($\lambda = 5, 3$) decaen a cero en cuestión de milisegundos tras cesar la actividad, AfterImage incorpora un mecanismo pasivo de recolección de memoria:

$$\text{Si } w_i < \epsilon \quad (\epsilon \approx 10^{-5}), \quad \text{se elimina la entrada } IS_{i,\lambda} \text{ de la tabla hash.}$$

Dado que los paquetes de escaneo aleatorio generan entradas transitorias que no reciben tráfico posterior, sus pesos amortiguados colapsan de inmediato, impidiendo el desbordamiento de memoria sin degradar el throughput de captura.

---

## 5. Umbral Estadístico Log-Normal de Decisión

Para operar sin supervisión y garantizar una tasa de falsas alarmas acotada ($FPR \le 0.001$), los residuos RMSE generados por la capa de salida $L^{(2)}$ durante el tráfico benigno (`AD_grace_period`) se ajustan a una distribución log-normal:

$$\ln(s) \sim \mathcal{N}(\mu_{\log}, \sigma_{\log}^2)$$

Los estimadores de máxima verosimilitud sobre $N$ muestras de calibración son:

$$\hat{\mu}_{\log} = \frac{1}{N} \sum_{i=1}^N \ln(s_i), \quad \hat{\sigma}_{\log} = \sqrt{\frac{1}{N} \sum_{i=1}^N \left(\ln(s_i) - \hat{\mu}_{\log}\right)^2}$$

El umbral analítico de corte $\tau$ para el percentil $99.9\%$ ($Z_{0.999} \approx 3.0902$) se calcula como:

$$\tau = \exp\left(\hat{\mu}_{\log} + 3.0902 \cdot \hat{\sigma}_{\log}\right)$$

Durante la fase de ejecución, cualquier paquete que verifique $RMSE(x) > \tau$ dispara una alerta inmediata de intrusión sin requerir intervención humana ni reentrenamiento supervisado.