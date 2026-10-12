# Doc 1: Manual Pedagógico Interno y Guía de Taller
### *Kitsune NIDS: Deconstrucción Arquitectónica, Extracción en Streaming y Detección No Supervisada en el Perímetro (Nivel Máster GRD / EQF 7)*

---

## Ficha del Documento Técnico y Guía del Facilitador

* **Código de referencia:** `DOC-GRD-KITSUNE-PED-01`.
* **Nivel académico / profesional:** Nivel MECES 3 / European Qualifications Framework Level 7 (Máster en Gestión del Riesgo y Ciberseguridad / Inteligencia Artificial Aplicada).
* **Repositorios de referencia:** `kitsune-research/Kitsune-py` (upstream institucional) y `paradiselord-dev/Kitsune-py` (fork de portafolio)[cite: 1].
* **Base metodológica y empírica:** Y. Mirsky et al., *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*, Proceedings of the Network and Distributed Systems Security Symposium (NDSS 2018)[cite: 1, 2].
* **Duración modular estimada:** 2 a 4 horas lectivas (distribuidas en 6 bloques temáticos).
* **Perfil de la audiencia:** Ingenieros de sistemas, arquitectos de software, analistas de SOC (Blue Team), administradores de redes y responsables de gobierno del riesgo (GRC) sin formación avanzada en cálculo multivariable ni estadística formal[cite: 1].
* **Directiva pedagógica rectora:** Prohibido el uso de abstracciones opacas. Cada concepto matemático debe traducirse a una analogía física verificable, una estructura de datos concreta y un modelo de colas e instrucciones de CPU[cite: 1, 2].

---

## Bloque 1: El Campo de Batalla y la Ruptura de Paradigma (35 min)

### 1.1 El Cuello de Botella Físico en el Edge
La inspección de tráfico en puntos perimetrales —como pasarelas de enlace en plantas industriales, delegaciones remotas o concentradores de vídeo sobre IP— opera bajo restricciones físicas severas[cite: 2]. En un enlace convencional que transporte entre 100 Mbps y 1 Gbps con predominio de paquetes pequeños (tramas TCP ACK, ráfagas DNS, telemetría SCADA), la tarjeta de red (NIC) debe procesar entre 50.000 y 150.000 paquetes por segundo[cite: 2].

El hardware disponible en estos nodos suele reducirse a microprocesadores embebidos o placas mononúcleo (como SoCs ARM Cortex-A53 a 1.2 GHz) equipados con 1 a 4 GB de memoria RAM compartida y sin acceso a procesadores gráficos (GPU)[cite: 2].

```
Flujo Masivo en el Cable (100 Mb/s - 1 Gb/s)
                   │
                   ▼
  ┌─────────────────────────────────┐
  │  NIC RX Ring Buffer (Hardware)  │
  └────────────────┬────────────────┘
                   │ Interrupciones / Polling NAPI
                   ▼
  ┌─────────────────────────────────┐
  │      Kernel Socket Buffer       │  ◄── Si la inspección excede ~10 µs:
  └────────────────┬────────────────┘      ¡Desbordamiento de colas (Packet Drops)!
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
Enfoques Clásicos      Kitsune NIDS
(Firmas / Deep Learning) (Streaming No Supervisado)
  - Firmas: Ciego a 0-days   - Ingesta en tiempo constante O(1)
  - Cloud: Latencia y coste  - Autoencoders ligeros O(k²)
  - DL: O(n²) colapsa CPU    - Inspección directa en el nodo
```

Frente a esta restricción, las estrategias clásicas colapsan[cite: 2]:

* **El desvío masivo a la nube / SIEM centralizado:** Exportar flujos brutos o trazas PCAP completas agota el ancho de banda del canal de retorno (*uplink*), genera costes de ingestión por gigabyte inasumibles y añade latencias de minutos que anulan cualquier contención automatizada de incidentes[cite: 2].
* **La trampa del espacio de usuario:** Si el análisis de cada trama toma más de 10 a 20 microsegundos en la CPU, los búferes del kernel (`AF_PACKET` / `NFQueue`) se saturan, forzando la pérdida de paquetes (*packet drops*) y dejando al sensor perimetral completamente ciego[cite: 2].

### 1.2 Límites Estructurales de los Enfoques Clásicos

#### A. Sistemas basados en firmas (Snort, Suricata)
Operan evaluando expresiones regulares o cadenas binarias sobre la carga útil (*payload*)[cite: 2].
1. **Opacidad por cifrado:** Con la adopción universal de TLS 1.3 y protocolos como QUIC, más del 90% del tráfico corporativo viaja cifrado punto a punto, impidiendo la inspección profunda de paquetes (*DPI*) en conmutadores intermedios sin romper la sesión criptográfica[cite: 2].
2. **Conformidad formal con el estándar RFC:** Ataques como el escaneo de huella de sistema operativo de Nmap (*OS Fingerprinting*) utilizan secuencias de banderas legales (SYN, FIN, PSH, URG o paquetes TCP a puertos cerrados)[cite: 2]. Ningún paquete individual contiene código malicioso ni firmas catalogadas; la intrusión reside en la secuencia, no en el byte[cite: 2].
3. **Ceguera comportamental:** Una interceptación en el cable (*active wiretap*) o la inyección de vídeo en un circuito cerrado transmite paquetes de vídeo legítimos H.264/RTP[cite: 2]. Las firmas son incapaces de notar que la alteración se encuentra en la dispersión temporal (*jitter*) y en las relaciones bidireccionales del canal[cite: 2].

#### B. Deep Learning Supervisado Convencional
Entrenar clasificadores neuronales tradicionales (redes densas multicapa, SVMs o árboles de decisión supervisados) exige disponer previamente de datos etiquetados exhaustivamente con clases binarias (`0: normal`, `1: ataque`)[cite: 2].
1. **Falacia de la etiqueta en producción:** Es inviable etiquetar manualmente millones de tramas en redes de producción vivas cuyo comportamiento cambia diariamente[cite: 2].
2. **Supuesto de "Mundo Cerrado":** Un clasificador supervisado solo reconoce aquello con lo que fue entrenado en laboratorio; cualquier técnica novedosa (*Zero-Day*) o mutación de malware será forzada en las categorías existentes, provocando fallos silenciosos[cite: 2].
3. **Pared computacional cuadrática ($\mathcal{O}(n^2)$):** Una red neuronal densa convencional alimentada con $n$ variables de red conecta todas sus entradas contra todas las neuronas de la capa intermedia[cite: 2]. Para un vector de más de 100 características, esto exige decenas de miles de multiplicaciones y sumas en coma flotante por paquete, provocando latencias superiores a 1.000 microsegundos por trama en procesadores embebidos[cite: 2].

### 1.3 El Paradigma Kitsune: Streaming No Supervisado en el Cable
Kitsune reformula el problema de raíz[cite: 2]:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   LOS TRES PRINCIPIOS DE KITSUNE                       │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Aprendizaje No Supervisado: No consume etiquetas ni conocimiento    │
│    previo. Aprende la variedad (manifold) de la normalidad observando  │
│    el tráfico legítimo del propio enlace.                              │
│                                                                        │
│ 2. Procesamiento Online en Streaming: Cada paquete se procesa en O(1)  │
│    en un solo paso de cómputo y se descarta de memoria de inmediato.   │
│                                                                        │
│ 3. Ensamble Desacoplado O(k²): Sustituye el modelo denso por un        │
│    escuadrón de micro-autoencoders independientes de tamaño acotado    │
│    (m ≤ 10), reduciendo la latencia y multiplicando por 5 la velocidad│
│    de procesamiento.                                                   │
└────────────────────────────────────────────────────────────────────────┘
```

#### Analogía Mecánica: El Perito Aduanero Forense
Para transmitir esta idea a un equipo sin base matemática:
* **El método de firmas:** Un guardia aduanero abre contenedores buscando las caras de una lista de delincuentes buscados[cite: 2]. Si el contenedor viene blindado con cerradura inviolable (cifrado) o la cara no está en la base de datos, el camión pasa libremente[cite: 2].
* **El método Kitsune:** El perito no abre los contenedores ni intenta romper candados[cite: 2]. En su lugar, mide variables externas: el peso bruto del camión, la cadencia de llegada a la báscula, la relación entre camiones que entran vacíos y salen llenos, y el retardo entre cada vehículo[cite: 2].
* Durante las primeras horas de tráfico normal, el perito memoriza la rutina ordinaria del puerto[cite: 2]. Si de pronto entran 500 furgonetas ligeras en tres segundos (un escaneo o un ataque de botnet), el perito detecta de inmediato que la cinemática del puerto se ha quebrado, haciendo sonar la alarma sin necesidad de examinar la mercancía transportada[cite: 2].

---

## Bloque 2: La Memoria sin Historial — AfterImage y el Decaimiento Continuo (45 min)

### 2.1 El Colapso de las Ventanas Deslizantes Tradicionales
El componente de extracción de características en Kitsune recibe el nombre de **AfterImage**[cite: 1, 2]. Su propósito es calcular estadísticas temporales (medias, varianzas, retardos entre llegadas) sobre múltiples canales de red[cite: 2].

La aproximación tradicional en desarrollo de software para calcular estadísticas en una ventana móvil de 60 segundos es el uso de un búfer circular (FIFO):
1. Llega un paquete: se añade un objeto con su estampa de tiempo y tamaño a una lista en memoria[cite: 2].
2. Se recorre la lista sumando sus elementos para calcular la media aritmética[cite: 2].
3. Se eliminan los elementos cuya antigüedad supere los 60 segundos[cite: 2].

En una red de producción, este esquema es inviable[cite: 2]:
* **Consumo de memoria desbordado ($\mathcal{O}(N)$):** Un enlace a 1 Gbps con 20.000 paquetes por segundo acumula 1.200.000 paquetes por minuto[cite: 2]. Multiplicado por cientos de conversaciones activas, la memoria RAM requerida alcanza varios gigabytes en pocos segundos[cite: 2].
* **Ausencia de escala temporal física:** Una cola estática de "los últimos 100 paquetes" trata de forma idéntica a una ráfaga de denegación de servicio que tardó 2 milisegundos en llegar y a una baliza de telemetría IoT que tardó 4 horas en emitir 100 tramas, destruyendo la noción física de velocidad o frecuencia[cite: 2].

### 2.2 El Reloj de Arena Amortiguado y la Función de Decaimiento Continuo
AfterImage sustituye el almacenamiento de paquetes por el principio de **decaimiento exponencial continuo**[cite: 2].

#### Analogía Física: La Brasa Incandescente
Imaginemos una brasa en un horno:
* Al llegar un paquete, se arroja un trozo de carbón: el calor del canal aumenta[cite: 2].
* Conforme pasa el tiempo sin tráfico, la brasa no se apaga repentinamente en un segundo fijo; se enfría de forma suave y continua a cada milisegundo transcurrido[cite: 2].
* Cuando llega un paquete nuevo, no hace falta recordar cuántos carbones se tiraron antes; basta con mirar el reloj, calcular cuánto se enfrió la brasa desde la última visita y sumar el calor de la nueva trama[cite: 2].

Matemáticamente, el enfriamiento continuo entre el paquete actual recibido en $t_{\text{cur}}$ y el paquete previo registrado en $T_{\text{last}}$ se calcula mediante la función de decaimiento[cite: 2]:

$$d_\lambda(\Delta t) = 2^{-\lambda \Delta t} \quad \text{donde } \Delta t = t_{\text{cur}} - T_{\text{last}}$$
[cite: 2]

El parámetro $\lambda > 0$ es el factor de amortiguamiento que define la velocidad a la que se desvanece la memoria del canal[cite: 2]. La base 2 se selecciona deliberadamente frente a la base $e$ por motivos de arquitectura de computadores: optimiza operaciones de registros y cálculo de punto flotante en procesadores de bajo coste[cite: 2].

```
                 DECAIMIENTO CONTINUO DEL PESO AMORTIGUADO (w)

Peso (w) ▲
         │     ▲ Paquete 1 llega (w += 1)
     1.0 │    ┌┴┐
         │    │  └─── Enfriamiento continuo: 2^(-λ · Δt)
     0.5 │    │       └───►             ▲ Paquete 2 llega (w_prev enfriado + 1)
         │    │                         ┌┴┐
     0.0 └───┴─────────────────────────┴─┴────────────────────────► Tiempo (t)
             t=0                       t=Δt
```

### 2.3 Estructura de la Tupla $IS_{i,\lambda}$ y Operaciones en $\mathcal{O}(1)$
En lugar de listas de paquetes, AfterImage mantiene en memoria una única estructura compacta de números flotantes de 64 bits para cada flujo[cite: 2]:

$$IS_{i,\lambda} := (w, LS, SS, SR_{ij}, T_{\text{last}})$$
[cite: 2]

* $w$ (**Peso amortiguado**): Conteo continuo de eventos ponderados por antigüedad[cite: 2].
* $LS$ (**Suma lineal amortiguada**): Suma ponderada de los valores observados (p. ej., tamaño en bytes)[cite: 2].
* $SS$ (**Suma cuadrática amortiguada**): Suma ponderada del cuadrado de las observaciones ($x^2$), requerida para calcular varianza[cite: 2].
* $SR_{ij}$ (**Suma de residuos cruzados**): Registro de interacción cruzada entre el canal de transmisión y recepción para métricas bidireccionales (2D)[cite: 2].
* $T_{\text{last}}$ (**Marca temporal**): Estampa en segundos del último paquete visto en este flujo[cite: 2].

#### El Algoritmo 3 de NDSS 2018 (Actualización en Tiempo Constante)
La inserción de una muestra $x_{\text{cur}}$ en el instante $t_{\text{cur}}$ requiere exactamente tres pasos elementales[cite: 2]:

```
┌────────────────────────────────────────────────────────────────────────┐
│             ALGORITMO 3: ACTUALIZACIÓN DE TUPLA AMORTIGUADA            │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Calcular decaimiento continuo:                                      │
│    γ = 2^(-λ · (t_cur - T_last))                                       │
│                                                                        │
│ 2. Aplicar decaimiento a la memoria acumulada:                         │
│    w  = γ · w                                                          │
│    LS = γ · LS                                                         │
│    SS = γ · SS                                                         │
│    SR = γ · SR                                                         │
│                                                                        │
│ 3. Sumar el evento actual y sellar estampa de tiempo:                  │
│    w      = w + 1                                                      │
│    LS     = LS + x_cur                                                 │
│    SS     = SS + (x_cur)²                                              │
│    T_last = t_cur                                                      │
└────────────────────────────────────────────────────────────────────────┘
```
[cite: 2]

A partir de estas variables fijas, las propiedades estadísticas del canal se calculan inmediatamente sin iteraciones[cite: 2]:

$$\mu = \frac{LS}{w}, \quad \sigma^2 = \left\vert{} \frac{SS}{w} - \left(\frac{LS}{w}\right)^2 \right\vert{}, \quad \sigma = \sqrt{\sigma^2}$$
[cite: 2]

Completada la operación, **la trama de red se descarta inmediatamente de la memoria RAM**[cite: 2].

### 2.4 Generación del Vector Numérico de 115 Características
Para que el detector capture tanto ataques instantáneos como maniobras lentas, AfterImage mantiene estas tuplas sobre **cinco ventanas temporales simultáneas**[cite: 1, 2]:

| Ventana Equivalente | Factor $\lambda$ | Alcance Operativo en Ciberseguridad |
| :--- | :--- | :--- |
| **100 ms** | $\lambda = 5$ | Ráfagas extremas, micro-escaneos SYN, ataques de inundación local[cite: 2]. |
| **500 ms** | $\lambda = 3$ | Anomalías en tráfico de voz/vídeo y variaciones repentinas de jitter[cite: 2]. |
| **1.5 s** | $\lambda = 1$ | Comportamiento en sesiones de aplicación (handshakes TCP, consultas DNS)[cite: 2]. |
| **10 s** | $\lambda = 0.1$ | Evolución de transferencias de archivos y persistencia de conexiones[cite: 2]. |
| **60 s** | $\lambda = 0.01$ | Tendencia de fondo de la conversación y balizas periódicas lentas[cite: 2]. |

En cada una de las 5 ventanas temporales se extraen estadísticas agrupadas en **cuatro entidades de comunicación**[cite: 2]:
1. **SrcMAC-IP (8 características):** Tráfico procedente de la dirección MAC e IP emisora (detecta suplantación ARP y cambios de host físico)[cite: 2].
2. **SrcIP (4 características):** Tráfico originado por la dirección IP de origen en general[cite: 2].
3. **Channel (8 características):** Conversación bidireccional entre la IP de origen y la de destino, correlacionando anchos de banda de subida y bajada[cite: 2].
4. **Socket (3 características):** Flujo específico a nivel de capa de transporte (IP y puerto origen contra IP y puerto destino)[cite: 2].

$$23 \text{ métricas por ventana} \times 5 \text{ ventanas de decaimiento} = \mathbf{115 \text{ características estadísticas}}$$
[cite: 2]

Cada paquete genera así un vector continuo $\vec{x} \in \mathbb{R}^{115}$ que resume la cinemática de la red en tiempo real[cite: 2].

### 2.5 Resiliencia contra Saturación de Tabla (*State-Exhaustion DoS*)
Un vector común contra los cortafuegos con estado consiste en inundar el enlace con millones de paquetes con IPs de origen falsificadas (*IP spoofing*) para saturar la memoria RAM asignada a las tablas de conexión (`conntrack`)[cite: 2].

AfterImage es inmune a esta técnica por diseño matemático[cite: 2]:
* Si un atacante emite un único paquete desde una IP falsa, se crea una tupla inicial con peso $w = 1.0$ (ocupando unos 40 bytes)[cite: 2].
* Al no llegar más paquetes para esa IP, el decaimiento $2^{-\lambda \Delta t}$ actúa de forma agresiva en las ventanas rápidas[cite: 2].
* En pocos ciclos de reloj, el peso residual cae por debajo de un umbral infinitesimal ($w_i < \epsilon \approx 10^{-5}$)[cite: 2].
* Un recolector de memoria en segundo plano inspecciona la tabla de dispersión y **elimina cualquier entrada con peso residual nulo**, devolviendo la memoria al sistema operativo[cite: 2]. Gracias a esto, la huella de memoria se mantiene constante en torno a **1 MB para 1.000 conversaciones activas concurrentes**[cite: 2].

---

## Bloque 3: KitNET — La Falange de Micro-Autoencoders (50 min)

### 3.1 Fundamentos del Autoencoder como Detector de Anomalías
Un autoencoder es una red neuronal feed-forward entrenada para aprender la función identidad restringida: reconstruir en la capa de salida exactamente los valores que entraron en la capa de entrada ($h_\theta(\vec{x}) \approx \vec{x}$)[cite: 2].

```
                  ANATOMÍA DE UN AUTOENCODER RECONSTRUCTOR
                  
  Instancia x ∈ ℝ³            Capa Oculta (Cuello)          Salida Reconstruida (x̂)
 ┌──────────────────┐           ┌──────────────┐           ┌──────────────────┐
 │ Variable 1 (x₁)  ├──────────►│              ├──────────►│ Variable 1 (x̂₁)  │
 │ Variable 2 (x₂)  ├──────────►│ Compresión β │──────────►│ Variable 2 (x̂₂)  │
 │ Variable 3 (x₃)  ├──────────►│ (Ratio 0.75) │──────────►│ Variable 3 (x̂₃)  │
 └──────────────────┘           └──────────────┘           └──────────────────┘
          │                                                         ▲
          │                                                         │
          └──────────────── Medición del Error (RMSE) ──────────────┘
```

Para evitar que la red simplemente copie los datos de entrada en la salida, se impone un **cuello de botella**: la capa oculta intermedia dispone de menos neuronas que las capas visibles (controlado por un factor de compresión $\beta = 0.75$)[cite: 2]. 

1. **Entrenamiento no supervisado sobre tráfico limpio:** La red se alimenta únicamente de paquetes legítimos[cite: 2]. Ajusta sus matrices de pesos para capturar las correlaciones habituales del enlace[cite: 2]. La reconstrucción es precisa y el residuo es mínimo[cite: 2].
2. **Inferencia en producción:** Al entrar un paquete hostil con combinaciones de retardo o volúmenes anómalas, la red intenta comprimir y reconstruir esos valores utilizando las reglas aprendidas para el tráfico normal[cite: 2]. La reconstrucción falla y el **Error Cuadrático Medio (RMSE)** se dispara[cite: 2]:

$$RMSE(\vec{x}, \vec{x}') = \sqrt{\frac{\sum_{i=1}^{n}(x_i - x'_i)^2}{n}}$$
[cite: 2]

### 3.2 La Barrera Cuadrática del Modelo Monolítico ($\mathcal{O}(n^2)$)
Si intentáramos conectar las $n = 115$ características en una única red neuronal densa:
* Para activar la capa oculta ($86$ neuronas para $\beta = 0.75$), se requieren $115 \times 86 = 9.890$ operaciones de multiplicación y acumulación (MAC)[cite: 2].
* La capa de descompresión requiere otras $9.890$ operaciones adicionales[cite: 2].
* En total, cada trama demanda casi $20.000$ operaciones en inferencia y cerca de $40.000$ durante el entrenamiento[cite: 2].

En un procesador de router sin aceleración por hardware, esta carga de orden $\mathcal{O}(n^2)$ consume más de 1.000 microsegundos por paquete, limitando el rendimiento a menos de 1.000 paquetes por segundo y desbordando las colas de la red[cite: 2].

### 3.3 Arquitectura Desacoplada de KitNET ($\mathcal{O}(k^2)$)
Para eludir este cuello de botella, KitNET estructura su red en dos niveles desacoplados[cite: 2]:

```
                     Vector Completo x ∈ ℝ¹¹⁵ (AfterImage)
                                       │
                    Mapeador de Características (corClust)
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          ▼                            ▼                            ▼
    Subespacio v₁                Subespacio v₂                Subespacio vₖ
   (m ≤ 10 variables)           (m ≤ 10 variables)           (m ≤ 10 variables)
          │                            │                            │
    Micro-AE₁ (L1)               Micro-AE₂ (L1)               Micro-AEₖ (L1)
     (Ratio 0.75)                 (Ratio 0.75)                 (Ratio 0.75)
          │                            │                            │
       RMSE₁                        RMSE₂                        RMSEₖ
          └────────────────────────────┼────────────────────────────┘
                                       │
                      Vector de Errores z ∈ ℝᵏ (Norm 0-1)
                                       │
                                       ▼
                         Autoencoder de Salida θ₀ (L2)
                                       │
                            Score RMSE Final (s)
```
[cite: 2]

1. **Capa de Ensamble ($L^{(1)}$):** Compuesta por $k$ micro-autoencoders independientes[cite: 2]. Cada uno recibe exclusivamente un subconjunto disjunto de variables $\vec{v}_i$ acotado estrictamente a un tamaño máximo de **$m \le 10$ características**[cite: 2]. Cada micro-red tiene únicamente tres capas: $dim(\vec{v}_i)$ en entrada y salida, y $\lceil 0.75 \cdot dim(\vec{v}_i) \rceil$ en el cuello de botella[cite: 2].
2. **Capa de Salida ($L^{(2)}$):** Un autoencoder final $\theta_0$ que no recibe características de red, sino exclusivamente los $k$ errores de reconstrucción producidos por la primera capa, normalizados en el rango $[0, 1]$[cite: 2]. Su función es aprender qué discrepancias entre detectores son normales en el enlace[cite: 2].

#### Demostración del Ahorro Computacional
La complejidad de cómputo combinada de KitNET se formula como[cite: 2]:

$$\text{Complejidad Total} = \mathcal{O}(k \cdot m^2 + k^2) \approx \mathcal{O}(k^2)$$
[cite: 2]

Al fijar $m \le 10$ como constante pequeña, la Capa de Ensamble escala linealmente respecto al número de variables de entrada[cite: 2]. En los ensayos empíricos de NDSS 2018 sobre una **Raspberry Pi 3B** mononúcleo[cite: 2]:
* Autoencoder monolítico denso ($k = 1$): **~1.000 paquetes por segundo** (latencia $> 1.000\ \mu\text{s}$)[cite: 2].
* Ensamble KitNET particionado ($k = 35, m \le 10$): **~5.400 paquetes por segundo** (latencia $< 185\ \mu\text{s}$, una mejora de velocidad superior a 5x)[cite: 2].

### 3.4 Clustering Incremental No Supervisado (`corClust`)
KitNET no requiere que un operador defina manualmente qué variables vigila cada micro-red[cite: 2]. Durante los primeros paquetes de la red (`FM_grace_period`), el sistema infiere la estructura mediante agrupamiento correlacional[cite: 1, 2]:

1. Actualiza de forma incremental la matriz de distancias por correlación $D$ sin almacenar el histórico de paquetes[cite: 2]:

   $$D_{i,j} = 1 - \frac{C_{i,j}}{\sqrt{c_{rs}^{(i)} \cdot c_{rs}^{(j)}}}$$
[cite: 2]

2. Construye un dendrograma aglomerativo que agrupa las variables con trayectorias estadísticas afines[cite: 2].
3. Aplica una poda jerárquica descendente: corta los enlaces del árbol hasta garantizar que **ningún clúster contenga más de $m$ variables** ($m \le 10$)[cite: 2].
4. Asigna cada clúster a un micro-autoencoder específico en $L^{(1)}$ y sella la topología para el resto de la ejecución[cite: 2].

### 3.5 Aprendizaje Online en un Solo Paso (`max_iter = 1`)
En el siguiente período de gracia (`AD_grace_period`), KitNET entrena sus redes sin paradas de servicio ni lotes (*batches*)[cite: 1, 2]:
* Emplea Descenso de Gradiente Estocástico (SGD) con **`max_iter = 1`**[cite: 2].
* Cada paquete enseña a las micro-redes una sola vez y se destruye inmediatamente[cite: 2].
* Al concluir `AD_grace_period`, los pesos sinápticos se congelan y el sistema entra en **modo de ejecución pura (`exec-mode`)**, garantizando que un atacante persistente no pueda deformar el modelo para acostumbrarlo a un ataque continuo[cite: 2].

---

## Bloque 4: La Decisión — ¿Cuándo Suena la Alarma? (30 min)

### 4.1 La Capa de Salida ($L^{(2)}$) como Reductora del Suelo de Ruido
Si evaluáramos los errores de los $k$ micro-autoencoders de forma individual, el sistema sufriría una disyuntiva inviable[cite: 2]:
* Disparar la alarma si un solo micro-autoencoder falla genera tormentas inasumibles de falsos positivos ante cualquier fluctuación inofensiva de la red[cite: 2].
* Promediar linealmente los $k$ errores diluye los ataques específicos y sigilosos entre las decenas de detectores que marcan cero error[cite: 2].

La Capa de Salida resuelve esto correlacionando las discrepancias[cite: 2]. Como demostraron Mirsky et al. (NDSS 2018, Sección V-D), **$L^{(2)}$ reduce drásticamente el suelo de ruido basal del sistema**, absorbiendo las imperfecciones naturales de la red y amplificando únicamente las rupturas estructurales en las que detectores normalmente alineados entran en contradicción[cite: 2].

### 4.2 Límites de los Umbrales Estáticos y el Peligro del Máximo Empírico
El residuo final emitido por KitNET es un número continuo $s \in [0, \infty)$[cite: 2]. Para convertirlo en un veredicto de seguridad, se requiere un umbral de corte $\tau$[cite: 2].

Fijar este umbral mediante métodos empíricos tradicionales provoca fallos operativos severos[cite: 2]:
1. **Umbrales fijos arbitrarios:** Un número estático (p. ej., `umbral = 2.0`) genera alertas continuas en una red troncal ruidosa y queda completamente sordo en un enlace industrial silencioso[cite: 2].
2. **La trampa del máximo empírico ($\phi = \max(s_{\text{train}})$):** Durante las primeras iteraciones del entrenamiento SGD, los micro-autoencoders ajustan sus matrices desde valores aleatorios, produciendo **picos transitorios aislados de convergencia**[cite: 2].

```
               EL PICO TRANSITORIO DE CONVERGENCIA EN SGD
               
 RMSE ▲
      │   ▲ Transitorio Inicial: Paquete #2543 (RMSE = 600.74)
600  ─┼───┼────────────────────────────────────────────────────────
      │   │   (Desajuste momentáneo de pesos durante el SGD inicial)
      │   │
  1.0 ┼───┼──────────────────────────────────────── (Umbral Empírico Máximo)
      │   │
  0.4 ┼───┼──────────────────┬───┬───┬───┬───┬───┬─ (Tráfico Normal Estable: p99 ≈ 0.41)
  0.1 ┼───┴──────────────────┴───┴───┴───┴───┴───┴─ (Mediana Normal ≈ 0.12)
      └────────────────────────────────────────────────────────────►
      0                      5.000                       15.000     Paquetes
      
 * Consecuencia: Fijar el corte en 600.74 inutiliza el sensor perimetral.
   Ningún ataque de severidad media logrará superar ese umbral inflado.
```

En la traza de 120.000 paquetes de la botnet Mirai, se observa cómo en el paquete #2543 un transitorio inicial disparó un pico puntual de $RMSE = 600.74$, mientras que el tráfico normal estabilizado se mantuvo en una mediana de $0.1297$ y un percentil 99 de $0.4155$[cite: 1, 2]. Fijar el umbral en el máximo empírico habría dejado al sistema sordo ante el ataque real posterior[cite: 2].

### 4.3 Calibración Analítica Log-Normal del Umbral ($\tau$)
El error de reconstrucción sobre tráfico normal no sigue una curva normal simétrica; presenta una cota inferior rígida en cero ($s \ge 0$) y una asimetría positiva con cola pesada hacia la derecha[cite: 2]. Esta morfología responde formalmente a una **distribución log-normal**[cite: 2].

Al calcular el logaritmo de los errores en régimen normal estacionario ($y_i = \ln(s_i)$), la distribución se proyecta como una gaussiana limpia[cite: 2]:

$$\tau = \exp(\hat{\mu}_{\log} + k \cdot \hat{\sigma}_{\log})$$
[cite: 2]

Donde:
* $\hat{\mu}_{\log}$ es el centro de gravedad del murmullo ordinario de la red[cite: 2].
* $\hat{\sigma}_{\log}$ representa la dispersión natural de ese ruido base[cite: 2].
* $k$ es el multiplicador que define a cuántas desviaciones estándar colocamos la frontera de alarma[cite: 2].

### 4.4 Cuantificación del Apetito de Riesgo: $k = 3.0902 \implies FPR \le 0.001$
En la gestión corporativa del riesgo (GRD), el parámetro $k$ no es un valor empírico; es la formalización matemática del apetito de riesgo corporativo[cite: 2]:

$$P(s > \tau) = 1 - \Phi(k) = FPR$$
[cite: 2]

```
                 CALIBRACIÓN DEL APETITO DE RIESGO FRENTE A ALERTAS
                 
 Multiplicador (k)   Desviaciones   Tasa Teórica de Falsa Alarma (FPR)   Frecuencia Operativa en Cable
 ─────────────────   ────────────   ──────────────────────────────────   ─────────────────────────────
 k = 1.0000             1.0 σ       FPR ≈ 15.86%                         1 falsa alarma cada 6 paquetes
 k = 2.0000             2.0 σ       FPR ≈ 2.28%                          1 falsa alarma cada 44 paquetes
 k = 3.0000             3.0 σ       FPR ≈ 0.13%                          1 falsa alarma cada 740 paquetes
 ─────────────────────────────────────────────────────────────────────────────────────────────────────
 k = 3.0902             3.09 σ      FPR ≤ 0.0010 (0.10%)                 ≤ 1 falsa alarma cada 1.000 pkts
 ─────────────────────────────────────────────────────────────────────────────────────────────────────
 k = 3.7190             3.72 σ      FPR ≤ 0.0001 (0.01%)                 ≤ 1 falsa alarma cada 10.000 pkts
 k = 4.2650             4.26 σ      FPR ≤ 0.00001 (0.001%)               ≤ 1 falsa alarma cada 100.000 pkts
```
[cite: 2]

Fijando **$k = 3.0902$** según el estándar de NDSS 2018[cite: 2]:
1. Se garantiza matemáticamente una tasa de falsas alarmas **$FPR \le 0.001$** ($\le 1$ falso positivo por cada 1.000 paquetes analizados)[cite: 2].
2. Los picos transitorios de convergencia del SGD quedan absorbidos en la varianza sin inflar el umbral analítico de corte[cite: 2].

---

## Bloque 5: Taller Práctico y Demostración Forense (40 min)

### 5.1 Despliegue del Entorno y CLI Unificada de Kitsune
El entorno operativo moderno del proyecto se ejecuta sobre Python 3.9+ / 3.11 bajo Windows 11 Pro, estandarizado mediante `pyproject.toml`[cite: 1]:

```powershell
# 1. Clonar y acceder al entorno de trabajo
git clone [https://github.com/kitsune-research/Kitsune-py.git](https://github.com/kitsune-research/Kitsune-py.git)
cd Kitsune-py

# 2. Inicialización y activación del entorno virtual
python -m venv .venv
.venv\Scripts\Activate.ps1    # En Linux/macOS: source .venv/bin/activate

# 3. Instalación editable del paquete y dependencias modernas
pip install --upgrade pip
pip install -e .

# 4. Verificación de la interfaz de línea de comandos
kitsune --help
```
[cite: 1]

La suite CLI expone tres subcomandos fundamentales[cite: 1]:
* `kitsune demo`: Ejecución automatizada de extremo a extremo sobre traza de ataque preempaquetada con exportación de gráficas[cite: 1].
* `kitsune run`: Ingesta directa de archivos PCAP/CSV indicando límites y períodos de gracia de red[cite: 1].
* `kitsune eval`: Evaluación y contraste forense contra etiquetas binarias (*ground truth*) bajo estándares NDSS 2018[cite: 1, 2].

### 5.2 Caso de Estudio 1: Ataque Volumétrico (Mirai Botnet)
Ejecución sobre 120.000 paquetes reales capturados en una red de videovigilancia IoT infectada con malware Mirai[cite: 1, 2]:

```
[ TRAZA MIRAI BOTNET (120k PAQUETES) EN ESCALA SEMILOGARÍTMICA ]

RMSE (log)
 ▲
10⁵│                                                       ▲ Pico Telnet (>10⁴)
10⁴│                                                       │
10³│                                  ▲ Pico Ráfaga (>600) │
10²│                                  │                    │
10¹│                  Transitorio SGD │                    │
10⁰│                         ▲        │                    │  Decaimiento Continuo: 2^(-λt)
10⁻¹│────────────────────────┼────────┴────────────────────┴──┴───────┴─────── (Umbral τ)
10⁻²│────────────────────────┴──────────────────────────────────────────────── (Mediana = 0.1297)
    └──────────────┬─────────┬────────┬───────────────────────────────►
    0            2.000     3.000    7.000                           120.000  Índice de Paquete
    │◄─ Fase 1 ──►│◄ Fase 2 ►│◄ Fase 3►│◄────────────── Fase 4 ──────────────►│
       corClust       SGD       Base               Invasión e Infiltración Mirai
```
[cite: 1, 2]

* **Fase 1 (0 a 2.000 pkts):** Agrupamiento `corClust`; error plano en `0.0`[cite: 1, 2].
* **Fase 2 (2.001 a 3.000 pkts):** Convergencia SGD; pico transitorio aislado en el paquete #2543 ($RMSE = 600.74$)[cite: 2].
* **Fase 3 (3.001 a 7.000 pkts):** Régimen estacionario benigno; error confinado en mediana de $0.1297$ y percentil 99 de $0.4155$[cite: 2].
* **Fase 4 (7.001 a 120.000 pkts):** Inyección del ataque Mirai; ruptura del *manifold* con picos de $RMSE > 10^4$ y relajación en pendiente exponencial continua ($2^{-\lambda \Delta t}$) tras cada ráfaga de escaneo Telnet[cite: 1, 2].

### 5.3 Caso de Estudio 2: Reconocimiento Sigiloso (Nmap OS Fingerprinting)
Demostración de detección de bajo volumen sobre tráfico multimedia legítimo RTP utilizando la traza sintética del laboratorio[cite: 1, 2]:

```powershell
# Generar la traza de prueba (1.500 pkts RTP voz + 400 sondas Nmap)
python tests/generate_os_scan_trace.py

# Ingesta con períodos de gracia adaptados
python cli.py run data/samples/os_scan_micro.pcap --fm-grace 500 --ad-grace 1000 --plot docs/os_scan_plot.png
```
[cite: 1]

```
[ RECONOCIMIENTO SIGILOSO: NMAP OS SCAN (2.233 PAQUETES) ]

RMSE
 ▲
1e13│                                        ▲ Ruptura por Sondajes Nmap
    │                                       ┌┴──────────────────┐
    │                                      ┌┘                    └┐
    │                                     ┌┘                      └────
    │                                    ┌┘
    │  Tráfico Multimedia RTP Benigno   ┌┘
0.0 └──┴────────────────────────────────┴──────────────────────────────►
    0                                 1.500                     2.233   Paquetes
```
[cite: 2]

A pesar de que las sondas TCP SYN/Xmas respetan formalmente el estándar RFC y no transportan carga maliciosa, alteran bruscamente los retardos entre llegadas (*jitter*) y la simetría de canal en AfterImage, elevando el residuo de reconstrucción a órdenes de magnitud extremos ($10^{13}$) con separación total frente al tráfico normal[cite: 2].

### 5.4 Evaluación Forense Automatizada (`kitsune eval`)
Contraste formal frente al estándar de investigación de NDSS 2018 (Sección V-C)[cite: 1, 2]:

```powershell
kitsune eval --scores anomaly_scores.csv --labels ground_truth.csv
```
[cite: 1]

```text
======================================================================
KITSUNE NIDS: FORENSIC EVALUATION REPORT (NDSS 2018 Sec. V-C)
======================================================================
Total evaluated packets: 120,000
  Benign baseline (0)  : 112,418
  Malicious instances (1): 7,582
----------------------------------------------------------------------
ROC Area Under Curve (AUC)      : 0.9998
Equal Error Rate (EER)          : 0.0032 (at tau = 8.4812)
True Positive Rate (FPR <= 0.001): 99.72% (at tau = 8.6102)
False Negative Rate (FNR)       : 0.28%
======================================================================
```
[cite: 1, 2]

* **ROC AUC (0.9998):** Capacidad discriminativa casi perfecta con independencia del umbral de corte seleccionado[cite: 2].
* **TPR @ $FPR \le 0.001$ (99.72%):** Detección efectiva de prácticamente la totalidad del ataque limitando las falsas alarmas a un máximo de 1 cada 1.000 paquetes[cite: 2].
* **FNR (0.28%):** Ángulo ciego residual inferior a un tercio de un uno por ciento[cite: 2].
* **EER (0.0032):** Tasa de error simétrico donde falsos positivos y negativos se cruzan por debajo del 0.32%[cite: 2].

---

## Bloque 6: Despliegue en Producción y Gobernanza del Riesgo (20 min)

### 6.1 Topologías de Inserción Fuera de Banda (*Out-of-Band*)
Kitsune opera de forma no invasiva, desacoplado de la ruta crítica de datos[cite: 2]:

```
┌────────────────────────────────┐
│  Segmento de Red Corporativo   │
│     (Tráfico de Producción)    │
└───────────────┬────────────────┘
                │
                │ Duplicación pasiva (SPAN / TAP / Traffic Mirroring)
                ▼
┌────────────────────────────────┐
│      Sonda Kitsune (Edge)      │
│  - Ingesta en tiempo real O(1) │
│  - Ensamble KitNET O(k²)       │
│  - Decisión Analítica Log-Norm │
└───────────────┬────────────────┘
                │
                │ Syslog CEF / Webhook / EventBridge (Sólo si RMSE > τ)
                ▼
┌────────────────────────────────┐
│      SIEM / SOC Central        │
│    (Incidentes de Alto Valor)  │
└────────────────────────────────┘
```
[cite: 1, 2]

* **Entornos locales e industriales (OT):** Puerto espejo (*SPAN / Port Mirroring*) en switches de distribución o grifos pasivos de fibra/cobre (*Network TAP*)[cite: 2]. Los autores demostraron la viabilidad de utilizar una Raspberry Pi 3B configurada como puente de red pasivo (*bridge*) con un adaptador USB-Ethernet[cite: 2].
* **Infraestructuras Cloud (AWS VPC):** Duplicación de tráfico en hipervisor mediante **VPC Traffic Mirroring** sobre las interfaces elásticas (ENI), encapsulado vía túneles VXLAN hacia la instancia del sensor perimetral.
* **Integración limpia con el SOC:** La sonda opera en silencio total mientras el tráfico sea normal; únicamente emite eventos estructurados (Syslog/JSON) cuando el residuo supera la cota analítica $\tau$, reduciendo drásticamente la fatiga de alertas del equipo de seguridad[cite: 2].

### 6.2 Gestión de Riesgos Operativos y Resiliencia BCP

```
┌────────────────────────────────────────────────────────────────────────┐
│                   MATRIZ DE RIESGO OPERATIVO: KITSUNE                  │
├────────────────────────────────────────────────────────────────────────┤
│ RIESGO 1: Envenenamiento de la Línea Base (Baseline Poisoning)         │
│ Impacto: Si el atacante ya está presente durante AD_grace_period, el   │
│          sistema asume su actividad como tráfico benigno[cite: 2].   │
│ Mitigación: Desplegar la calibración inicial tras una auditoría        │
│             perimetral limpia o verificada con firmas tradicionales.   │
│                                                                        │
│ RIESGO 2: Evasión por Decaimiento Lento (Low & Slow Evasion)           │
│ Impacto: El atacante espacia los paquetes para diluir el residuo.      │
│ Mitigación: Las cinco ventanas temporales (hasta 60 segundos)          │
│             capturan rupturas de covarianza y dispersión de jitter[cite: 2].│
│                                                                        │
│ RIESGO 3: Continuidad Operativa ante Sobrecarga de Enlace              │
│ Impacto: Ráfagas extremas que superen la capacidad de la CPU embebida. │
│ Mitigación: La operación pasiva fuera de banda garantiza cero impacto  │
│             en el servicio; si la sonda satura sus búferes, el tráfico │
│             de producción continúa fluyendo sin interrupción[cite: 2].│
└────────────────────────────────────────────────────────────────────────┘
```
[cite: 2]

### 6.3 Resumen de Garantías de Ingeniería
1. **Consumo de memoria determinista:** La huella de memoria en ejecución permanece acotada a aproximadamente 1 MB para 1.000 conversaciones activas concurrentes gracias a la poda continua de tuplas inactivas ($w_i < \epsilon$)[cite: 2].
2. **Latencia acotada por paquete:** La descomposición en micro-redes ($m \le 10$) limita el coste de inferencia a menos de $185\ \mu\text{s}$ en hardware mononúcleo ARM, absorbiendo picos de más de 5.400 paquetes por segundo sin acumulación de colas en el kernel[cite: 2].
3. **Independencia de la nube:** La inferencia y la calibración se ejecutan íntegramente en local; la sonda mantiene su capacidad de detección perimetral ininterrumpida incluso ante caídas de los enlaces externos WAN[cite: 2].