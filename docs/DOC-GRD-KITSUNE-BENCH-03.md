# Doc 3: Informe Forense Experimental y Benchmarks
### *Kitsune NIDS: Validación Empírica, Análisis de Vectores Hostiles y Rendimiento en Hardware Restringido (NDSS 2018 Sec. V)*

---

## Control del Documento y Metadatos de Ingeniería

* **Identificador de Especificación:** `DOC-GRD-KITSUNE-BENCH-03`.
* **Nivel de Clasificación Técnica:** Nivel MECES 3 / European Qualifications Framework Level 7 (Auditoría Forense / Detección Comportamental de Redes).
* **Entidades y Repositorios:** Upstream institucional `kitsune-research/Kitsune-py` y nodo de portafolio `paradiselord-dev/Kitsune-py`[cite: 1].
* **Base Experimental:** Y. Mirsky et al., *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*, NDSS 2018, Sección V (*Evaluation*)[cite: 2].
* **Pila de Ejecución Local:** Windows 11 Pro, Python 3.11.9, Scapy, NumPy 2.x, CLI unificada (`kitsune eval`, `kitsune run`) y datasets de captura directa[cite: 1].
* **Propósito:** Formalizar los resultados empíricos, curvas de rendimiento, benchmarks de throughput/latencia en SoCs embebidos y la disección forense de los 9 vectores de ataque catalogados en el paper fundacional[cite: 2].

---

## 1. Metodología Experimental y Topologías de Red

La evaluación empírica de Kitsune se diseñó para contrastar su tasa de detección no supervisada frente a detectores de firmas comerciales y algoritmos de Machine Learning por lotes (*batch/offline*), operando sobre dos infraestructuras físicas de producción[cite: 2]:

```
                     TOPOLOGÍA 1: RED DE VIDEOVIGILANCIA IP (PoE)
                     
      [ Distribución A ]                                [ Distribución B ]
  4 Cámaras Sony SNC HD                              4 Cámaras Sony SNC HD
  (EM602RC, EM600, EB600, EB602R)                    (EM602RC, EM600, EB600, EB602R)
           │                                                  │
     Switch PoE (A)                                     Switch PoE (B)
           │                                                  │
           └───────────────────► Router VPN ◄─────────────────┘
                                     │ (Túnel IPsec S2S)
                              Switch Central
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
              [ Sonda KITSUNE ]                  Servidor DVR
             (Puerto Espejo SPAN)            (Almacenamiento RTSP)
                    ▲
                    │ Interceptación Física (Vector 1, 2)
              [ Atacante LAN ]

---------------------------------------------------------------------------------

                      TOPOLOGÍA 2: RED DOMÓTICA / IoT (Wi-Fi)
                      
   [ 9 Dispositivos IoT Heterogéneos ]              [ 3 Estaciones de Trabajo ]
   - Termostato inteligente                        - PCs de oficina (Navegación)
   - Monitor de bebés / Webcam                     
   - 2 Videoporteros IP                            
   - 4 Cámaras IP comerciales (Infección Mirai)     
                    │                                         │
                    └────────────────► Router Wi-Fi ◄─────────┘
                                           │
                                  [ Sonda KITSUNE ]
                                 (Monitoreo Pasivo)
```

### 1.1 Entorno 1: Red de Videovigilancia Comercial (Cámaras IP)
Diseñada para monitorizar flujos constantes de alta tasa de transferencia multimedia[cite: 2]. Emplea 8 cámaras de videovigilancia Sony profesionales alimentadas mediante PoE, transmitiendo vídeo H.264/MPEG-4 a 720p y 15 fps hacia un servidor DVR a través de un túnel VPN sitio a sitio[cite: 2]:
* **Modelos SNC-EM602RC / SNC-EM600:** Streaming mediante protocolo RTP sobre UDP (195 a 350 pkts/s sostenidos, 1.4 a 1.8 Mbps)[cite: 2].
* **Modelos SNC-EB600 / SNC-EB602R:** Streaming encapsulado en HTTPS (TLSv1) y HTTP/TCP (290 a 320 pkts/s, 1.8 Mbps)[cite: 2].
* **Punto de Captura:** Interfaz troncal del switch central antes del procesado en el DVR[cite: 2].

### 1.2 Entorno 2: Red Inalámbrica IoT (Vector Botnet)
Red inalámbrica compuesta por 9 dispositivos de Internet de las Cosas (termostato, monitor de bebés, webcam, dos videoporteros y cuatro cámaras de gama blanca) junto con tres ordenadores de escritorio que generan tráfico de navegación real[cite: 2]. En esta red se introdujo una muestra real de malware de la botnet Mirai para analizar la fase de infección y propagación transversal[cite: 2].

---

## 2. Catálogo Forense de Amenazas (Los 9 Vectores de NDSS 2018)

Se evaluaron 9 escenarios de ataque reales que comprometen la Confidencialidad (C), Integridad (I) y Disponibilidad (A) del canal[cite: 2]. Para cada escenario, los modelos fueron entrenados en el primer millón de paquetes benignos ($1.000.000$) y evaluados en el tráfico remanente de la captura[cite: 2]:

| Categoría | Vector Hostil | Herramienta / Método | Violación | Paquetes Totales | Duración Train | Duración Exec |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Reconocimiento** | **OS Scan** | Nmap | C | $1.697.851$ | $33.3\text{ min}$ | $18.9\text{ min}$[cite: 2] |
| **Reconocimiento** | **Fuzzing** | SFuzz | C | $2.244.139$ | $33.3\text{ min}$ | $52.2\text{ min}$[cite: 2] |
| **Man-in-the-Middle**| **Video Injection** | Video Jack | C, I | $2.472.401$ | $14.2\text{ min}$ | $19.2\text{ min}$[cite: 2] |
| **Man-in-the-Middle**| **ARP MitM** | Ettercap | C | $2.504.267$ | $8.05\text{ min}$ | $20.1\text{ min}$[cite: 2] |
| **Man-in-the-Middle**| **Active Wiretap** | Raspberry Pi 3B Bridge | C | $4.554.925$ | $20.8\text{ min}$ | $74.8\text{ min}$[cite: 2] |
| **Denegación (DoS)** | **SSDP Flood** | Saddam | A | $4.077.266$ | $14.4\text{ min}$ | $26.4\text{ min}$[cite: 2] |
| **Denegación (DoS)** | **SYN DoS** | Hping3 | A | $2.771.276$ | $18.7\text{ min}$ | $34.1\text{ min}$[cite: 2] |
| **Denegación (DoS)** | **SSL Renegotiation**| THC-SSL-DOS | A | $6.084.492$ | $10.7\text{ min}$ | $54.9\text{ min}$[cite: 2] |
| **Botnet Malware** | **Mirai Infection** | Telnet Worm propagation | C, I | $764.137$ | $52.0\text{ min}$ | $66.9\text{ min}$[cite: 2] |

---

## 3. Caso de Estudio 1: Inundación y Propagación Masiva (Mirai Botnet)

La botnet Mirai explota credenciales débiles por defecto en dispositivos IoT mediante fuerza bruta sobre el puerto Telnet ($23/2323$), convirtiendo los dispositivos comprometidos en nodos zombis para el lanzamiento de ataques DoS distribuidos[cite: 2].

```
                     TRAZA FORENSE MIRAI: FASES DE EVOLUCIÓN DEL RMSE
                     
  RMSE (Escala Logarítmica)
   ▲
10⁴│                                                      ▲ Escaneo Masivo Telnet (RMSE > 10⁴)
   │                                                      │
10²│                                 ▲ Pico Ráfaga SYN    │
   │                                 │                    │
10¹│                 Pico SGD (#2543)│                    │
   │                        ▲        │                    │  Decaimiento Continuo 2^(-λt)
10⁰│────────────────────────┼────────┴────────────────────┴───┴──────┴──────── (Umbral τ, FPR ≤ 0.001)
   │                        │
10⁻¹│════════════════════════╧═════════════════════════════════════════════════ (Mediana Normal = 0.1297)
   └──────────────┬─────────┬────────┬───────────────────────────────►
   0            2.000     3.000    7.000                           120.000    Índice de Paquetes
   │◄── Fase 1 ──►│◄ Fase 2 ►│◄ Fase 3►│◄────────────── Fase 4 ──────────────►│
      corClust       SGD       Régimen             Infección Activa y Propagación
      (Mapping)   Transitorio  Estacionario              de la Botnet Mirai
```

### 3.1 Anatomía de las Cuatro Fases de Ejecución

#### Fase 1: Extracción y Mapeo Estocástico (Paquetes 0 a 2.000)
* **Comportamiento del Sensor:** Durante el período `FM_grace_period = 2000`, AfterImage alimenta la matriz de distancia correlacional $D_{i,j}$ sin instanciar autoencoders[cite: 1, 2].
* **Firma Forense:** El residuo de salida es plano y nulo ($RMSE = 0.0$)[cite: 1, 2]. En esta etapa, el árbol dendrograma agrupa los canales en clústeres disjuntos de tamaño $m \le 10$[cite: 2].

#### Fase 2: Convergencia Numérica del SGD (Paquetes 2.001 a 3.000)
* **Comportamiento del Sensor:** KitNET inicializa sus matrices sinápticas con pesos aleatorios procedentes de la distribución uniforme $\mathcal{U}\left(-\frac{1}{dim(\vec{v}_i)}, \, \frac{1}{dim(\vec{v}_i)}\right)$ y ejecuta Descenso de Gradiente Estocástico (SGD) con `max_iter = 1` paquete a paquete[cite: 2].
* **Firma Forense:** Al acomodarse los hiperplanos a la variedad benigna, se registra un transitorio numérico de ajuste en el paquete **#2543**, donde el residuo experimenta un pico puntual de **$RMSE = 600.74$**[cite: 1, 2]. La calibración analítica log-normal aísla este pico en la dispersión $\hat{\sigma}_{\log}$, impidiendo el falseamiento del umbral[cite: 2].

#### Fase 3: Variedad Estacionaria Benigna (Paquetes 3.001 a 7.000)
* **Comportamiento del Sensor:** Los $k$ micro-autoencoders han completado su convergencia sobre el tráfico legítimo de la red Wi-Fi y los dispositivos IoT[cite: 1, 2].
* **Firma Forense:** El residuo global se confina dentro de una banda estrecha con una **mediana de $0.1297$** y un **percentil 99 ($p_{99}$) de $0.4155$**[cite: 1]. La reconstrucción sobre el tráfico habitual opera con pérdidas casi despreciables[cite: 2].

#### Fase 4: Compromiso Hostil e Infiltración Telnet (Paquetes 7.001 a 120.000)
* **Comportamiento del Sensor:** La cámara comprometida inicia el sondeo activo de propagación, inyectando ráfagas continuas de paquetes TCP SYN a destinos aleatorios[cite: 2].
* **Firma Forense:** El RMSE quiebra el umbral log-normal de alerta $\tau$, alcanzando valores superiores a $10^2$ y picos críticos de **$RMSE > 10^4$**[cite: 1, 2]. Tras el cese de cada ráfaga, la caída del error no es instantánea; exhibe una pendiente continua gobernada por la función amortiguada de AfterImage ($d_\lambda(\Delta t) = 2^{-\lambda \Delta t}$), capturando la inercia del estado de contaminación en la tabla hash[cite: 1, 2].

---

## 4. Caso de Estudio 2: Reconocimiento Sigiloso (Nmap OS Fingerprinting)

Frente a la inundación volumétrica de Mirai, el escaneo de huella de sistema operativo (*OS Fingerprinting*) ejecutado con Nmap representa el paradigma del atacante sigiloso de baja intensidad[cite: 2].

```
                     SONDEO SIGILOSO NMAP: EXPLOSIÓN DE RMSE
                     
  RMSE (Escala Lineal)
   ▲
1e13│                                        ▲ Ruptura Relacional Multicanal
    │                                       ┌┴──────────────────┐
    │                                      ┌┘                    └┐
    │                                     ┌┘                      └────
    │                                    ┌┘
    │   Tráfico Multimedia RTP Limpio   ┌┘
0.0 └───┴───────────────────────────────┴──────────────────────────────►
    0                                 1.500                     2.233   Índice de Paquetes
    │◄────── Calibración Benigna ──────►│◄─── Sondeo Furtivo Nmap ──►│
```

### 4.1 Ruptura Estructural de Covarianza en Canales RTP
1. **Conformidad de Protocolo:** Nmap transmite una secuencia acotada de sondas hacia la cámara (aproximadamente 400 paquetes en la traza sintetizada, y $697.851$ tramas en el dataset de producción extendido)[cite: 1, 2]. Utiliza banderas TCP legales (SYN a puertos cerrados, paquetes Xmas, flags FIN y combinaciones URG/PSH)[cite: 2].
2. **Ceguera de Firmas Tradicionales:** Ninguna regla estática de inspección de contenido (DPI) dispara la alarma, ya que no existe un *payload* de explotación binaria ni saturación de ancho de banda[cite: 2].
3. **Mecanismo de Detección en Kitsune:**
   * En condiciones benignas, el canal de la cámara emitía exclusivamente tráfico UDP/RTP con un retardo inter-paquete (*jitter*) regular y una covarianza bidireccional casi estricta entre subida y bajada ($Cov_{S_i, S_j}$)[cite: 2].
   * La inyección de paquetes TCP altera instantáneamente las estadísticas univariadas de tamaño y conteo en las ventanas rápidas ($\lambda = 5$ y $\lambda = 3$), colapsando las covarianzas bivariadas de canal en AfterImage[cite: 2].
   * Las micro-redes de KitNET especializadas en retardos y simetría de transporte emiten simultáneamente errores elevados en $L^{(1)}$[cite: 2]. La Capa de Salida ($L^{(2)}$), desacostumbrada a esa discordancia estructural, amplifica el fallo elevando el residuo hasta magnitudes del orden de **$10^{13}$**, permitiendo una separación nítida frente al ruido basal[cite: 1, 2].

---

## 5. Benchmarks de Detección: Kitsune vs. Estado del Arte (NDSS 2018 Sec. V-D)

Se evaluó la eficacia de Kitsune frente a cinco arquitecturas de referencia bajo condiciones idénticas de extracción de características[cite: 2]:
* **Suricata (NIDS Basado en Firmas):** Configurado con el repositorio completo de **13.465 reglas de Emerging Threats**[cite: 2].
* **Isolation Forest (IF):** Algoritmo no supervisado *offline/batch* basado en aislamiento de anomalías por hiperplanos[cite: 2].
* **Gaussian Mixture Models (GMM):** Modelo probabilístico *offline/batch* entrenado por Maximización de la Esperanza (EM)[cite: 2].
* **Incremental GMM (GMM Inc.):** Variante probabilística en línea para flujos dinámicos[cite: 2].
* **pcStream2:** Algoritmo de agrupamiento en streaming basado en distancias de Mahalanobis hacia centroides activos[cite: 2].

### 5.1 Matriz Comparativa Consolidada de Detección

```
========================================================================================================================
TABLA COMPARATIVA GLOBAL DE RENDIMIENTO FORENSE (NDSS 2018, SECCIÓN V-D, FIGURA 9)
========================================================================================================================
Dataset / Ataque      Métrica         Suricata    IsoForest      GMM       GMM Inc.    pcStream    Kitsune(m=10) Kitsune(m=1)
------------------------------------------------------------------------------------------------------------------------
ARP MitM              ROC AUC          0.5000      0.5984      0.7671       0.5984      0.7170      0.8842        0.9580
                      EER              0.5000      0.5563      0.2906       0.4388      0.2803      0.0774        0.1356
                      TPR @ FPR≤0.001  0.0000      0.5000      0.5563       0.2906      0.4388      0.6492        0.2315
                      FNR @ FPR≤0.001  1.0000      0.5000      0.4437       0.7094      0.5612      0.3508        0.7685
------------------------------------------------------------------------------------------------------------------------
OS Scan (Nmap)        ROC AUC          0.5000      0.9070      0.8403       0.6797      0.7419      0.8146        0.9548
                      EER              0.5000      0.1568      0.0940       0.0974      0.2803      0.0941        0.0941
                      TPR @ FPR≤0.001  0.0000      0.1568      0.0940       0.0974      0.0830      0.0941        0.0941
                      FNR @ FPR≤0.001  1.0000      0.8432      0.9060       0.9026      0.9170      0.9059        0.9059
------------------------------------------------------------------------------------------------------------------------
Video Injection       ROC AUC          0.5006      0.5166      0.8732       0.6866      0.5770      0.8538        0.9458
                      EER              0.4997      0.4907      0.2040       0.3499      0.3998      0.0228        0.2676
                      TPR @ FPR≤0.001  0.0006      0.4907      0.2040       0.3499      0.0006      0.2280        0.2676
                      FNR @ FPR≤0.001  0.9994      0.5093      0.7960       0.6501      0.9994      0.7720        0.7324
------------------------------------------------------------------------------------------------------------------------
Active Wiretap        ROC AUC          0.5000      0.5738      0.8788       0.5527      0.7393      0.9651        0.9993
                      EER              0.5000      0.5427      0.2103       0.5254      0.7498      0.1727        0.1693
                      TPR @ FPR≤0.001  0.0000      0.5427      0.2103       0.0845      0.0110      0.8108        0.1727
                      FNR @ FPR≤0.001  1.0000      0.4573      0.7897       0.9155      0.9890      0.1892        0.8273
------------------------------------------------------------------------------------------------------------------------
Mirai Botnet          ROC AUC          0.5005      0.5255      0.9993       0.5860      0.8737      0.9921        0.9900
                      EER              0.5002      0.5139      0.0110       0.4477      0.0003      0.0032        0.0032
                      TPR @ FPR≤0.001  0.0005      0.5139      0.0110       0.4477      0.0003      0.9972        0.9968
                      FNR @ FPR≤0.001  0.9995      0.4861      0.9890       0.5523      0.9997      0.0028        0.0032
------------------------------------------------------------------------------------------------------------------------
SYN DoS               ROC AUC          0.5000      0.5867      0.8335       0.6797      0.6347      0.9877        0.9942
                      EER              0.5000      0.4473      0.2360       0.2452      0.1684      0.0774        0.1356
                      TPR @ FPR≤0.001  0.0000      0.4473      0.2360       0.2452      0.0830      0.9877        0.9942
                      FNR @ FPR≤0.001  1.0000      0.5527      0.7640       0.7548      0.9170      0.0123        0.0058
========================================================================================================================
```

### 5.2 Hallazgos Forenses Clave

1. **El Colapso Estructural de Suricata:** Suricata obtuvo un área bajo la curva equivalente al azar puro ($\text{ROC AUC} \approx 0.50$) en 7 de los 9 escenarios analizados[cite: 2]. A pesar de cargar $13.465$ firmas activas, fue incapaz de detectar los ataques MitM (ARP, Active Wiretap, Video Injection), los sondeos de Nmap ni las inundaciones volumétricas complejas en la red IoT, demostrando la inoperancia de las firmas ante anomalías puramente cinemáticas o tráfico de red cifrado[cite: 2].
2. **Superioridad de Kitsune frente a Modelos Offline:** En la detección del *Active Wiretap* (puente transparente que intercepta cables Ethernet físicos), Kitsune con $m=1$ alcanzó un **$\text{ROC AUC} = 0.9993$**, superando ampliamente a los modelos por lotes más potentes como GMM ($0.8788$) e Isolation Forest ($0.5738$), pese a operar con una sola pasada de cómputo en streaming[cite: 2].
3. **El Efecto Filtro de Ruido en la Capa de Salida ($m=10$ vs. $m=1$):** Aunque teóricamente $m=1$ maximiza la sensibilidad aislando cada dimensión, en vectores complejos como *Active Wiretap* la configuración **$m=10$ obtuvo un $\text{TPR} = 81.08\%$ frente al $17.27\%$ de $m=1$ bajo la cota estricta de falsos positivos ($FPR \le 0.001$)**[cite: 2]. La Capa de Salida ($L^{(2)}$) actúa como un reductor del suelo de ruido basal que aplasta las fluctuaciones irrelevantes y amplifica las anomalías de relación[cite: 2].

---

## 6. Benchmarks de Runtime en Hardware Restringido (NDSS 2018 Sec. V-E)

Para validar la viabilidad de despliegue en conmutadores perimetrales y enrutadores domésticos, se evaluó el rendimiento temporal del ensamble KitNET codificado en C++ sobre dos plataformas de referencia utilizando $n=198$ métricas estadísticas sobre un único núcleo físico/lógico[cite: 2]:

```
+---------------------------------------------------------------------------------------+
|                ESPECIFICACIÓN DE ENTORNOS DE BENCHMARK (TABLA V)                      |
+---------------------------------------------------------------------------------------+
| Parámetro                  Plataforma Embebida              Estación de Trabajo (PC)   |
| Dispositivo:               Raspberry Pi 3B                  Máquina Virtual Ubuntu    |
| Procesador:                Broadcom BCM2837                 Intel Core i7-4790        |
| Frecuencia de Reloj:       1.2 GHz                          3.60 GHz                  |
| Núcleos Asignados:         1 núcleo físico (de 4)           1 núcleo lógico (de 8)    |
| Memoria RAM:               1 GB                             4 GB                      |
+---------------------------------------------------------------------------------------+
```

```
                    THROUGHPUT VS. TAMAÑO DEL ENSAMBLE (k)
                    
  Tasa de Paquetes/Seg
   ▲
40k│                                                        ▲ Ubuntu VM (Exec: ~37.300)
   │                                                       ┌┴──────────────────────────
30k│                                                      ┌┘  Ubuntu VM (Train: ~31.000)
   │                                                     ┌┘
20k│                                                    ┌┘
   │                                                   ┌┘
10k│                                                  ┌┘
   │   ▲ Ubuntu VM Monolítico (k=1: ~7.500)          ┌┘
 5k│───┼─────────────────────────────────────────────┴───── ▲ RPi 3B Ensamble (k=35: ~5.400)
   │   │                                             ══════ RPi 3B Monolítico (k=1: ~1.000)
 0 └───┴───────────────────────────────────────────────────►
       1                                             35     Número de Autoencoders (k)
```

### 6.1 Throughput de Paquetes en Streaming

* **Escalamiento en Raspberry Pi 3B:**  
  * Con un autoencoder monolítico ($k=1$ en $L^{(1)}$), la Raspberry Pi procesa **$\sim 1.000$ paquetes por segundo** en modo ejecución[cite: 2].
  * Con la descomposición en ensamble particionado ($k=35$ en $L^{(1)}$ con $m \le 10$), la tasa de procesamiento se eleva a **$\sim 5.400$ paquetes por segundo**, multiplicando la velocidad del nodo por un factor de **$5.4\times$**[cite: 2].
* **Escalamiento en Arquitectura x86 (Intel i7-4790):**  
  * El throughput pasa de **$\sim 7.500$ paquetes por segundo** ($k=1$) a más de **$37.300$ paquetes por segundo** ($k=35$) en modo ejecución, y **$31.000$ pkts/s** durante el entrenamiento online estocástico[cite: 2].

### 6.2 Latencia de Inferencia y Supresión de Varianza (*Jitter*)

El análisis de densidad temporal sobre el tiempo de procesamiento por paquete en la Raspberry Pi 3B (Fig. 11 de NDSS 2018) evidencia una transformación cualitativa en el comportamiento de la CPU[cite: 2]:

```
                     DENSIDAD DE TIEMPO DE PROCESAMIENTO (RPi 3B)
                     
  [ CASO k = 1: AUTOENCODER MONOLÍTICO ]
  Densidad
    ▲             Modo Execute                     Modo Train
    │                ┌───┐                            ┌───┐
    │               ┌┘   └┐                          ┌┘   └┐
    │             ┌─┘     └─┐                      ┌─┘     └─┐
    └─────────────┴─────────┴──────────────────────┴─────────┴─────────►
    850          950       1000                  1050       1100         Latencia [μs]
    (Alta dispersión: Latencia media ~970 μs en Exec, ~1050 μs en Train)

---------------------------------------------------------------------------------

  [ CASO k = 35: ENSAMBLE KITNET (m ≤ 10) ]
  Densidad
    ▲
  6 │      ▲ Modo Execute (Pico agudo en ~185 μs)
    │      │
    │     ┌┴┐
    │     │ │                                        ▲ Modo Train (~260 μs)
    └─────┴─┴────────────────────────────────────────┴─────────────────►
    175   185   200                                 260      275         Latencia [μs]
    (Baja dispersión: Inferencia determinista en <185 μs)
```

1. **Eliminación del Cuello de Botella:** La latencia media de ejecución por trama en la Raspberry Pi se desploma desde **$\sim 970\ \mu\text{s}$** hasta **$< 185\ \mu\text{s}$**[cite: 2].
2. **Supresión del Jitter Interno:** Con $k=1$, la distribución de tiempos es ancha y dispersa, provocando variabilidad indeseada en el procesado de colas[cite: 2]. Con $k=35$, la densidad converge en un pico hiper-concentrado alrededor de $185\ \mu\text{s}$, garantizando determinismo temporal en la absorción de paquetes de red sin desbordar los búferes del sistema operativo[cite: 2].

---

## 7. Protocolo de Auditoría y Verificación Local (`kitsune eval`)

Para garantizar la reproducibilidad científica de estos resultados en cualquier entorno de auditoría, la CLI de nuestro proyecto implementa el motor automatizado de evaluación forense en `src/kitsune/metrics.py`[cite: 1]:

```powershell
# 1. Ejecutar análisis forense completo contrastando scores contra Ground Truth
kitsune eval --scores anomaly_scores.csv --labels ground_truth.csv
```

### 7.1 Algoritmo de Cálculo de Métricas en Producción

```python
import numpy as np
from sklearn.metrics import roc_curve, auc

def evaluate_forensic_performance(scores: np.ndarray, labels: np.ndarray) -> dict:
    """
    Calcula las métricas de rendimiento según NDSS 2018 Sec. V-C.
    """
    fpr_array, tpr_array, thresholds = roc_curve(labels, scores)
    roc_auc = auc(fpr_array, tpr_array)
    
    # 1. Equal Error Rate (EER): Punto donde FNR == FPR
    fnr_array = 1.0 - tpr_array
    eer_idx = np.nanargmin(np.absolute(fnr_array - fpr_array))
    eer = (fpr_array[eer_idx] + fnr_array[eer_idx]) / 2.0
    eer_tau = thresholds[eer_idx]
    
    # 2. True Positive Rate bajo cota estricta FPR <= 0.001
    valid_fpr_indices = np.where(fpr_array <= 0.001)[0]
    optimal_idx = valid_fpr_indices[-1] if len(valid_fpr_indices) > 0 else 0
    tpr_at_low_fpr = tpr_array[optimal_idx]
    fnr_at_low_fpr = 1.0 - tpr_at_low_fpr
    tau_low_fpr = thresholds[optimal_idx]
    
    return {
        "ROC_AUC": float(roc_auc),
        "EER": float(eer),
        "EER_tau": float(eer_tau),
        "TPR_at_low_FPR": float(tpr_at_low_fpr),
        "FNR_at_low_FPR": float(fnr_at_low_fpr),
        "tau_operational": float(tau_low_fpr)
    }
```

---

*Fin del documento técnico `DOC-GRD-KITSUNE-BENCH-03`. Memoria experimental lista para archivo en el repositorio de documentación técnica, soporte de certificación y base empírica de divulgación tecnológica.*[cite: 1]