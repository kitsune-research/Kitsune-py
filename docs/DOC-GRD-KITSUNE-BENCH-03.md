# DOC-GRD-KITSUNE-BENCH-03: Evaluación Empírica y Confrontación Arquitectónica (Kitsune NIDS vs. Suricata IDS)

**Código de Documento:** `DOC-GRD-KITSUNE-BENCH-03`  
**Versión:** `1.0.0`  
**Fecha de Consolidación:** 14 de noviembre de 2026  
**Marco de Referencia:** EQF Level 7 / MECES 3 — Ingeniería de Detección de Intrusiones y Aprendizaje Automático Online  
**Repositorio:** `kitsune-research/Kitsune-py` (`v0.4.0`)

---

## 1. Resumen Ejecutivo

Este informe documenta la evaluación empírica de `Kitsune-py` frente al motor de detección basado en firmas **Suricata 8.0.8** sobre la traza canónica de infección y propagación de la botnet **Mirai** ($764{.}137$ tramas L2–L4). Los experimentos verifican la fidelidad matemática de la implementación frente al trabajo fundacional de Mirsky et al. (NDSS 2018) y demuestran la superioridad operativa de la detección no supervisada en entornos de borde frente a reglas estáticas cuando no existen firmas explícitas coincidentes.

---

## 2. Topología del Banco de Pruebas y Metodología

El entorno de validación (`LAB-WS-01`) se construyó sobre un bus virtual de nivel 2 aislado (`veth-inj` $\leftrightarrow$ `veth-nids`) con descarga por hardware (*TSO*, *GRO*, *LRO*) deshabilitada y buffers de recepción del kernel ampliados (`rmem_max` $= 16\ \mathrm{MB}$, `netdev_max_backlog` $= 10{.}000$):

* **Traza de Evaluación:** `mirai.pcap` ($764{.}137$ tramas). Fase benigna de operación normal entre los paquetes $1$ y $121{.}999$; inicio de escaneo e intrusión Telnet de Mirai en el paquete $122{.}000$ ($642{.}137$ tramas maliciosas).
* **Configuración Kitsune NIDS:**
  * **AfterImage FE:** Estadísticas incrementales amortiguadas mediante $d_{\lambda}(\Delta t) = 2^{-\lambda \Delta t}$ sobre $\lambda \in \{5, 3, 1, 0{.}1, 0{.}01\}$ ($100\ \mathrm{ms}$ a $1\ \mathrm{min}$). Espacio vectorial estrictamente acotado a $\mathbb{R}^{100}$ ($20$ métricas continuas $\times$ $5$ ventanas temporales, suprimiendo el *jitter* de canal para preservar complejidad $\mathcal{O}(1)$).
  * **KitNET AD:** Agrupamiento jerárquico incremental (`corClust`) con cota rígida $m \le 10$ que particiona $\mathbb{R}^{100}$ en $k = 16$ autoencoders ($\bar{m} = 6{,}25$), razón de compresión $\beta = 0{,}75$, complejidad de inferencia $\mathcal{O}(k^2)$ y entrenamiento online estricto ($\mathrm{max\_iter} = 1$) durante un período de gracia de $20{.}000$ tramas.
* **Configuración Suricata 8.0.8 IDS:** Captura en modo sistema mediante `AF_PACKET` sobre `veth-nids` ($4$ hilos de trabajo `W: 4`, `FM: 1`, `FR: 1`), cargando $69{.}469$ reglas de *Emerging Threats Open* ($53{.}495$ firmas activas tras `suricata-update`), bajo inyección controlada de `tcpreplay` a $5{.}000\ \mathrm{pps}$.

---

## 3. Resultados Empíricos y Matriz de Confrontación

### 3.1. Rendimiento de Detección (Kitsune NIDS)

Sobre las $744{.}137$ tramas evaluadas en fase de ejecución ($101{.}999$ benignas y $642{.}137$ maliciosas), el piso de ruido benigno registró $\mu_{\mathrm{RMSE}} = 0{,}026040$, mientras que el tráfico de escaneo de Mirai elevó el residuo de reconstrucción por encima de $0{,}60$:

| Punto Operativo | Umbral ($\tau$) | $\mathrm{TP}$ | $\mathrm{FN}$ | $\mathrm{FP}$ | $\mathrm{TN}$ | $\mathrm{TPR}$ (Sensibilidad) | $\mathrm{FPR}$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Calibración Estadística ($\tau_{3\sigma}$)** | $0{,}114134$ | $567{.}987$ | $74{.}150$ | $2{.}096$ | $99{.}903$ | **$88{,}4526\%$** | $2{,}0549\%$ |
| **Estándar NDSS 2018 ($\mathrm{FPR} = 0{,}1\%$)** | $0{,}302031$ | $566{.}520$ | $75{.}617$ | $102$ | $101{.}897$ | **$88{,}2242\%$** | **$0{,}1000\%$** |

### 3.2. Comportamiento de Suricata 8.0.8 (Firmas *Emerging Threats Open*)

De las $764{.}137$ tramas capturadas en interfaz (`kernel_drops`: $1{.}436$, $0{,}19\%$), Suricata decodificó $762{.}701$ paquetes y generó exactamente **$4{.}533$ alertas** en `fast.log`:

| Firma / Regla Disparada (`SID`) | Impactos | Clasificación Forense |
| :--- | :---: | :--- |
| `[1:2200121:1] SURICATA Ethertype unknown` | $4{.}380$ | Ruido L2 del decodificador ante tramas IoT Wi-Fi heterogéneas ($96{,}62\%$). |
| `[1:2200075:2] SURICATA UDPv4 invalid checksum` | $148$ | Anomalía de suma de verificación en capa de transporte ($3{,}26\%$). |
| `[1:2210063:2] SURICATA STREAM 3way handshake excessive different SYNs` | $5$ | Heurística genérica de flujo TCP ($0{,}11\%$). |
| **Firmas específicas de malware Mirai / Telnet Brute-Force** | **$0$** | **Ceguera total de firma ($\mathrm{TPR}_{\mathrm{Mirai}} = 0{,}00\%$).** |

---

## 4. Comparativa de Huella Computacional y Eficiencia

| Dimensión Técnica | Kitsune NIDS (`Kitsune-py` v0.4.0) | Suricata 8.0.8 IDS (`AF_PACKET`) |
| :--- | :--- | :--- |
| **Paradigma** | Aprendizaje no supervisado online ($\mathrm{max\_iter}=1$) | Inspección determinista por firmas y estado de flujo |
| **Complejidad Asintótica** | $\mathcal{O}(1)$ extracción / $\mathcal{O}(k^2)$ inferencia ($k=16$) | $\mathcal{O}(R \cdot L)$ búsqueda multipatrón ($53{.}495$ reglas) |
| **Memoria Residente ($\mathrm{RSS}$)** | **$\approx 85\ \mathrm{MB}$** (estado incremental acotado) | **$486{.}668\ \mathrm{KB}$ ($\approx 475{,}26\ \mathrm{MB}$)** |
| **Latencia de Procesamiento** | $p_{99} = 9{,}23\ \mathrm{ms}$ (pipeline acelerado con `tshark`) | Tiempo real multihilo ($10\%$ CPU en $4$ workers) |
| **Requisito de Etiquetado** | **Cero** (autocalibración en tráfico benigno) | Alto (dependiente de actualización continua de reglas) |

---

## 5. Conclusiones Arquitectónicas

1. **Complementariedad Operativa:** Suricata ofrece un rendimiento excelente para amenazas conocidas con firmas maduras, pero exige $\approx 475\ \mathrm{MB}$ de RAM base y resulta ciego frente a variantes de escaneo IoT sin firma coincidente ($\mathrm{TPR} = 0{,}00\%$).
2. **Viabilidad en Dispositivos de Borde:** Kitsune NIDS demuestra una capacidad de detección superior al $88{,}2\%$ manteniendo una tasa de falsos positivos de apenas $0{,}10\%$ sin supervisión previa, validando su despliegue en pasarelas IoT y sensores con memoria restringida.
3. **Evolución hacia Hito 4:** La transición de la extracción de características hacia una extensión compilada en Cython/Rust permitirá cerrar la brecha de *throughput* de Python puro frente a enlaces de alta velocidad manteniendo intacta la precisión matemática del ensamble KitNET.
