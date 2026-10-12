# Doc 4: Guía de Despliegue en Producción, Topologías y Gobernanza BCP
### *Kitsune NIDS: Integración Perimetral Fuera de Banda, Endurecimiento Operativo y Resiliencia Empresarial (Nivel Máster GRD / EQF 7)*

---

## Control del Documento y Metadatos de Ingeniería

* **Identificador de Especificación:** `DOC-GRD-KITSUNE-PROD-04`
* **Nivel de Clasificación Técnica:** Nivel MECES 3 / European Qualifications Framework Level 7 (Arquitectura de Seguridad / Gestión de Riesgos de Continuidad de Negocio)
* **Entidades y Repositorios:** Upstream institucional `kitsune-research/Kitsune-py` y nodo de portafolio `paradiselord-dev/Kitsune-py`[cite: 1]
* **Base Teórica y Experimental:** Y. Mirsky et al., *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*, NDSS 2018, Secciones V y VI[cite: 2]
* **Ámbito de Aplicación:** Infraestructuras On-Premise (Switches Core / Entornos OT-SCADA), Edge Embebido (SoCs ARM Cortex) y Nubes Públicas (AWS VPC)[cite: 2]
* **Propósito:** Definir los patrones arquitectónicos de captura pasiva fuera de banda (*Out-of-Band*), los contratos de integración con SIEM/SOAR, la mitigación del riesgo de envenenamiento de línea base (*baseline poisoning*) y los controles de Continuidad de Negocio (BCP/DRP) frente a sobrecargas y ataques de agotamiento de recursos[cite: 2].

---

## 1. Topologías de Despliegue Pasivo Fuera de Banda (*Out-of-Band*)

Para garantizar la no interferencia con los flujos productivos y eliminar la latencia de procesamiento del camino crítico de red, Kitsune se despliega exclusivamente en modo **pasivo fuera de banda** (*Out-of-Band*)[cite: 2]. Bajo este modelo, el fallo total del proceso, el colapso del sistema operativo anfitrión o el bloqueo de la tarjeta de red del sensor no degradan ni interrumpen el tránsito legítimo de la infraestructura[cite: 2].

```
                 TOPOLOGÍAS DE INGESTA CORPORATIVA PASIVA
                 
 ┌─────────────────────────┐               ┌─────────────────────────┐
 │ RED LOCAL / OT INDUSTRIAL│               │   NUBE PÚBLICA (AWS)    │
 └────────────┬────────────┘               └────────────┬────────────┘
              │                                         │
    ┌─────────┴─────────┐                     ┌─────────┴─────────┐
    │ Switch Core / TAP │                     │ Instancias EC2 /  │
    │ Hardware Pasivo   │                     │ Interfaz ENI      │
    └─────────┬─────────┘                     └─────────┬─────────┘
              │                                         │
   Réplica    │ Réplica SPAN                  Réplica   │ VPC Traffic Mirroring
   Física     │ Copia Espejo                  Virtual   │ Encapsulado VXLAN
              ▼                                         ▼
   ┌───────────────────────┐                 ┌───────────────────────┐
   │ Sonda Kitsune (Edge)  │                 │ Sonda Kitsune (Cloud) │
   │ NIC en Modo Promiscuo │                 │ Desencapsulado VXLAN  │
   │ Ingesta O(1) Streaming│                 │ Ingesta O(1) Streaming│
   └──────────┬────────────┘                 └──────────┬────────────┘
              │                                         │
              └───────────────────┬─────────────────────┘
                                  │ Alerta Syslog CEF / JSON
                                  │ (Sólo si RMSE > τ)
                                  ▼
                     ┌─────────────────────────┐
                     │  SIEM / SOC Corporativo │
                     │ (Splunk / Sentinel / ES)│
                     └─────────────────────────┘
```

### 1.1 Puerto Espejo (*SPAN / Port Mirroring*) en Conmutadores
* **Principio de Operación:** El conmutador de distribución o núcleo duplica el tráfico de entrada y salida de las interfaces seleccionadas (o VLANs de producción) y lo reenvía hacia un puerto dedicado donde está conectada la interfaz de captura de Kitsune[cite: 2].
* **Requisitos de Interfaz:** La tarjeta de red (NIC) de la sonda debe operar en **modo promiscuo sin dirección IP configurada** en la interfaz de escucha, impidiendo la exposición del sensor a escaneos o intentos de explotación directa en capa 2 o capa 3[cite: 2].
* **Consideración de Tráfico:** Los puertos SPAN descartan tramas malformadas en capa física (errores FCS/CRC). Si se requiere auditoría estricta de perturbaciones en capa 1/2, se debe priorizar un TAP físico[cite: 2].

### 1.2 Grifo de Red Pasivo (*Network TAP*) y Puente Hardware
En segmentos industriales (SCADA/OT) o enlaces de alta criticidad donde los conmutadores no soportan la sobrecarga de puertos SPAN, se intercala un *Test Access Point* (TAP) pasivo de cobre o fibra óptica[cite: 2]:
* **Transparencia Física:** El TAP divide físicamente la señal lumínica o eléctrica; no introduce retardo y garantiza aislamiento galvánico de la sonda respecto a la red viva[cite: 2].
* **Implementación de Laboratorio / Bajo Coste (NDSS 2018 Sec. V-A):** En el estudio fundacional, los autores validaron el despliegue de una sonda perimetral convirtiendo una **Raspberry Pi 3B en un puente de red transparente** mediante un adaptador USB-a-Ethernet adicional[cite: 2]. La trama se procesa en tiempo real sin alterar las marcas temporales del cable[cite: 2].

### 1.3 Réplica de Tráfico en Nube Pública (*VPC Traffic Mirroring*)
En entornos virtualizados donde no existe acceso físico al conmutador:
* **Mecanismo:** Se activa *VPC Traffic Mirroring* sobre las Elastic Network Interfaces (ENI) de las instancias críticas.
* **Encapsulamiento:** El hipervisor empaqueta las tramas duplicadas dentro de datagramas UDP utilizando el protocolo estándar **VXLAN (puerto 4789)**.
* **Decodificación en la Sonda:** Kitsune recibe el flujo VXLAN, extrae la cabecera interna mediante Scapy o sockets crudos (`AF_PACKET`) y entrega la trama original directamente al motor de extracción AfterImage[cite: 1, 2].

### 1.4 Matriz Comparativa de Enfoques de Captura

| Característica | Puerto Espejo (SPAN) | TAP Hardware Pasivo | Cloud VPC Traffic Mirroring |
| :--- | :--- | :--- | :--- |
| **Punto Único de Fallo (SPOF)** | Nulo (Fail-Open en switch) | Nulo (Conmutación pasiva/óptica) | Nulo (Gestionado en hipervisor) |
| **Impacto en Producción** | Sobrecarga de backplane en switch | Cero impacto | Cero impacto en cómputo EC2 |
| **Pérdida por Saturación** | Descarta réplica si satura puerto | Requiere buffer en NIC receptora | Limitado por cuotas de VPC/interfaz |
| **Coste de Despliegue** | Cero (Configuración lógica) | Coste de hardware dedicado | Coste por GB analizado en nube |
| **Visibilidad de Tramas Corruptas** | No (Filtradas por el switch) | Sí (Captura total en capa física)[cite: 2] | No (Validadas en SDN) |

---

## 2. Dimensionamiento de Hardware y Capacidad Operativa

La viabilidad del despliegue en nodos perimetrales depende de la contención de recursos de CPU y memoria[cite: 2]. Kitsune fue diseñado para ejecutarse en microprocesadores mononúcleo sin acceso a unidades de procesamiento gráfico (GPU)[cite: 2].

```
                     PIPELINE DE ABSORCIÓN Y COLAS EN MEMORIA
                     
    Paquete en Tránsito (100 Mb/s - 1 Gb/s)
                       │
                       ▼
    ┌────────────────────────────────────────┐
    │     NIC Ring Buffer (Hardware RX)      │  (Configurar ethtool -G rx 4096)
    └──────────────────┬─────────────────────┘
                       │ Interrupciones NAPI / Driver
                       ▼
    ┌────────────────────────────────────────┐
    │      Kernel Socket Buffer (AF_PACKET)  │  (sysctl: rmem_max = 16MB)
    └──────────────────┬─────────────────────┘
                       │ Recogida en bloque (recvfrom / PACKET_MMAP)
                       ▼
    ┌────────────────────────────────────────┐
    │     AfterImage: Extracción O(1)        │  Huella Hash: ~1 MB para 1.000 flujos[cite: 2]
    │     - Tuplas IS en memoria continua    │  Poda Pasiva: w_i < ε (ε = 1e-5)[cite: 2]
    └──────────────────┬─────────────────────┘
                       │ Vector numérico de 115D
                       ▼
    ┌────────────────────────────────────────┐
    │     KitNET: Inferencia O(k²)           │  Latencia: < 185 µs en ARM (k=35)[cite: 2]
    │     - k micro-autoencoders (m ≤ 10)    │  Throughput: ~5.400 pkts/s (RPi 3B)[cite: 2]
    │     - 1 autoencoder de salida θ₀       │              ~37.300 pkts/s (x86 i7)[cite: 2]
    └────────────────────────────────────────┘
```

### 2.1 Requisitos de Infraestructura por Escenario

| Componente | Perfil Embebido / Edge (NDSS 2018)[cite: 2] | Perfil Servidor Corporativo (Edge Server) |
| :--- | :--- | :--- |
| **Dispositivo Modelo** | Raspberry Pi 3B / Gateways Industriales[cite: 2] | Appliance 1U / Instancia EC2 (`c6i.xlarge`) |
| **Arquitectura CPU** | Broadcom BCM2837 ARM Cortex-A53 @ 1.2 GHz[cite: 2] | Intel Xeon / AMD EPYC / Apple Silicon (x86/ARM) |
| **Núcleos Requeridos** | **1 único núcleo físico**[cite: 2] | 2 a 4 núcleos virtuales (1 Ingesta + 1 KitNET) |
| **Memoria RAM** | 1 GB total (Consumo Kitsune: $\approx 150\text{ MB}$)[cite: 2] | 4 GB a 8 GB ECC RAM |
| **Throughput Pico** | $\sim 5.400\text{ paquetes/segundo}$ ($k=35$)[cite: 2] | $\sim 37.300 - 50.000\text{ paquetes/segundo}$[cite: 2] |
| **Latencia Media** | $< 185\ \mu\text{s}$ por paquete en modo ejecución[cite: 2] | $< 25\ \mu\text{s}$ por paquete en modo ejecución |

### 2.2 Optimización de Búferes del Kernel y Prevención de Descartes
Para absorber ráfagas sin desbordar los búferes del sistema operativo en entornos de alto tráfico:

1. **Ajuste de Ring Buffers en Hardware:**
   ```bash
   ethtool -G eth0 rx 4096 tx 4096
   ```
2. **Ampliación del Búfer de Recepción de Sockets:**
   ```bash
   sysctl -w net.core.rmem_max=16777216
   sysctl -w net.core.rmem_default=16777216
   sysctl -w net.core.netdev_max_backlog=10000
   ```
3. **Mapeo de Memoria Compartida (`PACKET_MMAP`):**  
   En implementaciones de producción sobre Linux, sustituir llamadas directas `recvfrom()` por un búfer anular en memoria compartida entre el kernel y el espacio de usuario (`PACKET_RX_RING`) para eliminar el coste de copia de contexto por trama[cite: 2].

### 2.3 Huella de Memoria Determinista y Poda Pasiva
El uso de una tabla hash en AfterImage presenta el riesgo teórico de saturar la memoria si un atacante falsifica millones de IPs de origen (*State-Exhaustion DoS*)[cite: 2].

Kitsune neutraliza este riesgo mediante la **poda pasiva continua** gobernada por el factor de decaimiento[cite: 2]:
* **Tasa de Consumo:** En C++, una tupla estadística amortiguada para 5 ventanas temporales consume aproximadamente 40 bytes por flujo[cite: 2]. 1.000 conversaciones activas concurrentes ocupan aproximadamente **$1\text{ MB}$ de RAM**[cite: 2].
* **Condición de Desalojo:** Si un flujo efímero no recibe tráfico subsiguiente, su peso decae exponencialmente ($w_i = w_0 \cdot 2^{-\lambda \Delta t}$)[cite: 2].
* **Recolector de Estados:** El motor ejecuta un hilo ligero que purga cualquier registro cuyo peso descienda por debajo de $\epsilon = 10^{-5}$[cite: 2]:

$$\text{Desalojar flujo } S_i \iff w_i < 10^{-5}$$
[cite: 2]

Esto confina el consumo de memoria en una cota estricta determinista, impidiendo que el proceso sea terminado por el *Out-Of-Memory (OOM) Killer* del kernel[cite: 2].

---

## 3. Integración Corporativa con SIEM, SOAR y SOC

El objetivo de diseño de Kitsune es suprimir la fatiga de alertas del analista de seguridad[cite: 2]. Por tanto, la sonda opera en **silencio local determinista**, enviando telemetría al SIEM únicamente ante rupturas estocásticas confirmadas[cite: 2].

```
                     FLUJO DE EVENTOS HACIA EL CENTRO DE OPERACIONES
                     
 [ Tráfico de Red ] ──► [ Sonda Kitsune ]
                              │
                              ├── (RMSE ≤ τ) ──► Silencio Local (Paquete Liberado en RAM)[cite: 2]
                              │
                              └── (RMSE > τ) ──► Ruptura Estocástica Confirmada (FPR ≤ 0.001)[cite: 2]
                                                       │
                               ┌───────────────────────┴───────────────────────┐
                               ▼                                               ▼
                     [ Integración On-Premise ]                     [ Integración Cloud ]
                      Syslog RFC 5424 / CEF                          Amazon EventBridge / JSON
                               │                                               │
                               ▼                                               ▼
                     [ SIEM: Splunk / Sentinel ]                    [ SOC: SOAR / SNS Alert ]
```

### 3.1 Criterio de Emisión: Supresión del Suelo de Ruido
* **Evaluación Local:** Cada paquete procesado genera un error de reconstrucción global $s$ emitido por la Capa de Salida ($L^{(2)}$)[cite: 2].
* **Umbral Log-Normal:** El paquete se compara contra la frontera analítica calibrada $\tau = \exp(\hat{\mu}_{\log} + k \cdot \hat{\sigma}_{\log})$ con $k = 3.0902$[cite: 2].
* **Regla de Disparo:** Si $s \le \tau$, el paquete se libera de memoria sin registrar incidencias[cite: 2]. Si $s > \tau$, se genera un evento de seguridad estructurado[cite: 2].

### 3.2 Formato Estándar de Alerta (Common Event Format - CEF)
Para integración nativa en plataformas como Splunk, IBM QRadar o Microsoft Sentinel, la sonda formatea las anomalías bajo el estándar CEF sobre Syslog TLS (puerto TCP 6514):

```text
CEF:0|KitsuneResearch|KitsuneNIDS|0.2.0|ANOMALY_DETECTED|Statistical Network Anomaly|8|
src=192.168.1.105 dst=192.168.1.1 spt=44322 dpt=23 proto=TCP 
cs1Label=ScoreRMSE cs1=14.8231 cs2Label=Threshold cs2=8.6102 
cs3Label=Confidence cs3=0.9990 msg=Kinematic baseline deviation detected in ensemble L2
```

### 3.3 Formato JSON Estructurado para Automatizaciones SOAR
Para integración mediante Webhooks, brokers de mensajería (Kafka, RabbitMQ) o Amazon EventBridge:

```json
{
  "timestamp": "2026-10-12T14:47:00.124Z",
  "sensor_id": "kitsune-edge-ot-01",
  "event_type": "KITSUNE_ANOMALY_ALERT",
  "network_context": {
    "src_ip": "192.168.1.105",
    "src_mac": "B8:27:EB:55:A1:02",
    "dst_ip": "192.168.1.1",
    "dst_mac": "00:15:5D:12:34:56",
    "protocol": "TCP",
    "src_port": 44322,
    "dst_port": 23
  },
  "anomaly_metrics": {
    "rmse_score": 14.8231,
    "threshold_tau": 8.6102,
    "k_multiplier": 3.0902,
    "theoretical_fpr": 0.001,
    "compromised_layer": "L2_OUTPUT_ENSEMBLE"
  },
  "action_recommended": "QUARANTINE_SOURCE_IP"
}
```

---

## 4. Protocolo de Arranque y Mitigación del Riesgo de Envenenamiento

Dado que Kitsune es un sistema no supervisado que aprende de la propia red, el vector de amenaza más crítico es el **envenenamiento de la línea base** (*Baseline Poisoning*) durante sus ventanas iniciales de calibración[cite: 2].

```
                     CICLO DE ARRANQUE HIGIENIZADO EN CUATRO FASES
                     
  [ T0: Despliegue ] ──► Fase 1: Auditoría de Red Limpia (Inspección Suricata / Reglas ET)[cite: 2]
                                │ (Confirmación: Enlace Libre de Ataques Conocidos)
                                ▼
                         Fase 2: Feature Mapping (FM_grace_period: 2k - 5k pkts)[cite: 1, 2]
                                │ (Construcción del Dendrograma corClust)[cite: 2]
                                ▼
                         Fase 3: Entrenamiento Base (AD_grace_period: 10k - 50k pkts)[cite: 1, 2]
                                │ (SGD max_iter = 1 + Calibración MLE Log-Normal)[cite: 2]
                                ▼
  [ T_prod: Bloqueo ] ──► Fase 4: Congelación y Modo Ejecución Pura (exec-mode)[cite: 2]
                                  (Pesos Invariables + Detección Activa)[cite: 2]
```

### 4.1 Mecánica del Ataque de Envenenamiento (*Baseline Poisoning*)
Si un actor hostil está presente y activo en el segmento de red durante `AD_grace_period` (por ejemplo, transmitiendo balizas periódicas de C2 o ejecutando un canal encubierto), KitNET interpretará esos patrones como parte de la normalidad cotidiana[cite: 2]. Los micro-autoencoders ajustarán sus pesos para reconstruir esa agresión con residuo mínimo, volviéndose ciegos a la persistencia del ataque en producción[cite: 2].

### 4.2 Protocolo de Despliegue Higienizado (*Clean Window Deployment*)
Para mitigar esta vulnerabilidad, el procedimiento operativo estándar (SOP) exige un ciclo de inicialización estructurado[cite: 2]:

1. **Fase 1: Triaje con Firmas Tradicionales:**  
   Durante las primeras 24 horas previas al entrenamiento de Kitsune, se activa un motor de firmas (Suricata o Snort) con el conjunto completo de reglas activas[cite: 2]. Se verifica que el segmento esté libre de anomalías conocidas, tráfico hacia IPs maliciosas catalogadas o tráfico no autorizado[cite: 2].
2. **Fase 2: Agrupamiento Incremental (`FM_grace_period`):**  
   Se capturan entre $2.000$ y $5.000$ paquetes limpios[cite: 1, 2]. `corClust` actualiza la matriz de correlación $D_{i,j}$ y fragmenta las variables en subespacios de tamaño $m \le 10$[cite: 2].
3. **Fase 3: Convergencia Benigna (`AD_grace_period`):**  
   Se procesan entre $10.000$ y $50.000$ paquetes[cite: 1, 2]. KitNET ejecuta Descenso de Gradiente Estocástico (SGD) con `max_iter = 1`[cite: 2]. Hacia el final de esta fase, se calculan los estimadores de máxima verosimilitud ($\hat{\mu}_{\log}$, $\hat{\sigma}_{\log}$) y se computa el corte analítico $\tau$ con $k = 3.0902$[cite: 2].
4. **Fase 4: Congelación y Paso a Modo Ejecución (`exec-mode`):**  
   **Los pesos neuronales de todos los micro-autoencoders y de la capa de salida se congelan permanentemente**[cite: 2]. El sistema entra en producción operativa; ninguna trama futura altera las matrices sinápticas, bloqueando cualquier intento de manipulación progresiva del modelo[cite: 2].

### 4.3 Gestión de la Deriva Conceptual (*Concept Drift*)
Si la infraestructura sufre cambios estructurales legítimos (despliegue de un nuevo servidor, migración de telefonía VoIP o cambio de protocolos), el error de reconstrucción basal se elevará naturalmente[cite: 2].  
* **Política de Recalibración:** No se permite el reentrenamiento en caliente continuo.
* **Procedimiento:** Un operador del equipo de infraestructura programa una **ventana de mantenimiento certificada**, reinicia la máquina de estados del sensor e inicia un nuevo ciclo controlado de períodos de gracia[cite: 2].

---

## 5. Continuidad de Negocio (BCP) y Resiliencia del Servicio

Desde el marco de la Gestión del Riesgo y Continuidad del Negocio (ISO 22301 / BCP), los controles de seguridad perimetral nunca deben convertirse en vectores de indisponibilidad.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   MATRIZ DE RESILIENCIA Y CONTINUIDAD (BCP)            │
├────────────────────────────────────────────────────────────────────────┤
│ CONTROL BCP 1: Fail-Open Arquitectónico                                │
│ Mecanismo: Ingesta fuera de banda vía SPAN/TAP.                        │
│ Garantía: RTO = 0, RPO = 0 para el enlace productivo si la sonda cae[cite: 2]. │
│                                                                        │
│ CONTROL BCP 2: Inmunidad a Saturación de CPU                           │
│ Mecanismo: Complejidad acotada O(k²) con micro-redes acotadas (m ≤ 10)[cite: 2].│
│ Garantía: Latencia determinista <185 µs en ARM; cero cola de paquetes[cite: 2].│
│                                                                        │
│ CONTROL BCP 3: Supervivencia Perimetral Local (Edge Survivability)     │
│ Mecanismo: Inferencia autónoma desacoplada de nubes externas[cite: 2].       │
│ Garantía: Operación continua al 100% ante caídas de la conexión WAN[cite: 2].  │
│                                                                        │
│ CONTROL BCP 4: Poda Activa Anti-DoS de Estado                          │
│ Mecanismo: Recolector de tuplas inactivas con w_i < ε en AfterImage[cite: 2].  │
│ Garantía: Huella de memoria acotada a ~1 MB para 1.000 flujos[cite: 2].         │
└────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Principio Fail-Open y Desacoplamiento Operativo
* **Riesgo Operativo:** Un desbordamiento de búfer o fallo de segmentación (*Segmentation Fault*) en una herramienta de análisis que corra en línea (*In-Line*, como un IPS tradicional) interrumpe el tránsito del enlace corporativo.
* **Mitigación:** Al desplegarse sobre copias de tráfico (SPAN o puertos de monitorización de TAP), la indisponibilidad de la sonda Kitsune impacta únicamente la observabilidad de seguridad, manteniendo el tráfico productivo con una disponibilidad del **100% (RTO = 0, RPO = 0)**[cite: 2].

### 5.2 Autonomía Operativa Perimetral (*Edge Survivability*)
Las arquitecturas NIDS dependientes de servicios en la nube exponen al centro de trabajo a una pérdida crítica de visibilidad defensiva si se corta la conexión WAN o si el proveedor de nube sufre incidencias de servicio.  
Kitsune ejecuta la extracción estadística, el agrupamiento y la inferencia neuronal íntegramente en los ciclos de reloj de la CPU local[cite: 2]. El sensor continúa detectando movimientos laterales, infecciones por malware interno o escaneos sigilosos aunque la instalación quede completamente aislada de Internet[cite: 2].

---

## 6. Mapeo de Cumplimiento Normativo y Gobernanza

Para auditores de sistemas y comités de riesgo y cumplimiento, el despliegue de Kitsune proporciona evidencias cuantitativas alineadas con los principales marcos de referencia:

### 6.1 Esquema Nacional de Seguridad (ENS) / Real Decreto 311/2022
* **[op.exp.8] Detección de Intrusión:** Kitsune proporciona monitorización continua del tráfico sobre los puntos de interconexión perimetral, alertando ante comportamientos atípicos no catalogados[cite: 2].
* **[op.mon.1] Monitorización del Sistema:** Proporciona registro estructurado de eventos de anomalía sin registrar cargas útiles con datos de carácter personal, garantizando cumplimiento del principio de minimización de datos.

### 6.2 ISO/IEC 27001:2022 (Anexo A)
* **Control A.8.16 (Monitorización de Actividades):** Vigilancia comportamental en tiempo real sobre redes de datos para identificar anomalías operativas[cite: 2].
* **Control A.8.20 (Seguridad en Redes):** Segmentación y auditoría pasiva de flujos de transporte en infraestructuras críticas (PoE, IoT y vídeo sobre IP)[cite: 2].
* **Control A.8.23 (Segregación en Redes):** Detección temprana de roturas de límites de red y movimientos laterales mediante monitoreo de canales bidireccionales en AfterImage[cite: 2].

### 6.3 Directiva NIS2 (Seguridad de las Redes y Sistemas de Información)
* **Medidas de Gestión de Riesgos de Ciberseguridad (Artículo 21):** Capacidad analítica de detección temprana ante ciberataques avanzados y días cero en operadores esenciales e importantes sin fuga de metadatos confidenciales hacia servidores externos[cite: 2].

---

## 7. Anexo: Despliegue como Servicio y Automatización

### 7.1 Configuración de Servicio del Sistema Linux (`systemd`)
Archivo de definición para ejecución desatendida en `/etc/systemd/system/kitsune-nids.service`:

```ini
[Unit]
Description=Kitsune NIDS Production Monitoring Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/kitsune/Kitsune-py
Environment="PATH=/opt/kitsune/Kitsune-py/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
ExecStartPre=/sbin/ip link set dev eth1 promisc on
ExecStart=/opt/kitsune/Kitsune-py/.venv/bin/python cli.py run eth1 \
    --fm-grace 5000 \
    --ad-grace 50000 \
    --max-ae 10 \
    --csv /var/log/kitsune/anomaly_scores.csv
Restart=always
RestartSec=5s
LimitNOFILE=65535
MemoryMax=512M
CPUQuota=150%

[Install]
WantedBy=multi-user.target
```

### 7.2 Despliegue en Contenedor Docker Aislado
`Dockerfile` de producción multi-etapa optimizado para arquitecturas ARM64 y x86_64:

```dockerfile
FROM python:3.11-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ src/
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir build && \
    python -m build --wheel

FROM python:3.11-slim

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/dist/*.whl .
RUN pip install --no-cache-dir *.whl && rm -f *.whl

VOLUME ["/var/log/kitsune", "/data"]

# Ejecución requiriendo host networking para captura de tráfico
ENTRYPOINT ["kitsune"]
CMD ["--help"]
```

Comando de despliegue en host perimetral:

```bash
docker run -d \
  --name kitsune-sensor \
  --restart unless-stopped \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v /var/log/kitsune:/var/log/kitsune \
  kitsune-nids:latest run eth1 --fm-grace 5000 --ad-grace 50000
```

---

*Fin del documento técnico `DOC-GRD-KITSUNE-PROD-04`. Especificación lista para ser integrada en el repositorio de documentación técnica y servir como marco de referencia para auditorías de implantación perimetral y planes de continuidad de negocio (BCP).*[cite: 1]