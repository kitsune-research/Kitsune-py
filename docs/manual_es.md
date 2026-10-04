# Manual Práctico de Kitsune NIDS: Guía Completa de Cero a Producción ("Para Dummies")

**Autoría Técnica:** Tamamo-no-Mae & paradiselord-dev  
**Ecosistema:** kitsune-research / Kitsune-py (Python 3.9 - 3.11)  
**Referencia Base:** NDSS Symposium 2018 (Y. Mirsky et al.)

---

## 1. La Gran Analogía: ¿Qué demonios es Kitsune y por qué no usa GPUs?

Imagina un aeropuerto internacional con millones de pasajeros pasando cada minuto. Un sistema tradicional de Deep Learning pondría a un equipo de 50 inspectores con supercomputadoras a sacarle radiografías en 3D a cada persona, buscar en una base de datos de sospechosos conocidos y tardar 10 segundos por pasajero. Si llega un criminal que nunca antes fue fichado (un "ataque de día cero"), pasa inadvertido porque nadie sabe su cara.

**Kitsune funciona al revés:**
1. **No busca caras malas, aprende cómo camina la gente normal.**
2. **No guarda equipajes pasados en la memoria:** solo mira el flujo del segundo actual y olvida el pasado de inmediato.
3. **Es un ensamble de espejos deformantes (Autoencoders):** Cada espejo aprende a reflejar una postura normal. Si alguien camina normal, el espejo devuelve una imagen perfecta (error casi cero). Si entra un atacante corriendo de espaldas y gritando en binario (como el botnet Mirai), los espejos fallan estrepitosamente al reconstruirlo: la diferencia matemática entre lo que el espejo esperaba y lo que vio dispara la alarma de intrusión.

Y lo mejor: todo esto corre en una humilde Raspberry Pi o un router doméstico a velocidad de cable, sin requerir GPUs de miles de euros.

---

## 2. Los Cuatro Motores Bajo el Capó

El pipeline de Kitsune procesa paquetes en tiempo y memoria $O(1)$ a través de cuatro etapas secuenciales:

```
[ Paquete en Red ] 
         │
         ▼
┌─────────────────────────────────┐
│ 1. AfterImage (Extracción O(1)) │  ──► 5 ventanas temporales amortiguadas
└─────────────────────────────────┘      (100ms a 1min) ──► Vector de 100 dimensiones
         │
         ▼
┌─────────────────────────────────┐
│ 2. corClust (Mapeo Inteligente) │  ──► Agrupamiento por correlación jerárquica
└─────────────────────────────────┘      Parte las 100 variables en k subconjuntos (≤ 10)
         │
         ▼
┌─────────────────────────────────┐
│ 3. Ensamble L^(1) (Autoencoders)│  ──► k pequeños autoencoders entrenados con SGD
└─────────────────────────────────┘      Cada uno vigila su propio subconjunto de variables
         │
         ▼
┌─────────────────────────────────┐
│ 4. Capa de Salida L^(2) (Juez)  │  ──► Autoencoder maestro que analiza las discrepancias
└─────────────────────────────────┘      Genera el Score Final de Anomalía (RMSE)
```

### Motor 1: AfterImage (El Taquígrafo Amortiguado)
En lugar de guardar una lista gigante de todos los paquetes recibidos en el último minuto (lo que llenaría la memoria RAM en segundos), AfterImage mantiene un registro matemático amortiguado con un factor de decaimiento exponencial:

$$d_{\lambda}(t) = 2^{-\lambda t}$$

Donde $\lambda$ representa qué tan rápido olvidamos el pasado ($\lambda \in \{5, 3, 1, 0.1, 0.01\}$, desde 100 milisegundos hasta 1 minuto). Con solo tres variables (peso, suma lineal y suma cuadrática), AfterImage calcula al vuelo:
- Tasa de paquetes por segundo.
- Ancho de banda saliente y entrante.
- Jitter (variaciones de retraso entre paquetes).
- Covarianza y correlación entre sockets origen y destino.
Resultado: Un vector numérico exacto de 100 dimensiones por paquete, calculado en nanosegundos.

### Motor 2: corClust (Divide y Vencerás)
Si le damos un vector de 100 números a un solo autoencoder gigante, la matemática de matrices exige un esfuerzo de $O(n^2)$ (es decir, $100^2 = 10,000$ operaciones por capa).
Kitsune utiliza `corClust`: durante los primeros paquetes benignos (`FM_grace_period`), calcula qué variables se mueven juntas usando la distancia de correlación:

$$d_{	ext{cor}}(u, v) = 1 - rac{(u - ar{u}) \cdot (v - ar{v})}{\|u - ar{u}\|_2 \|v - ar{v}\|_2}$$

Y parte las 100 variables en familias pequeñas de máximo 10 variables cada una ($m \le 10$). Esto reduce la complejidad a $O(k^2)$, acelerando el sistema hasta 5 veces.

### Motor 3: La Capa de Ensamble $L^{(1)}$ (Los Inspectores Locales)
Cada familia de variables se asigna a su propio autoencoder de 3 capas con un factor de compresión $eta = 0.75$. Cada inspector aprende únicamente a reconstruir su pequeño grupo de variables normales mediante Descenso por Gradiente Estocástico (SGD) en una sola pasada. Cada autoencoder emite su error de reconstrucción:

$$	ext{RMSE}(x, y) = \sqrt{rac{\sum_{i=1}^{n} (x_i - y_i)^2}{n}}$$

### Motor 4: La Capa de Salida $L^{(2)}$ (El Tribunal Supremo)
Un autoencoder final recibe los errores de todos los inspectores locales. Si uno o varios inspectores sufren una crisis de reconstrucción al mismo tiempo, la capa de salida detecta la ruptura del patrón relacional global y eleva el RMSE final.

---

## 3. Comandos de la CLI: Guía de Uso Rápido

La suite modernizada ofrece una interfaz de línea de comandos limpia:

### Instalación en Modo Desarrollo
```bash
git clone https://github.com/kitsune-research/Kitsune-py.git
cd Kitsune-py
python -m pip install --upgrade pip
pip install -e .
```

### Ejecutar la Demo Integrada
```bash
# Procesa 15,000 paquetes de la traza Mirai de prueba
kitsune demo --limit 15000
```
Genera automáticamente:
- `demo_scores.csv`: La serie temporal de errores RMSE paquete por paquete.
- `demo_plot.png`: Gráfica visual de la intrusión.

### Analizar una Captura PCAP Propia
```bash
kitsune run trafico_sospechoso.pcap --limit 50000 --fm-grace 5000 --ad-grace 20000 --csv mis_scores.csv --plot deteccion.png
```

---

## 4. El Caso Real: Cazando a Mirai Botnet

Al analizar la traza real de 15,000 paquetes con la botnet Mirai atacando una cámara de videovigilancia, los números arrojan una separación quirúrgica:

| Segmento de Tráfico | Parámetro Estadístico | Valor Observado | Interpretación para Humanos |
| :--- | :--- | :--- | :--- |
| **Tráfico Benigno Basal** | Mediana ($p50$) | **0.1297 RMSE** | Tráfico normal, la red duerme tranquila. |
| | Percentil 99 ($p99$) | **0.4155 RMSE** | El 99% del ruido normal jamás supera este valor. |
| **Ataque Mirai Botnet** | Pico Anómalo (#12,322) | **11.2944 RMSE** | Escaneo masivo Telnet reventando los autoencoders. |
| **Separación de Señal** | Ratio sobre $p99$ | **27.18x** | La alarma suena 27 veces por encima del techo normal. |
| | Ratio sobre Mediana | **87.09x** | 87 veces por encima del valor típico basal. |

### La Trampa del Paquete #2543 (Desmitificada)
En las primeras versiones parecía haber una alarma gigante en el paquete #2543 con un RMSE de 600.74. No era un ataque: era un **artefacto numérico de convergencia inicial**. Al terminar el `FM_grace_period` (paquete 2,000), los pesos de la red neuronal apenas se estaban acomodando con las primeras iteraciones de SGD. Un verdadero ingeniero de datos sabe distinguir un temblor de calibración de una intrusión sostenida.

---

## 5. Control de Calidad: Tests y CI/CD

El proyecto cuenta con un arnés de pruebas automatizadas:
```bash
pytest tests/ -v --cov=.
```
Y una GitHub Actions Pipeline que compila y prueba automáticamente en una matriz cruzada:
- **Sistemas Operativos:** Ubuntu Latest y Windows Latest.
- **Versiones de Python:** 3.9, 3.10 y 3.11.
- **Dependencias de Red:** Enlazadas con `libpcap-dev`.
