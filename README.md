# Layer 2 Network Attack Detection System

Sistema de detección de ataques a nivel de enlace de datos (Layer 2) mediante análisis de tráfico ARP en tiempo real.

## Descripción

Este proyecto resuelve la necesidad de detectar ataques que ocurren a nivel de enlace de datos (Layer 2), los cuales son invisibles para muchos sistemas de seguridad tradicionales que operan en capas superiores.

### Ataques Detectados

- **ARP Spoofing/Poisoning** - Suplantación de identidad en la red
- **Man-in-the-Middle (MITM)** - Interceptación de comunicaciones
- **ARP Flooding** - Ataques de denegación de servicio
- **MAC Flooding** - Saturación de tablas de switches
- **Network Reconnaissance** - Escaneo y mapeo no autorizado

## Stack Tecnológico

- **Bash 4+** - Motor de scripting principal
- **tshark** (Wireshark CLI) - Captura de paquetes de red
- **jq** - Procesamiento complejo de JSON con pipelines funcionales
- **msmtp** - Cliente SMTP ligero para notificaciones (opcional)
- **JSON** - Formato de almacenamiento y análisis

## Sistema de Detección

Implementa 5 reglas de correlación mediante procesamiento de streams con jq:

| Regla | Severidad | Descripción |
|-------|-----------|-------------|
| **MAC_DUPLICATE** | CRITICAL | Detecta clonación de MAC addresses |
| **IP_CONFLICT** | CRITICAL | Identifica conflictos de IP (ARP spoofing) |
| **SUDDEN_IP_CHANGE** | HIGH | Cambios rápidos sospechosos (MITM) |
| **ARP_FLOOD** | HIGH | Tasa anormal de paquetes ARP |
| **MAC_FLAPPING** | MEDIUM | Inestabilidad de tablas ARP |

## Innovaciones Clave

### 1. Análisis en Tiempo Real
- Modo live con actualización continua
- Procesamiento incremental de streams
- Visualización instantánea de amenazas

### 2. Motor de Correlación Avanzado
- Análisis temporal de patrones
- Detección de anomalías por comportamiento
- Ventanas deslizantes configurables

### 3. Sistema de Alertas Inteligente
- Clasificación por severidad (CRITICAL/HIGH/MEDIUM)
- Notificaciones HTML responsivas por email
- Rate limiting anti-spam (5 min cooldown)
- Filtrado configurable por criticidad

### 4. Footprinting de Red
- Mapeo automático de dispositivos
- Análisis de patrones de comunicación
- Estadísticas por dispositivo (requests/replies ratio)

## Instalación

### Requisitos del Sistema

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install tshark jq msmtp

# Fedora/RHEL
sudo dnf install wireshark-cli jq msmtp

# Arch Linux
sudo pacman -S wireshark-cli jq msmtp
```

### Configuración de Permisos

**Opción 1: Ejecutar con sudo (recomendado para pruebas)**
```bash
sudo ./l2_monitor.sh
```

**Opción 2: Configurar capabilities (para uso regular)**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)
sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)
```

### Configuración de Alertas por Email (Opcional)

Crear archivo `~/.msmtprc`:

```ini
# Gmail
account default
host smtp.gmail.com
port 587
from tu-email@gmail.com
user tu-email@gmail.com
password tu-contraseña-app
auth on
tls on
tls_starttls on

# SMTP Local
account local
host localhost
port 25
from alerts@$(hostname)
```

Dar permisos:
```bash
chmod 600 ~/.msmtprc
```

## Uso

### Sintaxis General

```bash
sudo ./l2_monitor.sh [OPCIONES]
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `-i, --interface IFACE` | Interfaz de red a monitorear (autodetecta si se omite) |
| `-d, --duration SECONDS` | Duración de captura en segundos (default: 30) |
| `-l, --live` | Modo análisis en tiempo real continuo |
| `-a, --alert EMAIL` | Email para alertas |
| `-s, --severity LEVEL` | Severidad mínima: CRITICAL\|HIGH\|MEDIUM (default: MEDIUM) |
| `-D, --debug` | Modo debug (verbose + archivos de depuración) |
| `-P, --profile` | Generar perfiles detallados de dispositivos |
| `-h, --help` | Mostrar ayuda |

### Ejemplos de Uso

#### Captura básica de 60 segundos
```bash
sudo ./l2_monitor.sh -d 60
```

#### Modo live en interfaz específica
```bash
sudo ./l2_monitor.sh -i eth0 -l
```

#### Monitoreo con alertas por email
```bash
sudo ./l2_monitor.sh -i wlan0 -d 120 -a security@empresa.com
```

#### Solo alertas críticas
```bash
sudo ./l2_monitor.sh -s CRITICAL -a admin@example.com
```

#### Monitoreo continuo de WiFi
```bash
sudo ./l2_monitor.sh -i wlan0 -l -s HIGH
```

## Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────┐
│                   L2 Monitor System                      │
└─────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│   Captura     │  │   Análisis    │  │    Alertas    │
│   (tshark)    │→ │     (jq)      │→ │   (msmtp)     │
└───────────────┘  └───────────────┘  └───────────────┘
        │                  │                  │
        ▼                  ▼                  ▼
  arp_data.json   network_state.json    alerts.log
```

### Flujo de Datos

1. **Captura**: tshark captura paquetes ARP en formato JSON
2. **Procesamiento**: jq transforma y agrega datos en estado de red
3. **Correlación**: Motor ejecuta 5 reglas de detección
4. **Alertas**: Sistema notifica según severidad y cooldown
5. **Reporte**: Genera footprint y estadísticas visuales

## Salida del Sistema

### Consola

```
═══════════════════════════════════════════════════════
        LAYER 2 NETWORK SECURITY REPORT
═══════════════════════════════════════════════════════

📊 Estadísticas Generales:
  • Hosts únicos detectados: 15
  • Total paquetes ARP: 342
  • Hosts sospechosos: 2

⚠ ALERTA: MAC_DUPLICATE
Severidad: CRITICAL | Confianza: 95%
Clonación de MAC address detectada
IP 192.168.1.100 asociada con 2 MACs diferentes: aa:bb:cc:11:22:33, dd:ee:ff:44:55:66

📡 Top 10 Dispositivos Más Activos:
  192.168.1.1    | MAC: aa:bb:cc:dd:ee:ff | Paquetes: 120 | Req/Rep: 60/60
  192.168.1.100  | MAC: 11:22:33:44:55:66 | Paquetes: 89  | Req/Rep: 45/44

🗺️  Network Footprint (IP → MAC Mapping):
  ✓  192.168.1.1   → aa:bb:cc:dd:ee:ff
  ⚠️  192.168.1.100 → aa:bb:cc:11:22:33, dd:ee:ff:44:55:66 [MÚLTIPLES MACs]

🔍 Análisis de Comportamiento:
  • 192.168.1.100: SOSPECHOSO: Múltiples MACs (Req/Rep ratio: 98%)
  • 192.168.1.50: ALTO TRÁFICO: Posible escaneo (Req/Rep ratio: 5%)
```

### Archivos Generados

- `l2_monitor.log` - Log completo del sistema
- `alerts.log` - Registro de todas las alertas
- `arp_data.json` - Datos crudos capturados
- `network_state.json` - Estado agregado de la red

## Escenarios de Detección

### Escenario 1: ARP Spoofing

**Ataque**:
```bash
# Atacante ejecuta:
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
```

**Detección**:
```
⚠ ALERTA: IP_CONFLICT
Severidad: CRITICAL | Confianza: 95%
MAC aa:bb:cc:dd:ee:ff pretende ser múltiples IPs: 192.168.1.1, 192.168.1.100
```

### Escenario 2: Man-in-the-Middle

**Ataque**:
```bash
# Atacante cambia rápidamente de identidad
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//
```

**Detección**:
```
⚠ ALERTA: SUDDEN_IP_CHANGE
Severidad: HIGH | Confianza: 80%
IP 192.168.1.1 cambió de MAC 3 veces en 15 segundos
```

### Escenario 3: Network Reconnaissance

**Ataque**:
```bash
# Escaneo de red
nmap -PR 192.168.1.0/24
```

**Detección**:
```
⚠ ALERTA: ARP_FLOOD
Severidad: HIGH | Confianza: 95%
IP 192.168.1.50 generó 250 paquetes ARP (4 pps)
```

## Parámetros de Configuración

Editar variables en la sección de configuración del script:

```bash
# Detección
readonly TIME_WINDOW=60                    # Ventana de análisis (segundos)
readonly ARP_FLOOD_THRESHOLD=50            # Umbral de flooding
readonly IP_CHANGE_WINDOW=30               # Ventana para cambios rápidos
readonly MAC_FLAP_THRESHOLD=5              # Umbral de flapping

# Alertas
readonly ALERT_COOLDOWN=300                # Cooldown entre alertas (5 min)
readonly MIN_ALERT_SEVERITY="MEDIUM"       # Severidad mínima
```

## Device Profiling Mode

El modo de perfilado genera fingerprints detallados de cada dispositivo en la red:

```bash
sudo ./l2_monitor.sh -i wlo1 -d 120 -P
```

### Información Generada por Dispositivo

Cada perfil incluye:

- **Estadísticas de tráfico**: Total paquetes, bytes, tamaño promedio
- **Ventana temporal**: Primera/última aparición, duración de actividad
- **Protocolos usados**: Distribución de protocolos Layer 2-7
- **Direcciones IP**: IPv4 e IPv6 asociadas al MAC
- **Puertos**: TCP/UDP origen y destino
- **Destinos principales**: Top 5 MACs de destino
- **Tipo estimado**: Clasificación automática del dispositivo
- **Análisis de comportamiento**:
  - Actividad (basado en duración > 60s)
  - Uso de encriptación (TLS)
  - Transmisiones broadcast/multicast
  - Paquetes por segundo

### Tipos de Dispositivos Detectados

- **Router/Gateway**: DHCP + broadcasts, o IGMP/ICMPv6 + multicast
- **DNS Server**: Tráfico en puerto 53
- **Web Server**: Puertos 80/443
- **Network Switch**: Protocolos STP/CDP/LLDP
- **IoT Device**: Bajo volumen de paquetes + broadcasts
- **Unknown**: No coincide con patrones conocidos

### Archivo Generado

**`device_profiles.json`** - JSON con array de perfiles

```json
[
  {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "total_packets": 150,
    "total_bytes": 45000,
    "protocols": {"ARP": 10, "DHCP": 5, "DNS": 135},
    "ipv4_addresses": ["192.168.1.100"],
    "estimated_type": "Router/Gateway",
    "behavior": {
      "is_active": true,
      "uses_encryption": false,
      "broadcasts": true
    }
  }
]
```

### Casos de Uso

- **Inventario de red**: Descubre todos los dispositivos activos
- **Análisis de tráfico**: Identifica patrones de comunicación
- **Clasificación automática**: Identifica función de cada dispositivo
- **Detección de anomalías**: Compara perfiles entre sesiones
- **Documentación de red**: Genera mapas automáticos

## Debug Mode

Para troubleshooting de problemas de captura o procesamiento, usa el modo debug:

```bash
sudo ./l2_monitor.sh -d 30 -D
```

El modo debug proporciona:
- Salida verbose en tiempo real con timestamps
- Validación de JSON en cada paso
- Inspección de campos tshark capturados
- Archivos de debug guardados en `./debug/`

### Archivos de Debug Generados

```
debug/
├── debug.log                    # Log completo de debug
├── tshark_raw_output.json       # Salida cruda de tshark
├── sample_packet.json           # Primer paquete capturado
├── protocol_breakdown.txt       # Conteo por protocolo
└── network_state_pretty.json    # Estado de red formateado
```

**Documentación completa**: Ver [DEBUG_MODE.md](DEBUG_MODE.md)

## Troubleshooting

### Error: "Herramientas faltantes"
```bash
# Instalar dependencias
sudo apt-get install tshark jq msmtp
```

### Error: "Permisos insuficientes"
```bash
# Ejecutar con sudo
sudo ./l2_monitor.sh

# O configurar capabilities
sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)
```

### No se capturan paquetes
```bash
# Verificar interfaces disponibles
ip link show

# Especificar interfaz manualmente
sudo ./l2_monitor.sh -i eth0

# Verificar que hay tráfico ARP
sudo tcpdump -i eth0 arp

# Usar modo debug para diagnóstico detallado
sudo ./l2_monitor.sh -i eth0 -d 30 -D
# Revisar debug/tshark_stderr.log y debug/protocol_breakdown.txt
```

### Alertas por email no funcionan
```bash
# Verificar configuración de msmtp
msmtp --version
cat ~/.msmtprc

# Probar envío manual
echo "test" | msmtp -a default tu-email@example.com
```

## Casos de Uso

### Seguridad Empresarial
- Monitoreo continuo de LANs corporativas
- Detección temprana de ataques internos
- Auditoría de seguridad de red

### Administración de Redes
- Diagnóstico de problemas de conectividad
- Identificación de dispositivos malconfigurados
- Mapeo de topología de red

### Educación y Laboratorios
- Demostraciones de ataques Layer 2
- Prácticas de seguridad ofensiva/defensiva
- Análisis forense de red

### Pentesting
- Validación de defensas Layer 2
- Pruebas de concepto de ataques ARP
- Reconocimiento pasivo de redes

## Limitaciones

- Requiere permisos elevados (root o capabilities)
- Solo detecta ataques ARP (Layer 2)
- No previene ataques, solo los detecta
- Puede generar falsos positivos en redes con DHCP agresivo
- El modo live consume recursos continuamente

## Mejoras Futuras

- Soporte para otros protocolos Layer 2 (CDP, LLDP, STP)
- Integración con SIEM (Syslog, Splunk)
- Dashboard web en tiempo real
- Base de datos histórica (SQLite)
- Machine Learning para detección de anomalías
- Respuesta automática a ataques (iptables rules)

## Licencia

Este proyecto es software educativo. Usar solo en redes autorizadas.

## Referencias

- [ARP Spoofing - Wikipedia](https://en.wikipedia.org/wiki/ARP_spoofing)
- [tshark Documentation](https://www.wireshark.org/docs/man-pages/tshark.html)
- [jq Manual](https://stedolan.github.io/jq/manual/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## Autor

Proyecto creado para Admin_redes - Universidad

---

**ADVERTENCIA**: Este software debe usarse únicamente en redes donde tienes autorización explícita. El uso no autorizado puede ser ilegal.
