#!/bin/bash

################################################################################
# Multi-Protocol Layer 2 Network Security Monitor
# Protocols: ARP, DHCP, STP, CDP, LLDP
# Detections: Spoofing, Flooding, Rogue Servers, Topology Attacks, Reconnaissance
################################################################################

set -euo pipefail

# ==================== CONFIGURACIÓN ====================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CAPTURE_FILE="${SCRIPT_DIR}/l2_capture.pcap"
readonly PROTOCOL_DATA="${SCRIPT_DIR}/protocol_data.json"
readonly STATE_FILE="${SCRIPT_DIR}/network_state.json"
readonly LOG_FILE="${SCRIPT_DIR}/l2_monitor.log"
readonly ALERT_LOG="${SCRIPT_DIR}/alerts.log"

# Protocolos a monitorear
readonly PROTOCOLS=("arp" "dhcp" "stp" "cdp" "lldp")
ENABLED_PROTOCOLS=("arp" "dhcp" "stp" "cdp" "lldp")  # Por defecto todos

# Configuración de detección
readonly TIME_WINDOW=60

# Umbrales por protocolo
readonly ARP_FLOOD_THRESHOLD=50
readonly DHCP_FLOOD_THRESHOLD=30
readonly STP_CHANGE_THRESHOLD=3
readonly CDP_SCAN_THRESHOLD=20
readonly MAC_FLAP_THRESHOLD=5
readonly IP_CHANGE_WINDOW=30
readonly MIN_CAPTURE_DURATION=30

# Configuración de alertas
DETECTED_EMAIL=$(grep -E "^from" /etc/msmtprc 2>/dev/null | awk '{print $2}' | head -n 1)
ALERT_EMAIL="${ALERT_EMAIL:-${DETECTED_EMAIL}}"
MSMTP_ACCOUNT="${MSMTP_ACCOUNT:-gmail}"
readonly ALERT_COOLDOWN=300
MIN_ALERT_SEVERITY="${MIN_ALERT_SEVERITY:-MEDIUM}"

# Colores
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# ==================== UTILIDADES ====================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

error() {
    log "ERROR" "$@" >&2
    exit 1
}

check_requirements() {
    local missing_tools=()
    local missing_optional=()

    for tool in tshark jq; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if ! command -v msmtp &> /dev/null; then
        missing_optional+=("msmtp (alertas por email)")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        error "Herramientas faltantes: ${missing_tools[*]}\nInstalar: sudo apt-get install tshark jq"
    fi

    if [ ${#missing_optional[@]} -gt 0 ]; then
        log "WARN" "Opcionales no disponibles: ${missing_optional[*]}"
    fi

    if ! tshark -D &> /dev/null; then
        error "Permisos insuficientes. Ejecutar con sudo o:\nsudo setcap cap_net_raw,cap_net_admin=eip \$(which tshark)"
    fi

    if command -v msmtp &> /dev/null && [ -f /etc/msmtprc ] && [ -n "$ALERT_EMAIL" ]; then
        log "INFO" "Alertas por email habilitadas → ${ALERT_EMAIL}"
    fi
}

get_interface() {
    local interface="${1:-}"
    if [ -z "$interface" ]; then
        # Try ip command first
        if command -v ip &> /dev/null; then
            interface=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -n 1)
        fi

        # Fallback: try to find first non-lo interface
        if [ -z "$interface" ] && [ -d /sys/class/net ]; then
            for iface in /sys/class/net/*; do
                iface_name=$(basename "$iface")
                if [ "$iface_name" != "lo" ]; then
                    interface="$iface_name"
                    break
                fi
            done
        fi

        [ -z "$interface" ] && error "No se pudo detectar interfaz de red. Usar -i para especificar manualmente."
    fi
    echo "$interface"
}

# ==================== CAPTURA MULTI-PROTOCOLO ====================

build_capture_filter() {
    local filters=()

    for proto in "${ENABLED_PROTOCOLS[@]}"; do
        case "$proto" in
            arp) filters+=("arp") ;;
            dhcp) filters+=("(udp port 67 or udp port 68)") ;;
            stp) filters+=("(ether proto 0x0026 or ether proto 0x0027)") ;;
            cdp) filters+=("(ether proto 0x2000)") ;;
            lldp) filters+=("(ether proto 0x88cc)") ;;
        esac
    done

    # Unir con OR - usar loop en lugar de IFS
    local filter=""
    for i in "${!filters[@]}"; do
        if [ $i -eq 0 ]; then
            filter="${filters[$i]}"
        else
            filter="${filter} or ${filters[$i]}"
        fi
    done
    echo "$filter"
}

capture_traffic() {
    local interface="$1"
    local duration="$2"

    local filter=$(build_capture_filter)

    log "INFO" "Capturando protocolos: ${ENABLED_PROTOCOLS[*]}"
    log "INFO" "Interfaz: ${interface} | Duración: ${duration}s"

    # Captura multi-protocolo
    log "INFO" "Filtro BPF: $filter"

    local tshark_error="${SCRIPT_DIR}/tshark_error.log"

    # Disable exit-on-error temporarily to handle timeout exit code 124
    set +e
    timeout "$duration" tshark -i "$interface" -f "$filter" \
        -T json \
        -e frame.time_epoch \
        -e frame.protocols \
        -e eth.src \
        -e eth.dst \
        -e arp.opcode \
        -e arp.src.hw_mac \
        -e arp.src.proto_ipv4 \
        -e arp.dst.hw_mac \
        -e arp.dst.proto_ipv4 \
        -e dhcp.option.dhcp \
        -e dhcp.option.dhcp_server_id \
        -e dhcp.option.requested_ip_address \
        -e dhcp.hw.mac_addr \
        -e dhcp.ip.client \
        -e dhcp.ip.your \
        -e stp.root.hw \
        -e stp.bridge.hw \
        -e stp.type \
        -e stp.flags \
        -e cdp.deviceid \
        -e cdp.platform \
        -e lldp.chassis.id \
        -e lldp.port.id \
        > "$PROTOCOL_DATA" 2>"$tshark_error"

    local exit_code=$?
    set -e  # Re-enable exit-on-error

    # Mostrar errores de tshark si existen
    if [ -s "$tshark_error" ]; then
        log "WARN" "Salida de tshark:"
        cat "$tshark_error" | head -10 | tee -a "${LOG_FILE}"
    fi
    rm -f "$tshark_error"

    # Timeout exitcode 124 es esperado y OK
    if [ $exit_code -ne 0 ] && [ $exit_code -ne 124 ]; then
        log "WARN" "tshark finalizó con código: $exit_code"
    fi

    if [ ! -s "$PROTOCOL_DATA" ]; then
        log "WARN" "No se capturaron paquetes. Verificar interfaz y tráfico."
        echo "[]" > "$PROTOCOL_DATA"
    else
        # Convert newline-delimited JSON to proper JSON array
        jq -s '.' "$PROTOCOL_DATA" > "${PROTOCOL_DATA}.tmp" 2>/dev/null || echo "[]" > "${PROTOCOL_DATA}.tmp"
        mv "${PROTOCOL_DATA}.tmp" "$PROTOCOL_DATA"
    fi

    local packet_count=$(jq '. | length' "$PROTOCOL_DATA" 2>/dev/null || echo "0")
    log "INFO" "Capturados ${packet_count} paquetes"
}

capture_live() {
    local interface="$1"
    local filter=$(build_capture_filter)

    log "INFO" "Modo LIVE: ${interface} | Protocolos: ${ENABLED_PROTOCOLS[*]}"
    log "INFO" "Presionar Ctrl+C para detener..."
    log "INFO" "Análisis automático cada 50 paquetes..."

    local packet_counter=0
    local analysis_interval=50

    tshark -i "$interface" -f "$filter" -T json \
        -e frame.time_epoch \
        -e frame.protocols \
        -e eth.src \
        -e eth.dst \
        -e arp.opcode \
        -e arp.src.hw_mac \
        -e arp.src.proto_ipv4 \
        -e dhcp.option.dhcp \
        -e dhcp.option.dhcp_server_id \
        -e dhcp.hw.mac_addr \
        -e stp.root.hw \
        -e stp.type \
        -e cdp.deviceid \
        -e lldp.chassis.id \
        2>/dev/null | while read -r line; do
        echo "$line" >> "${PROTOCOL_DATA}.tmp"

        packet_counter=$((packet_counter + 1))

        # Trigger analysis every N packets
        if [ $((packet_counter % analysis_interval)) -eq 0 ]; then
            mv "${PROTOCOL_DATA}.tmp" "$PROTOCOL_DATA" 2>/dev/null || true
            if [ -s "$PROTOCOL_DATA" ]; then
                log "INFO" "Analizando ${packet_counter} paquetes capturados..."
                analyze_traffic && echo ""
            fi
        fi
    done
}

# ==================== MOTOR DE ANÁLISIS ====================

analyze_traffic() {
    [ ! -s "$PROTOCOL_DATA" ] && log "WARN" "No hay datos para analizar" && return

    log "INFO" "Analizando tráfico multi-protocolo..."

    # Generar estado por protocolo
    generate_network_state

    # Ejecutar detecciones
    detect_arp_attacks
    detect_dhcp_attacks
    detect_stp_attacks
    detect_discovery_recon

    # Generar reporte
    generate_report
}

generate_network_state() {
    jq -r '
        # Clasificar paquetes por protocolo
        # Handle both _source.layers and direct field access
        map(
            if has("_source") then ._source.layers else . end |
            {
                timestamp: (.["frame.time_epoch"][0] // .["frame.time_epoch"] // "0" | tonumber),
                protocols: (.["frame.protocols"][0] // .["frame.protocols"] // ""),
                eth_src: (.["eth.src"][0] // .["eth.src"] // ""),
                eth_dst: (.["eth.dst"][0] // .["eth.dst"] // ""),

                # ARP
                arp_opcode: (.["arp.opcode"][0] // .["arp.opcode"] // null),
                arp_src_mac: (.["arp.src.hw_mac"][0] // .["arp.src.hw_mac"] // null),
                arp_src_ip: (.["arp.src.proto_ipv4"][0] // .["arp.src.proto_ipv4"] // null),
                arp_dst_mac: (.["arp.dst.hw_mac"][0] // .["arp.dst.hw_mac"] // null),
                arp_dst_ip: (.["arp.dst.proto_ipv4"][0] // .["arp.dst.proto_ipv4"] // null),

                # DHCP
                dhcp_type: (.["dhcp.option.dhcp"][0] // .["dhcp.option.dhcp"] // null),
                dhcp_server: (.["dhcp.option.dhcp_server_id"][0] // .["dhcp.option.dhcp_server_id"] // null),
                dhcp_client_mac: (.["dhcp.hw.mac_addr"][0] // .["dhcp.hw.mac_addr"] // null),
                dhcp_client_ip: (.["dhcp.ip.client"][0] // .["dhcp.ip.client"] // null),
                dhcp_your_ip: (.["dhcp.ip.your"][0] // .["dhcp.ip.your"] // null),

                # STP
                stp_root: (.["stp.root.hw"][0] // .["stp.root.hw"] // null),
                stp_bridge: (.["stp.bridge.hw"][0] // .["stp.bridge.hw"] // null),
                stp_type: (.["stp.type"][0] // .["stp.type"] // null),

                # CDP
                cdp_device: (.["cdp.deviceid"][0] // .["cdp.deviceid"] // null),
                cdp_platform: (.["cdp.platform"][0] // .["cdp.platform"] // null),

                # LLDP
                lldp_chassis: (.["lldp.chassis.id"][0] // .["lldp.chassis.id"] // null),
                lldp_port: (.["lldp.port.id"][0] // .["lldp.port.id"] // null)
            }
        ) |

        # Estadísticas por protocolo
        {
            arp_packets: map(select(.arp_opcode != null)),
            dhcp_packets: map(select(.dhcp_type != null)),
            stp_packets: map(select(.stp_type != null)),
            cdp_packets: map(select(.cdp_device != null)),
            lldp_packets: map(select(.lldp_chassis != null)),

            # Mapeo IP-MAC (ARP)
            arp_table: (
                map(select(.arp_src_ip != null and .arp_src_mac != null)) |
                group_by(.arp_src_ip) |
                map({
                    ip: .[0].arp_src_ip,
                    macs: [.[].arp_src_mac] | unique,
                    mac_count: ([.[].arp_src_mac] | unique | length),
                    first_seen: (map(.timestamp) | min),
                    last_seen: (map(.timestamp) | max),
                    packet_count: length
                })
            ),

            # Servidores DHCP
            dhcp_servers: (
                map(select(.dhcp_server != null)) |
                group_by(.dhcp_server) |
                map({
                    server_ip: .[0].dhcp_server,
                    mac: .[0].eth_src,
                    offer_count: length,
                    first_seen: (map(.timestamp) | min),
                    last_seen: (map(.timestamp) | max)
                })
            ),

            # Root bridges STP
            stp_roots: (
                map(select(.stp_root != null)) |
                group_by(.stp_root) |
                map({
                    root_mac: .[0].stp_root,
                    changes: length,
                    first_seen: (map(.timestamp) | min),
                    last_seen: (map(.timestamp) | max)
                })
            ),

            # Dispositivos CDP/LLDP
            discovered_devices: (
                (map(select(.cdp_device != null)) | map({device: .cdp_device, mac: .eth_src, protocol: "CDP"})) +
                (map(select(.lldp_chassis != null)) | map({device: .lldp_chassis, mac: .eth_src, protocol: "LLDP"})) |
                unique_by(.mac)
            )
        }
    ' "$PROTOCOL_DATA" > "$STATE_FILE"
}

# ==================== DETECCIÓN ARP ====================

detect_arp_attacks() {
    log "INFO" "Ejecutando detección ARP..."

    # MAC Duplicate (IP con múltiples MACs)
    local alerts=$(jq -r '
        .arp_table |
        map(select(.mac_count > 1)) |
        map({
            severity: "CRITICAL",
            protocol: "ARP",
            rule: "MAC_DUPLICATE",
            description: "Clonación de MAC address / ARP Spoofing",
            ip: .ip,
            macs: .macs,
            confidence: ((.mac_count - 1) * 50 | if . > 100 then 100 else . end),
            details: "IP \(.ip) responde desde \(.mac_count) MACs diferentes: \(.macs | join(", "))"
        }) | .[]
    ' "$STATE_FILE")

    if [ -n "$alerts" ]; then
        echo "$alerts" | while IFS= read -r alert; do
            trigger_alert "$alert"
        done
    fi

    # ARP Flooding
    alerts=$(jq -r --argjson threshold "$ARP_FLOOD_THRESHOLD" '
        .arp_table |
        map(select(.packet_count > $threshold)) |
        map({
            severity: "HIGH",
            protocol: "ARP",
            rule: "ARP_FLOOD",
            description: "Tasa anormal de paquetes ARP",
            ip: .ip,
            packet_count: .packet_count,
            confidence: (if .packet_count > ($threshold * 2) then 95 else 75 end),
            details: "IP \(.ip) generó \(.packet_count) paquetes ARP"
        }) | .[]
    ' "$STATE_FILE")

    if [ -n "$alerts" ]; then
        echo "$alerts" | while IFS= read -r alert; do
            trigger_alert "$alert"
        done
    fi
}

# ==================== DETECCIÓN DHCP ====================

detect_dhcp_attacks() {
    log "INFO" "Ejecutando detección DHCP..."

    # Múltiples servidores DHCP (Rogue DHCP)
    local server_count=$(jq '.dhcp_servers | length' "$STATE_FILE")

    if [ "$server_count" -gt 1 ]; then
        local alerts=$(jq -r '
            .dhcp_servers |
            map({
                severity: "CRITICAL",
                protocol: "DHCP",
                rule: "ROGUE_DHCP",
                description: "Múltiples servidores DHCP detectados (Rogue DHCP Server)",
                server_ip: .server_ip,
                server_mac: .mac,
                offer_count: .offer_count,
                confidence: 95,
                details: "Servidor DHCP no autorizado: \(.server_ip) (MAC: \(.mac)) - \(.offer_count) ofertas"
            }) | .[]
        ' "$STATE_FILE")

        if [ -n "$alerts" ]; then
            echo "$alerts" | while IFS= read -r alert; do
                trigger_alert "$alert"
            done
        fi
    fi

    # DHCP Starvation
    local dhcp_count=$(jq '[.dhcp_packets[] | select(.dhcp_type == "1")] | length' "$STATE_FILE" 2>/dev/null || echo "0")

    if [ "$dhcp_count" -gt "$DHCP_FLOOD_THRESHOLD" ]; then
        local alert=$(jq -n \
            --arg count "$dhcp_count" \
            --arg threshold "$DHCP_FLOOD_THRESHOLD" \
            '{
                severity: "HIGH",
                protocol: "DHCP",
                rule: "DHCP_STARVATION",
                description: "Ataque de agotamiento DHCP detectado",
                request_count: ($count | tonumber),
                confidence: 85,
                details: "Se detectaron \($count) peticiones DHCP (umbral: \($threshold))"
            }')

        trigger_alert "$alert"
    fi
}

# ==================== DETECCIÓN STP ====================

detect_stp_attacks() {
    log "INFO" "Ejecutando detección STP..."

    # Cambios de root bridge
    local root_count=$(jq '.stp_roots | length' "$STATE_FILE")

    if [ "$root_count" -gt "$STP_CHANGE_THRESHOLD" ]; then
        local alerts=$(jq -r --argjson threshold "$STP_CHANGE_THRESHOLD" '
            .stp_roots |
            map({
                severity: "HIGH",
                protocol: "STP",
                rule: "STP_MANIPULATION",
                description: "Cambios anormales en topología STP",
                root_mac: .root_mac,
                changes: .changes,
                confidence: 80,
                details: "Root bridge \(.root_mac) con \(.changes) cambios detectados"
            }) | .[]
        ' "$STATE_FILE")

        if [ -n "$alerts" ]; then
            echo "$alerts" | while IFS= read -r alert; do
                trigger_alert "$alert"
            done
        fi
    fi
}

# ==================== DETECCIÓN RECONNAISSANCE ====================

detect_discovery_recon() {
    log "INFO" "Ejecutando detección de reconocimiento..."

    # Escaneo CDP/LLDP
    local device_count=$(jq '.discovered_devices | length' "$STATE_FILE")

    if [ "$device_count" -gt "$CDP_SCAN_THRESHOLD" ]; then
        local alert=$(jq -n \
            --arg count "$device_count" \
            '{
                severity: "MEDIUM",
                protocol: "CDP/LLDP",
                rule: "DISCOVERY_SCAN",
                description: "Reconocimiento de red mediante protocolos de descubrimiento",
                device_count: ($count | tonumber),
                confidence: 70,
                details: "Se detectaron \($count) dispositivos mediante CDP/LLDP (posible reconocimiento)"
            }')

        trigger_alert "$alert"
    fi
}

# ==================== SISTEMA DE ALERTAS ====================

trigger_alert() {
    local alert_json="$1"

    # Validate JSON input
    if [ -z "$alert_json" ]; then
        log "WARN" "trigger_alert: empty alert_json"
        return
    fi

    local severity=$(echo "$alert_json" | jq -r '.severity // empty' 2>/dev/null)
    local rule=$(echo "$alert_json" | jq -r '.rule // empty' 2>/dev/null)

    check_severity_threshold "$severity" || return
    check_alert_cooldown "$rule" || return

    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} | ${severity} | ${rule} | ${alert_json}" >> "$ALERT_LOG"

    display_alert "$alert_json"

    if command -v msmtp &> /dev/null && [ -f /etc/msmtprc ] && [ -n "$ALERT_EMAIL" ]; then
        send_email_alert "$alert_json"
    fi
}

check_severity_threshold() {
    local severity="$1"
    local min_level="$MIN_ALERT_SEVERITY"

    # Validate input
    if [ -z "$severity" ]; then
        log "WARN" "check_severity_threshold: severity is empty"
        return 1
    fi

    declare -A severity_levels=([CRITICAL]=3 [HIGH]=2 [MEDIUM]=1)

    local current_level=${severity_levels[$severity]:-0}
    local min_threshold=${severity_levels[$min_level]:-0}

    [ "$current_level" -ge "$min_threshold" ]
}

check_alert_cooldown() {
    local rule="$1"
    local cooldown_file="${SCRIPT_DIR}/.cooldown_${rule}"

    if [ -f "$cooldown_file" ]; then
        local last_alert=$(cat "$cooldown_file")
        local now=$(date +%s)
        local elapsed=$((now - last_alert))

        [ "$elapsed" -lt "$ALERT_COOLDOWN" ] && return 1
    fi

    date +%s > "$cooldown_file"
    return 0
}

display_alert() {
    local alert_json="$1"

    local severity=$(echo "$alert_json" | jq -r '.severity')
    local protocol=$(echo "$alert_json" | jq -r '.protocol')
    local rule=$(echo "$alert_json" | jq -r '.rule')
    local description=$(echo "$alert_json" | jq -r '.description')
    local details=$(echo "$alert_json" | jq -r '.details')
    local confidence=$(echo "$alert_json" | jq -r '.confidence')

    local color="$NC"
    case "$severity" in
        CRITICAL) color="$RED" ;;
        HIGH) color="$YELLOW" ;;
        MEDIUM) color="$CYAN" ;;
    esac

    echo -e "\n${color}${BOLD}⚠ ALERTA [${protocol}]: ${rule}${NC}"
    echo -e "${color}Severidad: ${severity} | Confianza: ${confidence}%${NC}"
    echo -e "${color}${description}${NC}"
    echo -e "${color}${details}${NC}"
}

send_email_alert() {
    local alert_json="$1"

    local severity=$(echo "$alert_json" | jq -r '.severity')
    local protocol=$(echo "$alert_json" | jq -r '.protocol')
    local rule=$(echo "$alert_json" | jq -r '.rule')
    local description=$(echo "$alert_json" | jq -r '.description')
    local details=$(echo "$alert_json" | jq -r '.details')

    local subject="[L2 Security/${protocol}] ${severity}: ${rule}"

    local html_body=$(cat <<EOF
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .alert { border-left: 5px solid #f44336; padding: 15px; background: #ffebee; }
        .alert.high { border-color: #ff9800; background: #fff3e0; }
        .alert.medium { border-color: #2196F3; background: #e3f2fd; }
        .header { font-size: 24px; font-weight: bold; margin-bottom: 10px; }
        .protocol { display: inline-block; background: #9c27b0; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }
        .details { margin-top: 15px; padding: 10px; background: #f5f5f5; }
        .timestamp { color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="alert $(echo $severity | tr '[:upper:]' '[:lower:]')">
        <div class="header">🚨 ${rule}</div>
        <span class="protocol">${protocol}</span>
        <div class="timestamp">$(date '+%Y-%m-%d %H:%M:%S')</div>
        <p><strong>${description}</strong></p>
        <div class="details">${details}</div>
        <p><em>Multi-Protocol Layer 2 Security Monitor</em></p>
    </div>
</body>
</html>
EOF
)

    command -v msmtp &> /dev/null || { log "WARN" "msmtp no disponible"; return 0; }

    (
        echo "To: ${ALERT_EMAIL}"
        echo "From: ${ALERT_EMAIL}"
        echo "Subject: ${subject}"
        echo "Content-Type: text/html; charset=UTF-8"
        echo ""
        echo "$html_body"
    ) | msmtp -a "${MSMTP_ACCOUNT}" "${ALERT_EMAIL}" 2>&1 | \
        tee -a "${LOG_FILE}" || log "WARN" "Error enviando email"
}

# ==================== REPORTING ====================

generate_report() {
    echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}   MULTI-PROTOCOL LAYER 2 SECURITY REPORT${NC}"
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════${NC}"

    # Estadísticas por protocolo
    local arp_count=$(jq '.arp_packets | length' "$STATE_FILE")
    local dhcp_count=$(jq '.dhcp_packets | length' "$STATE_FILE")
    local stp_count=$(jq '.stp_packets | length' "$STATE_FILE")
    local cdp_count=$(jq '.cdp_packets | length' "$STATE_FILE")
    local lldp_count=$(jq '.lldp_packets | length' "$STATE_FILE")

    echo -e "\n${BOLD}📊 Paquetes Capturados por Protocolo:${NC}"
    echo -e "  • ${MAGENTA}ARP:${NC}    ${GREEN}${arp_count}${NC} paquetes"
    echo -e "  • ${MAGENTA}DHCP:${NC}   ${GREEN}${dhcp_count}${NC} paquetes"
    echo -e "  • ${MAGENTA}STP:${NC}    ${GREEN}${stp_count}${NC} paquetes"
    echo -e "  • ${MAGENTA}CDP:${NC}    ${GREEN}${cdp_count}${NC} paquetes"
    echo -e "  • ${MAGENTA}LLDP:${NC}   ${GREEN}${lldp_count}${NC} paquetes"

    # Tabla ARP
    if [ "$arp_count" -gt 0 ]; then
        echo -e "\n${BOLD}🗺️  Mapeo ARP (IP → MAC):${NC}"
        jq -r '
            .arp_table |
            sort_by(.ip) |
            .[] |
            if .mac_count > 1 then
                "  ⚠️  \(.ip) → \(.macs | join(", ")) [MÚLTIPLES MACs - SOSPECHOSO]"
            else
                "  ✓  \(.ip) → \(.macs[0])"
            end
        ' "$STATE_FILE"
    fi

    # Servidores DHCP
    if [ "$dhcp_count" -gt 0 ]; then
        echo -e "\n${BOLD}🌐 Servidores DHCP Detectados:${NC}"
        local dhcp_server_count=$(jq '.dhcp_servers | length' "$STATE_FILE")

        if [ "$dhcp_server_count" -eq 0 ]; then
            echo -e "  ${CYAN}No se detectaron servidores DHCP activos${NC}"
        else
            jq -r '
                .dhcp_servers |
                .[] |
                "  • Servidor: \(.server_ip) (MAC: \(.mac)) - \(.offer_count) ofertas"
            ' "$STATE_FILE"

            if [ "$dhcp_server_count" -gt 1 ]; then
                echo -e "  ${RED}⚠️  ADVERTENCIA: Múltiples servidores DHCP detectados${NC}"
            fi
        fi
    fi

    # Topología STP
    if [ "$stp_count" -gt 0 ]; then
        echo -e "\n${BOLD}🌳 Topología STP:${NC}"
        jq -r '
            .stp_roots |
            .[] |
            "  • Root Bridge: \(.root_mac) (visto \(.changes) veces)"
        ' "$STATE_FILE"
    fi

    # Dispositivos descubiertos
    local device_count=$(jq '.discovered_devices | length' "$STATE_FILE")
    if [ "$device_count" -gt 0 ]; then
        echo -e "\n${BOLD}🔍 Dispositivos Descubiertos (CDP/LLDP):${NC}"
        jq -r '
            .discovered_devices |
            .[] |
            "  • [\(.protocol)] \(.device) - MAC: \(.mac)"
        ' "$STATE_FILE" | head -20

        if [ "$device_count" -gt 20 ]; then
            echo -e "  ${CYAN}... y $((device_count - 20)) más${NC}"
        fi
    fi

    echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════${NC}\n"
}

# ==================== CLI ====================

show_usage() {
    cat <<EOF
${BOLD}Multi-Protocol Layer 2 Network Security Monitor${NC}

${BOLD}USO:${NC}
    $0 [OPCIONES]

${BOLD}OPCIONES:${NC}
    -i, --interface IFACE      Interfaz de red (autodetecta si se omite)
    -d, --duration SECONDS     Duración de captura (default: ${MIN_CAPTURE_DURATION})
    -l, --live                 Modo análisis continuo en tiempo real
    -p, --protocols PROTO,...  Protocolos a monitorear (default: todos)
                               Valores: arp,dhcp,stp,cdp,lldp
    -a, --alert EMAIL          Email para alertas (opcional, requiere msmtp configurado)
    -s, --severity LEVEL       Severidad mínima: CRITICAL|HIGH|MEDIUM (default: ${MIN_ALERT_SEVERITY})
    -h, --help                 Mostrar esta ayuda

${BOLD}EJEMPLOS:${NC}
    # Monitoreo completo de 60 segundos
    sudo $0 -d 60

    # Solo ARP y DHCP en modo live
    sudo $0 -i eth0 -l -p arp,dhcp

    # Solo alertas críticas
    sudo $0 -s CRITICAL -a security@empresa.com

${BOLD}PROTOCOLOS MONITOREADOS:${NC}
    ${MAGENTA}ARP${NC}     - Spoofing, flooding, MAC duplication, IP conflicts
    ${MAGENTA}DHCP${NC}    - Rogue servers, starvation attacks
    ${MAGENTA}STP${NC}     - Root bridge changes, topology manipulation
    ${MAGENTA}CDP${NC}     - Device discovery reconnaissance
    ${MAGENTA}LLDP${NC}    - Device discovery reconnaissance

${BOLD}REGLAS DE DETECCIÓN:${NC}
    • MAC_DUPLICATE (CRITICAL)      - Clonación de MAC / ARP Spoofing
    • ARP_FLOOD (HIGH)              - Flooding de paquetes ARP
    • ROGUE_DHCP (CRITICAL)         - Servidor DHCP no autorizado
    • DHCP_STARVATION (HIGH)        - Agotamiento de pool DHCP
    • STP_MANIPULATION (HIGH)       - Manipulación de topología STP
    • DISCOVERY_SCAN (MEDIUM)       - Reconocimiento vía CDP/LLDP

${BOLD}REQUISITOS:${NC}
    • tshark, jq
    • msmtp (opcional, para alertas)
    • Permisos root o CAP_NET_RAW

EOF
}

# ==================== MAIN ====================

main() {
    local interface=""
    local duration="$MIN_CAPTURE_DURATION"
    local mode="capture"

    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface)
                interface="$2"
                shift 2
                ;;
            -d|--duration)
                duration="$2"
                shift 2
                ;;
            -l|--live)
                mode="live"
                shift
                ;;
            -p|--protocols)
                IFS=',' read -ra ENABLED_PROTOCOLS <<< "$2"
                shift 2
                ;;
            -a|--alert)
                ALERT_EMAIL="$2"
                shift 2
                ;;
            -s|--severity)
                MIN_ALERT_SEVERITY="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                error "Opción desconocida: $1\nUsar -h para ayuda"
                ;;
        esac
    done

    # Banner
    echo -e "${BOLD}${CYAN}"
    cat <<'EOF'
╔═══════════════════════════════════════════════════════╗
║   Multi-Protocol Layer 2 Security Monitor             ║
║   ARP | DHCP | STP | CDP | LLDP                       ║
╚═══════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    check_requirements
    interface=$(get_interface "$interface")
    log "INFO" "Interfaz: ${interface}"

    rm -f "${SCRIPT_DIR}/.cooldown_"*

    if [ "$mode" = "live" ]; then
        capture_live "$interface"
    else
        capture_traffic "$interface" "$duration"
        analyze_traffic
    fi

    log "INFO" "Análisis completado. Logs: ${LOG_FILE}"
}

cleanup() {
    log "INFO" "Deteniendo monitoreo..."
    rm -f "$PROTOCOL_DATA" "${PROTOCOL_DATA}.tmp"
    exit 0
}

trap cleanup SIGINT SIGTERM

main "$@"
