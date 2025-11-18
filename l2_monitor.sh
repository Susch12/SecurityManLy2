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
DETECTED_EMAIL=$(grep -E "^from" /etc/msmtprc 2>/dev/null | awk '{print $2}' | head -n 1 || true)
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

# Debug mode
DEBUG_MODE=false
readonly DEBUG_DIR="${SCRIPT_DIR}/debug"

# Device profiling
PROFILE_MODE=false
readonly PROFILE_FILE="${SCRIPT_DIR}/device_profiles.json"

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

# ==================== DEBUG FUNCTIONS ====================

debug() {
    if [ "$DEBUG_MODE" = true ]; then
        local level="${1:-DEBUG}"
        shift
        local message="$*"
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
        echo -e "${CYAN}[${timestamp}] [${level}] ${message}${NC}" | tee -a "${DEBUG_DIR}/debug.log"
    fi
}

setup_debug_mode() {
    if [ "$DEBUG_MODE" = true ]; then
        mkdir -p "$DEBUG_DIR"
        local session_id=$(date '+%Y%m%d_%H%M%S')

        log "INFO" "Debug mode ENABLED - Output: ${DEBUG_DIR}/"
        debug "DEBUG" "Session ID: ${session_id}"
        debug "DEBUG" "Working directory: ${SCRIPT_DIR}"
        debug "DEBUG" "Enabled protocols: ${ENABLED_PROTOCOLS[*]}"

        # Create debug session file
        cat > "${DEBUG_DIR}/session_info.txt" <<EOF
Debug Session: ${session_id}
Timestamp: $(date)
Working Dir: ${SCRIPT_DIR}
Enabled Protocols: ${ENABLED_PROTOCOLS[*]}
Min Severity: ${MIN_ALERT_SEVERITY}
EOF
    fi
}

validate_json() {
    local file="$1"
    local label="${2:-JSON}"

    debug "DEBUG" "Validating ${label}: ${file}"

    if [ ! -f "$file" ]; then
        debug "ERROR" "${label} file not found: ${file}"
        return 1
    fi

    if [ ! -s "$file" ]; then
        debug "WARN" "${label} file is empty: ${file}"
        return 1
    fi

    # Validate JSON syntax
    local error_log="/dev/null"
    if [ "$DEBUG_MODE" = true ]; then
        mkdir -p "$DEBUG_DIR"
        error_log="${DEBUG_DIR}/jq_error.log"
    fi

    if ! jq empty "$file" 2>"$error_log"; then
        debug "ERROR" "${label} is not valid JSON"
        if [ "$DEBUG_MODE" = true ] && [ -f "$error_log" ]; then
            debug "ERROR" "jq error output:"
            cat "$error_log" | head -20 | while IFS= read -r line; do
                debug "ERROR" "  $line"
            done
        fi
        return 1
    fi

    local element_count=$(jq '. | length' "$file" 2>/dev/null || echo "0")
    debug "INFO" "${label} validated: ${element_count} elements"

    if [ "$DEBUG_MODE" = true ] && [ "$element_count" -gt 0 ]; then
        # Show sample of first element
        debug "DEBUG" "Sample element from ${label}:"
        jq '.[0] // . | to_entries | map("\(.key): \(.value)") | .[]' "$file" 2>/dev/null | head -10 | while IFS= read -r line; do
            debug "DEBUG" "  $line"
        done
    fi

    return 0
}

debug_tshark_fields() {
    local file="$1"

    debug "DEBUG" "=== TSHARK FIELD INSPECTION ==="

    if [ ! -s "$file" ]; then
        debug "ERROR" "No data to inspect"
        return 1
    fi

    # Analyze available fields in first 5 packets
    debug "DEBUG" "Extracting field names from first packet..."
    jq -r '
        .[0] |
        if type == "object" and has("_source") then ._source.layers
        elif type == "object" then .
        else empty
        end |
        if type == "object" then
            keys | .[]
        else
            empty
        end
    ' "$file" 2>/dev/null | sort | while IFS= read -r field; do
        debug "DEBUG" "  Available field: ${field}"
    done

    # Count packets by protocol
    debug "DEBUG" "Packet distribution:"
    jq -r '
        # Normalize and extract protocols
        map(
            if type == "object" and has("_source") then ._source.layers["frame.protocols"][0]
            elif type == "object" then .["frame.protocols"][0]
            else "unknown"
            end
        ) |
        group_by(.) |
        map({
            protocol: .[0],
            count: length
        }) |
        .[] |
        "  \(.protocol): \(.count) packets"
    ' "$file" 2>/dev/null | while IFS= read -r line; do
        debug "DEBUG" "$line"
    done

    # Save full sample packet
    if [ "$DEBUG_MODE" = true ]; then
        jq '.[0]' "$file" > "${DEBUG_DIR}/sample_packet.json" 2>/dev/null
        debug "DEBUG" "Full sample packet saved to: ${DEBUG_DIR}/sample_packet.json"
    fi
}

debug_jq_query() {
    local input_file="$1"
    local query="$2"
    local description="$3"

    debug "DEBUG" "=== JQ QUERY DEBUG: ${description} ==="
    debug "DEBUG" "Input file: ${input_file}"
    debug "DEBUG" "Query: ${query}"

    local output_file="${DEBUG_DIR}/jq_output_$(date +%s).json"
    local error_file="${DEBUG_DIR}/jq_error_$(date +%s).log"

    # Execute query with error capture
    if jq -r "$query" "$input_file" > "$output_file" 2>"$error_file"; then
        local result_count=$(wc -l < "$output_file")
        debug "INFO" "Query successful: ${result_count} result lines"

        # Show first few results
        if [ "$result_count" -gt 0 ]; then
            debug "DEBUG" "First 5 results:"
            head -5 "$output_file" | while IFS= read -r line; do
                debug "DEBUG" "  $line"
            done
        fi
    else
        debug "ERROR" "Query failed!"
        debug "ERROR" "Error output:"
        cat "$error_file" | while IFS= read -r line; do
            debug "ERROR" "  $line"
        done
        return 1
    fi

    rm -f "$error_file"
}

debug_protocol_extraction() {
    local file="$1"

    debug "DEBUG" "=== PROTOCOL EXTRACTION DEBUG ==="

    # Test ARP extraction
    debug "DEBUG" "Testing ARP packet extraction..."
    local arp_count=$(jq '[.[] | select(type == "object") | select(._source.layers["arp.opcode"] != null or .["arp.opcode"] != null)] | length' "$file" 2>/dev/null || echo "0")
    debug "INFO" "Found ${arp_count} ARP packets"

    # Test DHCP extraction
    debug "DEBUG" "Testing DHCP packet extraction..."
    local dhcp_count=$(jq '[.[] | select(type == "object") | select(._source.layers["dhcp.option.dhcp"] != null or .["dhcp.option.dhcp"] != null)] | length' "$file" 2>/dev/null || echo "0")
    debug "INFO" "Found ${dhcp_count} DHCP packets"

    # Test STP extraction
    debug "DEBUG" "Testing STP packet extraction..."
    local stp_count=$(jq '[.[] | select(type == "object") | select(._source.layers["stp.type"] != null or .["stp.type"] != null)] | length' "$file" 2>/dev/null || echo "0")
    debug "INFO" "Found ${stp_count} STP packets"

    # Test CDP extraction
    debug "DEBUG" "Testing CDP packet extraction..."
    local cdp_count=$(jq '[.[] | select(type == "object") | select(._source.layers["cdp.deviceid"] != null or .["cdp.deviceid"] != null)] | length' "$file" 2>/dev/null || echo "0")
    debug "INFO" "Found ${cdp_count} CDP packets"

    # Test LLDP extraction
    debug "DEBUG" "Testing LLDP packet extraction..."
    local lldp_count=$(jq '[.[] | select(type == "object") | select(._source.layers["lldp.chassis.id"] != null or .["lldp.chassis.id"] != null)] | length' "$file" 2>/dev/null || echo "0")
    debug "INFO" "Found ${lldp_count} LLDP packets"

    # Save protocol breakdown
    cat > "${DEBUG_DIR}/protocol_breakdown.txt" <<EOF
Protocol Extraction Results
===========================
ARP packets:   ${arp_count}
DHCP packets:  ${dhcp_count}
STP packets:   ${stp_count}
CDP packets:   ${cdp_count}
LLDP packets:  ${lldp_count}
Total packets: $(jq '. | length' "$file" 2>/dev/null || echo "0")
EOF

    debug "INFO" "Protocol breakdown saved to: ${DEBUG_DIR}/protocol_breakdown.txt"
}

debug_capture_summary() {
    debug "DEBUG" "=== CAPTURE SUMMARY ==="

    if [ -f "$PROTOCOL_DATA" ]; then
        validate_json "$PROTOCOL_DATA" "Protocol Data"
        debug_tshark_fields "$PROTOCOL_DATA"
        debug_protocol_extraction "$PROTOCOL_DATA"
    fi

    if [ -f "$STATE_FILE" ]; then
        validate_json "$STATE_FILE" "Network State"

        # Show state file structure
        debug "DEBUG" "Network state structure:"
        jq 'keys' "$STATE_FILE" 2>/dev/null | while IFS= read -r line; do
            debug "DEBUG" "  $line"
        done
    fi
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

    debug "DEBUG" "=== STARTING PACKET CAPTURE ==="
    debug "DEBUG" "Interface: ${interface}"
    debug "DEBUG" "Duration: ${duration}s"
    debug "DEBUG" "BPF Filter: ${filter}"
    debug "DEBUG" "Output file: ${PROTOCOL_DATA}"

    local tshark_error="${SCRIPT_DIR}/tshark_error.log"

    # Copy tshark error to debug dir in debug mode
    if [ "$DEBUG_MODE" = true ]; then
        mkdir -p "$DEBUG_DIR"
    fi

    # Disable exit-on-error temporarily to handle timeout exit code 124
    set +e

    # Base fields for all modes
    local tshark_fields=(
        -e frame.time_epoch
        -e frame.protocols
        -e eth.src
        -e eth.dst
        -e arp.opcode
        -e arp.src.hw_mac
        -e arp.src.proto_ipv4
        -e arp.dst.hw_mac
        -e arp.dst.proto_ipv4
        -e dhcp.option.dhcp
        -e dhcp.option.dhcp_server_id
        -e dhcp.option.requested_ip_address
        -e dhcp.hw.mac_addr
        -e dhcp.ip.client
        -e dhcp.ip.your
        -e stp.root.hw
        -e stp.bridge.hw
        -e stp.type
        -e stp.flags
        -e cdp.deviceid
        -e cdp.platform
        -e lldp.chassis.id
        -e lldp.port.id
    )

    # Additional fields for device profiling
    if [ "$PROFILE_MODE" = true ]; then
        tshark_fields+=(
            -e frame.len
            -e ip.src
            -e ip.dst
            -e ipv6.src
            -e ipv6.dst
            -e tcp.srcport
            -e tcp.dstport
            -e udp.srcport
            -e udp.dstport
            -e tcp.flags
            -e http.request.method
            -e dns.qry.name
            -e tls.handshake.type
        )
        debug "DEBUG" "Profile mode enabled - capturing extended fields"
    fi

    timeout "$duration" tshark -i "$interface" -f "$filter" \
        -T json \
        "${tshark_fields[@]}" \
        > "$PROTOCOL_DATA" 2>"$tshark_error"

    local exit_code=$?
    set -e  # Re-enable exit-on-error

    debug "DEBUG" "tshark exit code: ${exit_code}"

    # Mostrar errores de tshark si existen
    if [ -s "$tshark_error" ]; then
        log "WARN" "Salida de tshark:"
        cat "$tshark_error" | head -10 | tee -a "${LOG_FILE}"

        if [ "$DEBUG_MODE" = true ]; then
            cp "$tshark_error" "${DEBUG_DIR}/tshark_stderr.log"
            debug "DEBUG" "tshark errors copied to: ${DEBUG_DIR}/tshark_stderr.log"
        fi
    fi
    rm -f "$tshark_error"

    # Timeout exitcode 124 es esperado y OK
    if [ $exit_code -ne 0 ] && [ $exit_code -ne 124 ]; then
        log "WARN" "tshark finalizó con código: $exit_code"
    fi

    debug "DEBUG" "Raw capture file size: $(wc -c < "$PROTOCOL_DATA" 2>/dev/null || echo 0) bytes"

    if [ ! -s "$PROTOCOL_DATA" ]; then
        log "WARN" "No se capturaron paquetes. Verificar interfaz y tráfico."
        echo "[]" > "$PROTOCOL_DATA"
        debug "WARN" "Empty capture - created empty JSON array"
    else
        # Save raw output in debug mode
        if [ "$DEBUG_MODE" = true ]; then
            cp "$PROTOCOL_DATA" "${DEBUG_DIR}/tshark_raw_output.json"
            debug "DEBUG" "Raw tshark output saved to: ${DEBUG_DIR}/tshark_raw_output.json"
        fi

        # Detect if tshark output is already a JSON array or newline-delimited
        local first_char=$(head -c 1 "$PROTOCOL_DATA" 2>/dev/null)

        if [ "$first_char" = "[" ]; then
            # Already a valid JSON array - just validate and prettify
            debug "DEBUG" "Detected JSON array format (modern tshark)"
            jq '.' "$PROTOCOL_DATA" > "${PROTOCOL_DATA}.tmp" 2>/dev/null || echo "[]" > "${PROTOCOL_DATA}.tmp"
        else
            # Newline-delimited JSON - convert to array
            debug "DEBUG" "Detected NDJSON format - converting to array..."
            jq -s '.' "$PROTOCOL_DATA" > "${PROTOCOL_DATA}.tmp" 2>/dev/null || echo "[]" > "${PROTOCOL_DATA}.tmp"
        fi

        mv "${PROTOCOL_DATA}.tmp" "$PROTOCOL_DATA"
        debug "DEBUG" "JSON processing complete"
    fi

    local packet_count=$(jq '. | length' "$PROTOCOL_DATA" 2>/dev/null || echo "0")
    log "INFO" "Capturados ${packet_count} paquetes"

    if [ "$DEBUG_MODE" = true ]; then
        debug_capture_summary
    fi
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

    # Generar perfiles de dispositivos si está habilitado
    if [ "$PROFILE_MODE" = true ]; then
        generate_device_profiles
    fi

    # Generar reporte
    generate_report
}

generate_network_state() {
    debug "DEBUG" "=== GENERATING NETWORK STATE ==="
    debug "DEBUG" "Processing ${PROTOCOL_DATA} with jq..."

    jq -r '
        # Clasificar paquetes por protocolo
        # Handle both _source.layers and direct field access
        # Filter out non-object elements first
        map(
            if (type == "object" and has("_source")) then ._source.layers
            elif type == "object" then .
            else empty
            end
        ) |
        map(
            select(type == "object") |
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

    debug "DEBUG" "Network state generation complete"

    if [ "$DEBUG_MODE" = true ]; then
        validate_json "$STATE_FILE" "Network State"

        # Save pretty-printed version for debugging
        jq '.' "$STATE_FILE" > "${DEBUG_DIR}/network_state_pretty.json" 2>/dev/null
        debug "DEBUG" "Pretty-printed state saved to: ${DEBUG_DIR}/network_state_pretty.json"

        # Show summary stats
        debug "INFO" "State Summary:"
        debug "INFO" "  ARP packets: $(jq '.arp_packets | length' "$STATE_FILE" 2>/dev/null || echo 0)"
        debug "INFO" "  DHCP packets: $(jq '.dhcp_packets | length' "$STATE_FILE" 2>/dev/null || echo 0)"
        debug "INFO" "  STP packets: $(jq '.stp_packets | length' "$STATE_FILE" 2>/dev/null || echo 0)"
        debug "INFO" "  CDP packets: $(jq '.cdp_packets | length' "$STATE_FILE" 2>/dev/null || echo 0)"
        debug "INFO" "  LLDP packets: $(jq '.lldp_packets | length' "$STATE_FILE" 2>/dev/null || echo 0)"
        debug "INFO" "  ARP table entries: $(jq '.arp_table | length' "$STATE_FILE" 2>/dev/null || echo 0)"
        debug "INFO" "  DHCP servers: $(jq '.dhcp_servers | length' "$STATE_FILE" 2>/dev/null || echo 0)"
        debug "INFO" "  STP roots: $(jq '.stp_roots | length' "$STATE_FILE" 2>/dev/null || echo 0)"
        debug "INFO" "  Discovered devices: $(jq '.discovered_devices | length' "$STATE_FILE" 2>/dev/null || echo 0)"
    fi
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

# ==================== DEVICE PROFILING ====================

generate_device_profiles() {
    [ ! -s "$PROTOCOL_DATA" ] && log "WARN" "No hay datos para perfilar dispositivos" && return

    log "INFO" "Generando perfiles de dispositivos..."
    debug "DEBUG" "=== GENERATING DEVICE PROFILES ==="

    jq '
        # Extract and normalize packet data
        map(
            if (type == "object" and has("_source")) then ._source.layers
            elif type == "object" then .
            else empty
            end
        ) |
        map(select(type == "object")) |

        # Group by source MAC address
        group_by(.["eth.src"][0] // .["eth.src"] // "unknown") |
        map(
            {
                mac_address: (.[0]["eth.src"][0] // .[0]["eth.src"] // "unknown"),
                packets: .,
                packet_count: length
            }
        ) |

        # Generate profile for each MAC
        map({
            mac_address: .mac_address,
            total_packets: .packet_count,
            first_seen: (
                [.packets[]["frame.time_epoch"][0] // .packets[]["frame.time_epoch"] // 0 | tonumber] |
                min |
                if . > 0 then . else null end
            ),
            last_seen: (
                [.packets[]["frame.time_epoch"][0] // .packets[]["frame.time_epoch"] // 0 | tonumber] |
                max |
                if . > 0 then . else null end
            ),
            duration_seconds: (
                ([.packets[]["frame.time_epoch"][0] // .packets[]["frame.time_epoch"] // 0 | tonumber] | max) -
                ([.packets[]["frame.time_epoch"][0] // .packets[]["frame.time_epoch"] // 0 | tonumber] | min) |
                if . < 0 then 0 else . end
            ),
            total_bytes: (
                [.packets[]["frame.len"][0] // .packets[]["frame.len"] // "0" | tonumber] |
                add // 0
            ),
            avg_packet_size: (
                if .packet_count > 0 then
                    (([.packets[]["frame.len"][0] // .packets[]["frame.len"] // "0" | tonumber] | add // 0) / .packet_count | floor)
                else
                    0
                end
            ),
            protocols: (
                [.packets[]["frame.protocols"][0] // .packets[]["frame.protocols"] // ""] |
                map(split(":") | .[-1] // .) |
                group_by(.) |
                map({key: .[0], value: length}) |
                from_entries
            ),
            ipv4_addresses: (
                [.packets[]["ip.src"][0] // .packets[]["ip.src"], .packets[]["arp.src.proto_ipv4"][0] // .packets[]["arp.src.proto_ipv4"]] |
                flatten |
                map(select(. != null)) |
                unique
            ),
            ipv6_addresses: (
                [.packets[]["ipv6.src"][0] // .packets[]["ipv6.src"]] |
                flatten |
                map(select(. != null)) |
                unique
            ),
            tcp_ports: {
                src: ([.packets[]["tcp.srcport"][0] // .packets[]["tcp.srcport"] // ""] | flatten | map(select(. != null and . != "")) | unique),
                dst: ([.packets[]["tcp.dstport"][0] // .packets[]["tcp.dstport"] // ""] | flatten | map(select(. != null and . != "")) | unique)
            },
            udp_ports: {
                src: ([.packets[]["udp.srcport"][0] // .packets[]["udp.srcport"] // ""] | flatten | map(select(. != null and . != "")) | unique),
                dst: ([.packets[]["udp.dstport"][0] // .packets[]["udp.dstport"] // ""] | flatten | map(select(. != null and . != "")) | unique)
            },
            top_destinations: (
                [.packets[]["eth.dst"][0] // .packets[]["eth.dst"]] |
                flatten |
                map(select(. != null)) |
                group_by(.) |
                map({mac: .[0], count: length}) |
                sort_by(.count) |
                reverse |
                .[0:5]
            ),
            estimated_type: "Unknown",
            behavior: {
                is_active: (
                    ([.packets[]["frame.time_epoch"][0] // .packets[]["frame.time_epoch"] // 0 | tonumber] | max) -
                    ([.packets[]["frame.time_epoch"][0] // .packets[]["frame.time_epoch"] // 0 | tonumber] | min) > 60
                ),
                uses_encryption: (
                    [.packets[]["tls.handshake.type"]] | flatten | any(. != null)
                ),
                broadcasts: (
                    [.packets[]["eth.dst"][0] // .packets[]["eth.dst"]] |
                    flatten |
                    any(. == "ff:ff:ff:ff:ff:ff")
                ),
                multicast: (
                    [.packets[]["eth.dst"][0] // .packets[]["eth.dst"]] |
                    flatten |
                    any(startswith("01:00:5e") or startswith("33:33"))
                ),
                packets_per_second: (
                    if (([.packets[]["frame.time_epoch"][0] // .packets[]["frame.time_epoch"] // 0 | tonumber] | max) -
                        ([.packets[]["frame.time_epoch"][0] // .packets[]["frame.time_epoch"] // 0 | tonumber] | min)) > 0 then
                        (.packet_count / (([.packets[]["frame.time_epoch"][0] // .packets[]["frame.time_epoch"] // 0 | tonumber] | max) -
                         ([.packets[]["frame.time_epoch"][0] // .packets[]["frame.time_epoch"] // 0 | tonumber] | min)) | floor)
                    else
                        0
                    end
                )
            }
        }) |

        # Device type classification
        map(
            .estimated_type = (
                if (.protocols.DHCP or .protocols.dhcp) and .behavior.broadcasts then
                    "Router/Gateway"
                elif (.protocols.DNS or .protocols.dns) and ([.udp_ports.dst[] | select(. == "53")] | length > 0) then
                    "DNS Server"
                elif ([.tcp_ports.dst[] | select(. == "80" or . == "443")] | length > 0) then
                    "Web Server"
                elif .behavior.multicast and (.protocols.IGMPv2 or .protocols.ICMPv6 or .protocols.MDNS) then
                    "Router/Gateway"
                elif .protocols.STP or .protocols.CDP or .protocols.LLDP then
                    "Network Switch"
                elif .total_packets < 10 and .behavior.broadcasts then
                    "IoT Device"
                else
                    "Unknown"
                end
            ) | .
        )
    ' "$PROTOCOL_DATA" > "$PROFILE_FILE"

    local device_count=$(jq '. | length' "$PROFILE_FILE" 2>/dev/null || echo "0")
    log "INFO" "Perfiles de ${device_count} dispositivos generados: ${PROFILE_FILE}"

    if [ "$DEBUG_MODE" = true ]; then
        debug "INFO" "Device profiles summary:"
        jq -r '.[] | "  \(.mac_address): \(.total_packets) packets, Type: \(.estimated_type)"' "$PROFILE_FILE" | head -10 | while IFS= read -r line; do
            debug "INFO" "$line"
        done
    fi
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
    -D, --debug                Habilitar modo debug (salida verbose + archivos de debug)
    -P, --profile              Generar perfiles detallados de dispositivos (device_profiles.json)
    -h, --help                 Mostrar esta ayuda

${BOLD}EJEMPLOS:${NC}
    # Monitoreo completo de 60 segundos
    sudo $0 -d 60

    # Solo ARP y DHCP en modo live
    sudo $0 -i eth0 -l -p arp,dhcp

    # Solo alertas críticas
    sudo $0 -s CRITICAL -a security@empresa.com

    # Modo debug para troubleshooting
    sudo $0 -d 30 -D

    # Perfilado de dispositivos con detección de ataques
    sudo $0 -i wlo1 -d 120 -P

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
            -D|--debug)
                DEBUG_MODE=true
                shift
                ;;
            -P|--profile)
                PROFILE_MODE=true
                shift
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
    setup_debug_mode
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

    if [ "$DEBUG_MODE" = true ] && [ -d "$DEBUG_DIR" ]; then
        echo -e "\n${CYAN}${BOLD}=== DEBUG FILES SAVED ===${NC}"
        echo -e "${CYAN}Debug directory: ${DEBUG_DIR}/${NC}"
        echo -e "${CYAN}Files created:${NC}"
        ls -lh "$DEBUG_DIR" | tail -n +2 | awk '{print "  " $9 " (" $5 ")"}' | while IFS= read -r line; do
            echo -e "${CYAN}$line${NC}"
        done
    fi

    exit 0
}

trap cleanup SIGINT SIGTERM

main "$@"
