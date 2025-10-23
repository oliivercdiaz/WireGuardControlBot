#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
    echo "Uso: ${0##*/} <nombre|ip|ruta.conf>" >&2
    exit 1
fi

QUERY="$1"
WG_IFACE="${WG_INTERFACE:-wg0}"
CONF_DIR="${WG_CLIENTS_DIR:-/config/wg_confs}"
WG_BIN="${WG_BIN:-wg}"
IPTABLES_BIN="${IPTABLES_BIN:-iptables}"

if ! command -v "$WG_BIN" >/dev/null 2>&1; then
    echo "❌ No encontré el binario '$WG_BIN'." >&2
    exit 2
fi
if ! command -v "$IPTABLES_BIN" >/dev/null 2>&1; then
    echo "❌ No encontré el binario '$IPTABLES_BIN'." >&2
    exit 2
fi

conf_path=""
if [ -f "$QUERY" ]; then
    conf_path="$QUERY"
elif [ -f "$CONF_DIR/$QUERY" ]; then
    conf_path="$CONF_DIR/$QUERY"
elif [ -f "$CONF_DIR/$QUERY.conf" ]; then
    conf_path="$CONF_DIR/$QUERY.conf"
else
    for file in "$CONF_DIR"/*.conf; do
        [ -e "$file" ] || break
        ip_line=$(grep -m1 -E '^Address' "$file" 2>/dev/null || true)
        ip_value=$(printf "%s" "$ip_line" | awk -F '=' '{print $2}' | tr -d ' ')
        ip_value=${ip_value%/*}
        if [ -n "$ip_value" ] && [ "$ip_value" = "$QUERY" ]; then
            conf_path="$file"
            break
        fi
    done
fi

if [ -z "$conf_path" ]; then
    echo "❌ No encontré un .conf para '$QUERY' en $CONF_DIR" >&2
    exit 3
fi

peer_name=$(basename "$conf_path")
peer_name=${peer_name%.conf}
address_line=$(grep -m1 -E '^Address' "$conf_path" 2>/dev/null || true)
client_address=$(printf "%s" "$address_line" | awk -F '=' '{print $2}' | tr -d ' ')
client_ip=${client_address%/*}
if [ -z "$client_ip" ]; then
    echo "❌ No pude extraer la IP de cliente desde $conf_path" >&2
    exit 4
fi

allowed_ip="${client_ip}/32"
peer_key=$($WG_BIN show "$WG_IFACE" allowed-ips 2>/dev/null | awk -v ip="$allowed_ip" '$2 == ip {print $1; exit}') || peer_key=""
latest_handshake=0
handshake_desc="sin handshake"
endpoint="(sin endpoint)"
transfer_desc="(sin tráfico)"
keepalive=""

if [ -n "$peer_key" ]; then
    latest_handshake=$($WG_BIN show "$WG_IFACE" latest-handshakes 2>/dev/null | awk -v key="$peer_key" '$1 == key {print $2; exit}') || latest_handshake=0
    endpoint=$($WG_BIN show "$WG_IFACE" endpoints 2>/dev/null | awk -v key="$peer_key" '$1 == key {print $2; exit}') || endpoint="(sin endpoint)"
    transfer_desc=$($WG_BIN show "$WG_IFACE" transfer 2>/dev/null | awk -v key="$peer_key" '$1 == key {printf "%s bytes ↓ / %s bytes ↑", $2, $3; exit}') || transfer_desc="(sin tráfico)"
    keepalive=$($WG_BIN show "$WG_IFACE" persistent-keepalive 2>/dev/null | awk -v key="$peer_key" '$1 == key {print $2; exit}') || keepalive=""
    if [ -z "$keepalive" ] || [ "$keepalive" = "0" ]; then
        keepalive="(no configurado)"
    fi
    now_ts=$(date +%s 2>/dev/null || echo 0)
    if [ -n "$latest_handshake" ] && [ "$latest_handshake" -gt 0 ] && [ "$now_ts" -gt 0 ]; then
        delta=$((now_ts - latest_handshake))
        if [ "$delta" -lt 0 ]; then delta=0; fi
        if [ "$delta" -lt 120 ]; then
            handshake_desc="hace ~${delta}s"
        elif [ "$delta" -lt 3600 ]; then
            mins=$((delta / 60))
            handshake_desc="hace ~${mins}m"
        elif [ "$delta" -lt 172800 ]; then
            hours=$((delta / 3600))
            handshake_desc="hace ~${hours}h"
        else
            days=$((delta / 86400))
            handshake_desc="hace ~${days}d"
        fi
    else
        handshake_desc="sin handshake"
    fi
fi

wg_subnet="${INTERNAL_SUBNET:-}"
if [ -z "$wg_subnet" ]; then
    wg_subnet=$(ip -o -4 addr show dev "$WG_IFACE" 2>/dev/null | awk 'NR==1 {print $4}')
fi
out_iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -z "$out_iface" ]; then
    out_iface=$(ip -o -4 route show to default 2>/dev/null | awk 'NR==1 {print $5}')
fi

nat_status="⚠️ No pude determinar regla MASQUERADE"
if [ -n "$wg_subnet" ]; then
    if [ -n "$out_iface" ] && $IPTABLES_BIN -t nat -C POSTROUTING -s "$wg_subnet" -o "$out_iface" -j MASQUERADE 2>/dev/null; then
        nat_status="✅ MASQUERADE para $wg_subnet → $out_iface"
    elif $IPTABLES_BIN -t nat -C POSTROUTING -s "$wg_subnet" -j MASQUERADE 2>/dev/null; then
        nat_status="⚠️ MASQUERADE detectado pero sin interfaz de salida. Revisa wg-nat.sh"
    else
        nat_status="❌ No hay MASQUERADE para $wg_subnet"
    fi
fi

forward_out="⚠️ No comprobado"
forward_in="⚠️ No comprobado"
if [ -n "$out_iface" ]; then
    if $IPTABLES_BIN -C FORWARD -i "$WG_IFACE" -o "$out_iface" -j ACCEPT 2>/dev/null; then
        forward_out="✅ FORWARD ${WG_IFACE}→${out_iface}"
    else
        forward_out="❌ Falta regla FORWARD ${WG_IFACE}→${out_iface}"
    fi
    if $IPTABLES_BIN -C FORWARD -i "$out_iface" -o "$WG_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        forward_in="✅ FORWARD ${out_iface}→${WG_IFACE} (RELATED,ESTABLISHED)"
    else
        forward_in="❌ Falta regla FORWARD ${out_iface}→${WG_IFACE}"
    fi
fi

ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "desconocido")
if [ "$ip_forward" = "1" ]; then
    ip_forward="✅ net.ipv4.ip_forward=1"
else
    ip_forward="❌ net.ipv4.ip_forward=$ip_forward"
fi

default_route=$(ip route get 1.1.1.1 2>/dev/null | head -n1)
if [ -z "$default_route" ]; then
    default_route="(sin ruta por defecto hacia 1.1.1.1)"
fi

echo "============================="
printf "Diagnóstico peer: %s\n" "$peer_name"
printf "Archivo cliente: %s\n" "$conf_path"
printf "IP asignada: %s\n" "$allowed_ip"
if [ -n "$peer_key" ]; then
    printf "Clave pública (servidor): %s\n" "$peer_key"
    printf "Último handshake: %s\n" "$handshake_desc"
    printf "Endpoint actual: %s\n" "$endpoint"
    printf "Tráfico acumulado: %s\n" "$transfer_desc"
    printf "Keepalive: %s\n" "$keepalive"
else
    printf "⚠️ El peer %s no está cargado en %s (no aparece en wg show).\n" "$peer_name" "$WG_IFACE"
    printf "   Revisa que hayas ejecutado /addpeer o añadido el bloque al servidor.\n"
fi
printf "\nEstado del router/NAT:\n"
printf "• %s\n" "$nat_status"
if [ -n "$wg_subnet" ]; then
    printf "• Subred detectada: %s\n" "$wg_subnet"
fi
if [ -n "$out_iface" ]; then
    printf "• Interfaz de salida: %s\n" "$out_iface"
fi
printf "• %s\n" "$forward_out"
printf "• %s\n" "$forward_in"
printf "• %s\n" "$ip_forward"
printf "• Ruta hacia Internet: %s\n" "$default_route"

echo "\nSugerencias:" 
if [ -z "$peer_key" ]; then
    echo "- Importa la configuración en el cliente y asegúrate de que el QR coincide con el último /addpeer."
    echo "- Comprueba que el puerto UDP ${SERVERPORT:-51820} esté abierto en tu router/Cloudflare."
elif [ "$handshake_desc" = "sin handshake" ]; then
    echo "- El cliente no ha hecho handshake. Revisa la IP pública/endpoint y que el puerto esté accesible."
    echo "- En el móvil, desconecta y vuelve a activar el túnel; revisa también la hora del dispositivo."
else
    echo "- El handshake existe. Si aún no hay Internet, revisa DNS del cliente y posibles firewalls intermedios."
fi
if printf "%s" "$nat_status" | grep -q '❌'; then
    echo "- No hay NAT: ejecuta /config/bin/wg-nat.sh up ${WG_IFACE} o reinicia el contenedor."
fi
if printf "%s" "$forward_out$forward_in" | grep -q '❌'; then
    echo "- Alguna regla FORWARD falta. Reaplica wg-nat.sh o revisa iptables."
fi
