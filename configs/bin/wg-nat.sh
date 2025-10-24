#!/bin/bash
# /config/bin/wg-nat.sh - manejador seguro de NAT para WireGuard (Docker host mode compatible)

set -e

ACTION=$1
INTERFACE=$2

case "$ACTION" in
  up)
    echo "[NAT] Activando NAT en $INTERFACE..."
    # Evitar error: no se puede modificar sysctl en modo host
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
      echo "[NAT] Advertencia: El reenvío IP (ip_forward) está desactivado en el host."
      echo "[NAT] Ejecute en el host: sudo sysctl -w net.ipv4.ip_forward=1"
    else
      echo "[NAT] Reenvío IP ya está activo en el host."
    fi

    # Detectar interfaz de salida
    OUT_IFACE=$(ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}')
    if [ -z "$OUT_IFACE" ]; then
      OUT_IFACE="eth0"
    fi
    echo "[NAT] Usando interfaz de salida: $OUT_IFACE"

    # Activar NAT si no existe
    if ! iptables -t nat -C POSTROUTING -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null; then
      iptables -t nat -A POSTROUTING -o "$OUT_IFACE" -j MASQUERADE
      echo "[NAT] Regla NAT agregada en $OUT_IFACE"
    else
      echo "[NAT] Regla NAT ya existente, omitida."
    fi
    ;;
  down)
    echo "[NAT] Desactivando NAT en $INTERFACE..."
    OUT_IFACE=$(ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}')
    if [ -z "$OUT_IFACE" ]; then
      OUT_IFACE="eth0"
    fi

    if iptables -t nat -C POSTROUTING -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null; then
      iptables -t nat -D POSTROUTING -o "$OUT_IFACE" -j MASQUERADE
      echo "[NAT] Regla NAT eliminada en $OUT_IFACE"
    else
      echo "[NAT] No se encontró regla NAT para eliminar."
    fi
    ;;
  *)
    echo "Uso: $0 {up|down} <interface>"
    exit 1
    ;;
esac
