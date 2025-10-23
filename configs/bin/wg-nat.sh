#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 {up|down} <wg-interface>" >&2
    exit 1
fi

ACTION=$1
WG_IFACE=$2

# Detect outbound interface, fallback to eth0
OUT_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -z "$OUT_IFACE" ]; then
    OUT_IFACE=$(ip -o -4 route show to default 2>/dev/null | awk 'NR==1 {print $5}')
fi
if [ -z "$OUT_IFACE" ]; then
    OUT_IFACE="eth0"
fi

# Determine subnet (prefer INTERNAL_SUBNET env, fallback to interface address)
WG_SUBNET=${INTERNAL_SUBNET:-}
if [ -n "$WG_SUBNET" ]; then
    case "$WG_SUBNET" in
        */*) ;;
        *) WG_SUBNET="${WG_SUBNET}/24" ;;
    esac
else
    WG_SUBNET=$(ip -o -4 addr show dev "$WG_IFACE" 2>/dev/null | awk 'NR==1 {print $4}')
fi

if [ "$ACTION" = "up" ]; then
    if [ -n "$WG_SUBNET" ]; then
        if ! iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o "$OUT_IFACE" -j MASQUERADE
        fi
    elif ! iptables -t nat -C POSTROUTING -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -o "$OUT_IFACE" -j MASQUERADE
    fi

    if ! iptables -C FORWARD -i "$WG_IFACE" -o "$OUT_IFACE" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$WG_IFACE" -o "$OUT_IFACE" -j ACCEPT
    fi

    if ! iptables -C FORWARD -i "$OUT_IFACE" -o "$WG_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$OUT_IFACE" -o "$WG_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    fi
elif [ "$ACTION" = "down" ]; then
    if [ -n "$WG_SUBNET" ]; then
        while iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null; do
            iptables -t nat -D POSTROUTING -s "$WG_SUBNET" -o "$OUT_IFACE" -j MASQUERADE
        done
    else
        while iptables -t nat -C POSTROUTING -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null; do
            iptables -t nat -D POSTROUTING -o "$OUT_IFACE" -j MASQUERADE
        done
    fi

    while iptables -C FORWARD -i "$WG_IFACE" -o "$OUT_IFACE" -j ACCEPT 2>/dev/null; do
        iptables -D FORWARD -i "$WG_IFACE" -o "$OUT_IFACE" -j ACCEPT
    done

    while iptables -C FORWARD -i "$OUT_IFACE" -o "$WG_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do
        iptables -D FORWARD -i "$OUT_IFACE" -o "$WG_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    done
else
    echo "usage: $0 {up|down} <wg-interface>" >&2
    exit 1
fi
