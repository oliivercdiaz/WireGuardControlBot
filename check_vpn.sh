#!/bin/bash
# === WireGuard Auto-Check & Telegram Alert ===
# Autor: OliverCloud
# Versión: 1.1

# === CONFIGURACIÓN ===
BOT_TOKEN="8425858092:AAH9ZJwUO-VilOm_-gX5MTZObJEEaDzfUVw"
CHAT_ID="8086739688"
CONTAINER="wireguard"
ENDPOINT="1.1.1.1"  # IP pública confiable para test de conectividad

# === FUNCIÓN PARA ENVIAR MENSAJE TELEGRAM ===
send_message() {
  local MESSAGE="$1"
  curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d chat_id="${CHAT_ID}" \
    -d text="${MESSAGE}" >/dev/null 2>&1
}

# === 1️⃣ Verificar si el contenedor WireGuard está activo ===
if ! sudo docker ps | grep -q "$CONTAINER"; then
  send_message "⚠️ Contenedor *WireGuard* no está en ejecución. Intentando reiniciar..."
  sudo docker start "$CONTAINER"
  sleep 5
  if ! sudo docker ps | grep -q "$CONTAINER"; then
    send_message "❌ Error: No se pudo iniciar el contenedor WireGuard."
    exit 1
  fi
  send_message "✅ Contenedor *WireGuard* reiniciado correctamente."
fi

# === 2️⃣ Verificar conectividad desde el contenedor ===
if ! sudo docker exec "$CONTAINER" ping -c 2 "$ENDPOINT" >/dev/null 2>&1; then
  send_message "🚨 WireGuard está activo pero *no tiene conexión a Internet*. Reiniciando contenedor..."
  sudo docker restart "$CONTAINER"
  sleep 8
  if ! sudo docker exec "$CONTAINER" ping -c 2 "$ENDPOINT" >/dev/null 2>&1; then
    send_message "❌ Error: WireGuard sigue sin conexión después del reinicio."
    exit 1
  else
    send_message "✅ WireGuard reconectado correctamente tras el reinicio."
  fi
else
  send_message "🟢 WireGuard funcionando correctamente. Conectividad OK."
fi
