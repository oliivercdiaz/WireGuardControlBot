#!/bin/bash
# === WireGuard Auto-Check & Telegram Alert ===
# Autor: OliverCloud
# Versión: 2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

if [[ -f "${ENV_FILE}" ]]; then
  source "${ENV_FILE}"
fi

BOT_TOKEN="${BOT_TOKEN:-}"
CHAT_ID="${CHAT_ID:-}"
CONTAINER="${CONTAINER:-wireguard}"
ENDPOINT="${ENDPOINT:-1.1.1.1}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
USE_SUDO="${USE_SUDO:-0}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl es requerido para notificar por Telegram" >&2
  exit 1
fi

if ! command -v "${DOCKER_BIN}" >/dev/null 2>&1; then
  echo "No se encontró el binario ${DOCKER_BIN}. Ajusta DOCKER_BIN en el entorno." >&2
  exit 1
fi

if [[ -z "${BOT_TOKEN}" || -z "${CHAT_ID}" ]]; then
  echo "BOT_TOKEN y CHAT_ID deben configurarse (variables de entorno o ${ENV_FILE})." >&2
  exit 1
fi

if [[ "${USE_SUDO}" == "1" ]]; then
  DOCKER_CMD=(sudo "${DOCKER_BIN}")
else
  DOCKER_CMD=("${DOCKER_BIN}")
fi

send_message() {
  local message="$1"
  curl -sS -m 10 -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d chat_id="${CHAT_ID}" \
    --data-urlencode text="${message}" >/dev/null
}

docker_exec() {
  "${DOCKER_CMD[@]}" exec "$@"
}

docker_running() {
  "${DOCKER_CMD[@]}" ps --format '{{.Names}}' | grep -Fxq "${CONTAINER}"
}

if ! docker_running; then
  send_message "⚠️ Contenedor *${CONTAINER}* no está en ejecución. Intentando reiniciar..."
  if "${DOCKER_CMD[@]}" start "${CONTAINER}" >/dev/null 2>&1; then
    sleep 5
  fi
  if ! docker_running; then
    send_message "❌ Error: No se pudo iniciar el contenedor ${CONTAINER}."
    exit 1
  fi
  send_message "✅ Contenedor *${CONTAINER}* reiniciado correctamente."
fi

if ! docker_exec "${CONTAINER}" ping -c 2 -W 3 "${ENDPOINT}" >/dev/null 2>&1; then
  send_message "🚨 ${CONTAINER} activo pero *sin salida a Internet*. Reiniciando contenedor..."
  if "${DOCKER_CMD[@]}" restart "${CONTAINER}" >/dev/null 2>&1; then
    sleep 8
  fi
  if ! docker_exec "${CONTAINER}" ping -c 2 -W 3 "${ENDPOINT}" >/dev/null 2>&1; then
    send_message "❌ ${CONTAINER} sigue sin conexión tras el reinicio. Requiere intervención."
    exit 1
  fi
  send_message "✅ ${CONTAINER} reconectado correctamente tras el reinicio."
else
  send_message "🟢 ${CONTAINER} funcionando correctamente. Conectividad OK."
fi
