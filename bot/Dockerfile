# --- WireGuardControlBot: Dockerfile (Python 3.11) ---
FROM python:3.11-slim

RUN apt-get update && apt-get install -y docker-cli curl && rm -rf /var/lib/apt/lists/*

# Evita .pyc y fuerza logs sin buffer
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Herramientas necesarias para comprobar WireGuard y red
# - wireguard-tools: para `wg show`
# - iproute2: utilidades de red (ip, ss…)
# - curl/ca-certificates: obtener IP pública, etc.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wireguard-tools iproute2 curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala dependencias primero (mejor caché)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copia el código del bot
COPY . .

# Arranca el bot
CMD ["python", "wireguardcontrolbot.py"]
