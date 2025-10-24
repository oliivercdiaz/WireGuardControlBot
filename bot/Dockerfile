FROM python:3.11-slim

# --- Instala dependencias del sistema necesarias ---
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        docker-cli \
        wireguard-tools \
        iproute2 \
        iputils-ping \         # 🔹 necesario para check_internet_connectivity()
        net-tools \            # 🔹 útil para debug y comandos ifconfig
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# --- Configuración del entorno Python ---
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# --- Directorio de trabajo ---
WORKDIR /app

# --- Instala dependencias Python ---
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# --- Copia el código del bot ---
COPY . .

# --- Comando de arranque ---
CMD ["python", "wireguardcontrolbot.py"]
