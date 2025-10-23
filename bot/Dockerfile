FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        docker-cli \
        wireguard-tools \
        iproute2 \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "wireguardcontrolbot.py"]
