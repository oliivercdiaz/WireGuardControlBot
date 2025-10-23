# WireGuardControlBot

Automatiza la gestión de un servidor WireGuard desplegado con Docker y lo integra con un bot de Telegram. Incluye automatizaciones para supervisar el estado, generar peers y actualizar DNS dinámico en Cloudflare.

## Requisitos
- Raspberry Pi 5 (o cualquier host con Docker y docker-compose).
- Docker 24+ y Docker Compose plugin.
- Cuenta de Telegram con un bot y token válido (`@BotFather`).
- (Opcional) Credenciales de API de Cloudflare para actualizar un registro DNS.

## Preparación
1. **Clona el repositorio**
   ```bash
   git clone https://github.com/tu-usuario/WireGuardControlBot.git
   cd WireGuardControlBot
   ```
2. **Copia el archivo de variables de entorno**
   ```bash
   cp .env.example .env
   ```
   Rellena `.env` con tus valores reales. Este archivo no se versiona y contiene credenciales.

3. **Revisa/ajusta la configuración de WireGuard**
   - `configs/templates/server.conf`: plantilla que usa el contenedor `linuxserver/wireguard`. Llama al script `configs/bin/wg-nat.sh` para detectar automáticamente la interfaz física y asegurar las reglas de `iptables` necesarias para dar salida a Internet a los clientes.
   - `configs/bin/wg-nat.sh`: script idempotente que añade o retira las reglas `MASQUERADE` y `FORWARD`. Si cambias la subred o la interfaz del host, edita aquí primero.
   - `configs/wg_confs/`: el contenedor lo rellena automáticamente en el primer arranque con `wg0.conf` y los peers creados. Consulta `configs/wg_confs/README.md` para saber cómo regenerarlo sin exponer claves.

4. **Configura el bot de Telegram**
   - `TELEGRAM_TOKEN`: token del bot.
   - `AUTHORIZED_USERS`: lista de IDs separados por comas que podrán usar los comandos.
   - `ADMIN_CHAT_ID`: chat ID que recibirá alertas del monitor.

5. **Configura Cloudflare (opcional)**
   - Activa `USE_CLOUDFLARE=true` en `.env` y rellena `CF_API_TOKEN`, `CF_ZONE_ID` y `CF_RECORD_NAME`.
   - El bot actualizará automáticamente el registro A si cambia la IP pública.

## Puesta en marcha
Compila e inicia los servicios:
```bash
docker compose build
docker compose up -d
```
Esto crea dos contenedores:
- `wireguard`: servicio VPN con WireGuard.
- `wireguardcontrolbot`: bot de Telegram que gestiona el servidor y monitoriza su estado.

## Comandos útiles
- `docker compose logs -f wireguardcontrolbot`: ver actividad del bot.
- `docker compose logs -f wireguard`: revisar el servidor WireGuard.
- `/help` en Telegram: lista completa de comandos disponibles.
- `/debugpeer <nombre>` desde Telegram genera un diagnóstico del peer (handshake, NAT, reglas `iptables`).

## Scripts adicionales
`check_vpn.sh` permite monitorizar el contenedor WireGuard desde el host y enviar alertas por Telegram. Configura las variables `BOT_TOKEN`, `CHAT_ID` y `CONTAINER` mediante variables de entorno o un archivo `.env` en el mismo directorio antes de programarlo con `cron`.

`configs/bin/wg-nat.sh` puede ejecutarse manualmente dentro del contenedor si necesitas volver a aplicar las reglas de NAT tras modificar la red:

```bash
docker compose exec wireguard /config/bin/wg-nat.sh up wg0
docker compose exec wireguard ping -c 3 1.1.1.1
docker compose exec wireguard iptables -t nat -S POSTROUTING
```
Las órdenes anteriores confirman que la interfaz externa se detecta bien, que las reglas se encuentran activas y que el contenedor tiene salida a Internet.

`configs/bin/wg-peer-debug.sh` recopila información útil cuando un cliente no navega (handshake, NAT, `ip_forward`, reglas FORWARD y sugerencias). Ejecútalo dentro del contenedor pasando el nombre del peer o su IP:

```bash
docker compose exec wireguard /config/bin/wg-peer-debug.sh peer1
docker compose exec wireguard /config/bin/wg-peer-debug.sh 10.119.153.2
```
Puedes lanzar el mismo diagnóstico desde Telegram con `/debugpeer peer1` para recibir el resultado en tu chat privado.

## Servicios systemd
Si prefieres systemd en lugar de Docker Compose, puedes usar `systemd/wireguardcontrolbot.service` como base. Ajusta las rutas y variables según tu despliegue.

## Seguridad
- Los archivos de clientes (.conf y .png) se crean con permisos 600.
- `.env` está excluido del control de versiones (`.gitignore`).
- Revisa periódicamente las claves y tokens almacenados en tu host.
