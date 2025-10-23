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
- `/debugpeer <nombre>` desde Telegram genera un diagnóstico del peer (handshake, NAT, reglas `iptables`, últimos logs).

## Scripts adicionales
`check_vpn.sh` permite monitorizar el contenedor WireGuard desde el host y enviar alertas por Telegram. Configura las variables `BOT_TOKEN`, `CHAT_ID` y `CONTAINER` mediante variables de entorno o un archivo `.env` en el mismo directorio antes de programarlo con `cron`.

`configs/bin/wg-nat.sh` puede ejecutarse manualmente dentro del contenedor si necesitas volver a aplicar las reglas de NAT tras modificar la red:

```bash
docker compose exec wireguard /config/bin/wg-nat.sh up wg0
docker compose exec wireguard ping -c 3 1.1.1.1
docker compose exec wireguard iptables -t nat -S POSTROUTING
```
Las órdenes anteriores confirman que la interfaz externa se detecta bien, que las reglas se encuentran activas y que el contenedor tiene salida a Internet.

### Diagnóstico cuando un cliente no tiene Internet

1. Conéctate al contenedor y lanza el script de diagnóstico. Verás si el peer está cargado, cuándo fue el último handshake, las reglas `iptables`, los últimos eventos del kernel y los logs disponibles, junto con sugerencias concretas.

   `configs/bin/wg-peer-debug.sh` recopila información útil cuando un cliente no navega (handshake, NAT, `ip_forward`, reglas FORWARD y sugerencias). Ejecútalo dentro del contenedor pasando el nombre del peer o su IP:

   ```bash
   docker compose exec wireguard /config/bin/wg-peer-debug.sh peer1
   docker compose exec wireguard /config/bin/wg-peer-debug.sh 10.119.153.2
   ```

2. Si estás fuera de casa y sólo tienes el móvil, abre Telegram y envía `/debugpeer peer1`. El bot comprobará que el contenedor WireGuard esté en marcha, levantará la interfaz si hiciera falta y ejecutará el mismo script dentro del contenedor para devolverte los resultados en tu chat privado: sabrás al instante si falta NAT, si el peer no ha hecho handshake, si hay eventos de error en los logs o si hay problemas con DNS.

> ℹ️ `/addpeer` y `/delpeer` también verifican que el contenedor `wireguard` y la interfaz `wg0` estén activos antes de tocar la configuración, evitando el error “Unable to modify interface: No such device”.

### Acceso SSH desde Windows a través de WireGuard

Si conectas un cliente Windows 11 y recibes errores `async io completed with error: 10013` o `10060` al usar `ssh`, revisa los pasos descritos en [docs/windows-wireguard-ssh.md](docs/windows-wireguard-ssh.md). Encontrarás instrucciones para:

- Confirmar la IP real del servidor dentro del túnel (`10.119.153.1` por defecto) y evitar intentos hacia direcciones inexistentes como `10.8.0.1`.
- Reaplicar las reglas de NAT (`/config/bin/wg-nat.sh up wg0`) y revisar `iptables` para asegurarte de que el tráfico del túnel puede salir hacia tu LAN.
- Crear reglas de firewall en Windows que permitan a `ssh.exe` usar el adaptador WireGuard y autoricen la subred doméstica (`192.168.1.0/24`).
- Repetir la conexión con `ssh -vvv` y comprobar en los logs del servidor (`journalctl -u ssh`) que el intento llega desde la IP del peer.

## Servicios systemd
Si prefieres systemd en lugar de Docker Compose, puedes usar `systemd/wireguardcontrolbot.service` como base. Ajusta las rutas y variables según tu despliegue.

## Seguridad
- Los archivos de clientes (.conf y .png) se crean con permisos 600.
- `.env` está excluido del control de versiones (`.gitignore`).
- Revisa periódicamente las claves y tokens almacenados en tu host.
