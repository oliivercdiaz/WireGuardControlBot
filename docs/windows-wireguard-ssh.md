# Acceso SSH desde Windows 11 a través de WireGuard

Este documento cubre el escenario más habitual cuando un cliente Windows 11 se conecta a la VPN y al intentar acceder por SSH aparece alguno de los siguientes errores:

- `async io completed with error: 10013` → el firewall o un antivirus bloquea la conexión saliente hacia el puerto 22.
- `async io completed with error: 10060` → el cliente intenta llegar a una IP que no responde en el túnel (por ejemplo `10.8.0.1` cuando el servidor realmente usa `10.119.153.1`).

Sigue los pasos en este orden para asegurarte de que la conexión pasa por WireGuard y llega al demonio SSH del servidor.

## 1. Verifica la IP del servidor en la red WireGuard

De manera predeterminada la plantilla `configs/templates/server.conf` establece la IP `10.119.153.1/24` para la interfaz `wg0`. Consulta el fichero real dentro del contenedor o en `configs/wg_confs/wg0.conf` para confirmar la dirección asignada.

Cuando abras una sesión SSH desde Windows deberías apuntar a esa IP o a la IP LAN del host (por ejemplo `192.168.1.69`).

```powershell
ssh -vvv oliver@10.119.153.1
ssh -vvv oliver@192.168.1.69
```

Si intentas usar otra (como `10.8.0.1`) la conexión terminará en un error `10060` porque no existe ningún host escuchando en esa dirección dentro del túnel.

## 2. Habilita el reenvío y las reglas NAT en la Raspberry Pi

El contenedor `linuxserver/wireguard` ya activa `net.ipv4.ip_forward=1`, pero si usas un despliegue manual asegúrate de aplicarlo también en el host:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

Para que los clientes puedan alcanzar tu red local, ejecuta el script de NAT incluido o replica sus reglas con `iptables`:

```bash
docker compose exec wireguard /config/bin/wg-nat.sh up wg0
```

El script detecta la interfaz de salida del host y añade las reglas `MASQUERADE` y `FORWARD` necesarias. Puedes comprobarlo desde el contenedor:

```bash
docker compose exec wireguard iptables -t nat -S POSTROUTING
docker compose exec wireguard iptables -S FORWARD
```

Si trabajas sin Docker, reproduce las reglas manualmente sustituyendo `eth0` por tu interfaz LAN:

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

## 3. Añade reglas de firewall para `ssh.exe` en Windows 11

Cuando el adaptador WireGuard está activo, Windows aplica un perfil independiente. Si no existe una regla explícita para `ssh.exe` o para el puerto 22, aparecerá el error `10013`. Ejecuta PowerShell **como Administrador** y crea las reglas necesarias:

```powershell
# Permite que ssh.exe abra conexiones salientes en cualquier perfil
New-NetFirewallRule -DisplayName "Allow OpenSSH Outbound" `
    -Program "C:\\Windows\\System32\\OpenSSH\\ssh.exe" `
    -Direction Outbound -Action Allow -Profile Any

# Opcional: asocia la regla al adaptador WireGuard cuando conozcas su alias
$wg = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*WireGuard*"} | Select-Object -First 1 -ExpandProperty Name
if ($wg) {
    New-NetFirewallRule -DisplayName "Allow SSH via WireGuard" `
        -Direction Outbound -Protocol TCP `
        -RemotePort 22 -InterfaceAlias $wg -Action Allow
}
```

Puedes revisar las reglas creadas con:

```powershell
Get-NetFirewallRule -DisplayName "Allow OpenSSH Outbound"
Get-NetFirewallRule -DisplayName "Allow SSH via WireGuard" | Get-NetFirewallPortFilter
```

Si utilizas un antivirus o una suite de seguridad, añade excepciones equivalentes para `ssh.exe` y para la subred de tu hogar (`192.168.1.0/24`).

## 4. Reconecta el túnel y prueba de nuevo

Desactiva y vuelve a activar la VPN en la aplicación de WireGuard para que Windows reevalúe las reglas. A continuación repite las pruebas con verbose:

```powershell
ssh -vvv oliver@10.119.153.1
ssh -vvv oliver@192.168.1.69
```

En el servidor, verifica los registros para confirmar que el intento llega desde tu IP de WireGuard (`10.119.153.x`):

```bash
sudo journalctl -u ssh --since "5 minutes ago"
```

## 5. Diagnóstico adicional

- Usa `wg show` en la Raspberry para confirmar el `latest handshake` del peer Windows y comprobar si el contador de bytes aumenta tras cada intento.
- Si la conexión se establece pero no tienes salida a Internet, revisa el script `configs/bin/wg-peer-debug.sh` o ejecuta `/debugpeer <peer>` desde el bot de Telegram.
- Para permitir el acceso a otros equipos de la LAN (router, NAS, etc.) asegúrate de que `AllowedIPs` en el cliente incluye `192.168.1.0/24` o la subred correspondiente.

Con estos pasos eliminas los bloqueos típicos en Windows y garantizas que el servidor enruta correctamente el tráfico entrante del túnel WireGuard hacia tu red doméstica.
