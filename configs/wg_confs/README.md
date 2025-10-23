# Configuraciones de WireGuard

Este directorio se rellena automáticamente cuando el contenedor `linuxserver/wireguard` se inicia por primera vez. Se generan:

- `wg0.conf`: configuración del servidor con las claves reales.
- `peerX.conf`/`peerX.png`: archivos de cliente creados por el bot o por el contenedor.

Los ficheros contienen claves privadas y no deben versionarse. El `.gitignore` de la raíz ya los excluye.

Si necesitas reinicializar la configuración, detén los contenedores, elimina el contenido de este directorio y vuelve a arrancar `docker compose up -d` para que se regenere todo.
