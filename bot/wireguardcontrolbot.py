import os
import json
import asyncio
import socket
import time
import statistics
import logging
import docker
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram.error import TelegramError
from subprocess import run, PIPE

# ========= Config =========
TOKEN = os.getenv("TELEGRAM_TOKEN")
AUTHORIZED_USERS = [int(u) for u in os.getenv("AUTHORIZED_USERS", "").split(",") if u.strip()]
WG_CONTAINER_NAME = os.getenv("WG_DOCKER_CONTAINER", "wireguard")
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WG_CONFIG_PATH = os.getenv("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf")
WG_MTU = int(os.getenv("WG_MTU", "1420"))
PING_INTERVAL = int(os.getenv("PING_INTERVAL", "300"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
STATE_FILE = "/configs/bot_state.json"

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("wg-control-bot")
docker_client = docker.from_env()

# ========= Helpers =========
def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"notifications": True}

def save_state(st):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(st, f)
    except Exception as e:
        log.warning(f"No pude guardar estado: {e}")

STATE = load_state()

def only_auth(func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id if update.effective_user else None
        if uid not in AUTHORIZED_USERS:
            if update.message:
                await update.message.reply_text("⛔ No estás autorizado para usar este bot.")
            return
        return await func(update, context)
    return wrapper

def container_ok():
    try:
        c = docker_client.containers.get(WG_CONTAINER_NAME)
        return c.status == "running"
    except Exception:
        return False

def container_exec(cmd, timeout=10):
    c = docker_client.containers.get(WG_CONTAINER_NAME)
    exec_id = docker_client.api.exec_create(c.id, cmd, stdout=True, stderr=True)
    output = docker_client.api.exec_start(exec_id, demux=True, stream=False)
    if isinstance(output, tuple):
        out = (output[0] or b"") + (output[1] or b"")
    else:
        out = output or b""
    insp = docker_client.api.exec_inspect(exec_id)
    return insp.get("ExitCode", 1), out.decode(errors="ignore")

def restart_wireguard():
    try:
        docker_client.containers.get(WG_CONTAINER_NAME).restart()
        return True
    except Exception as e:
        log.error(f"Error reiniciando WG: {e}")
        return False

def get_public_ip():
    try:
        r = run(["curl", "-s", "https://api.ipify.org"], stdout=PIPE, stderr=PIPE, text=True, timeout=8)
        return r.stdout.strip() or "Desconocida"
    except Exception:
        return "Desconocida"

def ping_host(host="1.1.1.1", count=4):
    try:
        r = run(["ping", "-c", str(count), "-W", "2", host], stdout=PIPE, stderr=PIPE, text=True, timeout=10)
        if r.returncode == 0:
            times = [float(line.split("time=")[1].split()[0])
                     for line in r.stdout.splitlines() if "time=" in line]
            if times:
                return True, {"avg": round(statistics.mean(times), 2),
                              "min": round(min(times), 2),
                              "max": round(max(times), 2),
                              "samples": len(times)}
        start = time.perf_counter()
        with socket.create_connection(("1.1.1.1", 53), timeout=2):
            pass
        elapsed = (time.perf_counter() - start) * 1000
        return True, {"avg": round(elapsed, 2), "tcp": True}
    except Exception:
        return False, {}

def parse_wg_show(text):
    peers, current = [], {}
    for line in text.splitlines():
        if line.startswith("peer:"):
            if current:
                peers.append(current)
            current = {"peer": line.split("peer:")[1].strip()}
        elif "allowed ips:" in line:
            current["ips"] = line.split("allowed ips:")[1].strip()
        elif "latest handshake:" in line:
            current["handshake"] = line.split("latest handshake:")[1].strip()
    if current:
        peers.append(current)
    return peers

# ========= Commands =========
@only_auth
async def cmd_start(update, ctx):
    await update.message.reply_text(
        "👋 Hola! WireGuardControlBot v2.1 activo ✅\n\n"
        "Comandos disponibles:\n"
        "/status - Estado del servidor\n"
        "/restart - Reiniciar WireGuard\n"
        "/clients - Lista de peers conectados\n"
        "/latency - Ping a 1.1.1.1\n"
        "/addpeer <nombre> - Crear un nuevo peer\n"
        "/report - Informe completo"
    )

@only_auth
async def cmd_status(update, ctx):
    ok = container_ok()
    ip = get_public_ip()
    if ok:
        code, out = container_exec(f"wg show {WG_INTERFACE}")
        peers = parse_wg_show(out)
        msg = f"🟢 WireGuard activo\n🌐 IP: {ip}\n👥 Peers: {len(peers)}"
    else:
        msg = f"🔴 WireGuard detenido\n🌐 IP: {ip}"
    await update.message.reply_text(msg)

@only_auth
async def cmd_restart(update, ctx):
    await update.message.reply_text("♻️ Reiniciando WireGuard…")
    msg = "✅ Reiniciado" if restart_wireguard() else "❌ Error al reiniciar"
    await update.message.reply_text(msg)

@only_auth
async def cmd_clients(update, ctx):
    if not container_ok():
        await update.message.reply_text("🔴 WG no está corriendo.")
        return
    code, out = container_exec(f"wg show {WG_INTERFACE}")
    peers = parse_wg_show(out)
    if not peers:
        await update.message.reply_text("Sin peers configurados.")
        return
    lines = [f"👥 {len(peers)} peers:"]
    for i, p in enumerate(peers, 1):
        lines.append(f"{i}. {p.get('ips','-')} | {p.get('handshake','-')}")
    await update.message.reply_text("\n".join(lines))

@only_auth
async def cmd_latency(update, ctx):
    ok, data = ping_host("1.1.1.1", 4)
    if ok:
        await update.message.reply_text(f"⏱️ Latencia promedio: {data['avg']} ms")
    else:
        await update.message.reply_text("❌ Error midiendo latencia.")

@only_auth
async def cmd_report(update, ctx):
    ip = get_public_ip()
    ok = container_ok()
    code, out = container_exec(f"wg show {WG_INTERFACE}") if ok else (1, "")
    peers = parse_wg_show(out) if ok else []
    msg = (f"📋 Reporte\n🌐 IP pública: {ip}\n"
           f"📦 WG: {'activo' if ok else 'inactivo'}\n"
           f"👥 Peers: {len(peers)}")
    await update.message.reply_text(msg)

# ========= /addpeer =========
@only_auth
async def cmd_addpeer(update, ctx):
    if not ctx.args:
        await update.message.reply_text("Uso: /addpeer <nombre>")
        return
    peer_name = ctx.args[0].strip()
    peers_json = "/configs/peers.json"
    peer_file = f"/configs/{peer_name}.conf"

    peers = {}
    if os.path.exists(peers_json):
        with open(peers_json) as f:
            peers = json.load(f)

    if peer_name in peers:
        await update.message.reply_text(f"⚠️ Peer '{peer_name}' ya existe.")
        return

    try:
        c = docker_client.containers.get(WG_CONTAINER_NAME)
        private = c.exec_run("wg genkey").output.decode().strip()
        public = c.exec_run(f"bash -c 'echo {private} | wg pubkey'").output.decode().strip()
        new_ip = f"10.6.0.{len(peers)+2}/32"
    except Exception as e:
        await update.message.reply_text(f"❌ Error generando claves: {e}")
        return

    peer_block = f"\n[Peer]\n# {peer_name}\nPublicKey = {public}\nAllowedIPs = {new_ip}\n"
    container_exec(f"bash -c 'echo \"{peer_block}\" >> {WG_CONFIG_PATH}'")

    server_pub = container_exec(f"wg show {WG_INTERFACE} public-key")[1].strip()
    endpoint = container_exec(f"grep Endpoint {WG_CONFIG_PATH} | head -1 | awk '{{print $3}}'")[1].strip() or "example.com:51820"

    conf = (
        f"[Interface]\nPrivateKey = {private}\nAddress = {new_ip}\nDNS = 1.1.1.1\n\n"
        f"[Peer]\nPublicKey = {server_pub}\nEndpoint = {endpoint}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
    )
    with open(peer_file, "w") as f:
        f.write(conf)

    peers[peer_name] = {"ip": new_ip, "public_key": public}
    with open(peers_json, "w") as f:
        json.dump(peers, f, indent=2)

    await update.message.reply_document(open(peer_file, "rb"), filename=f"{peer_name}.conf")
    await update.message.reply_text(f"✅ Peer '{peer_name}' creado con IP {new_ip}")

# ========= MONITOR =========
async def monitor(app):
    while True:
        if not container_ok():
            restarted = restart_wireguard()
            if STATE.get("notifications", True):
                for uid in AUTHORIZED_USERS:
                    try:
                        await app.bot.send_message(uid, "⚠️ WireGuard estaba caído y se ha reiniciado." if restarted else "❌ WireGuard caído y no se pudo reiniciar.")
                    except:
                        pass
        await asyncio.sleep(PING_INTERVAL)

# ========= MAIN =========
def main():
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("restart", cmd_restart))
    app.add_handler(CommandHandler("clients", cmd_clients))
    app.add_handler(CommandHandler("latency", cmd_latency))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("addpeer", cmd_addpeer))
    app.job_queue.run_repeating(lambda _: asyncio.create_task(monitor(app)), interval=PING_INTERVAL, first=10)
    log.info("WireGuardControlBot v2.1 iniciado.")
    app.run_polling()

if __name__ == "__main__":
    main()
