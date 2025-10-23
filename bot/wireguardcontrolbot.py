#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import shlex
import subprocess
import threading
import time
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import glob
import json
import io
import ipaddress

import qrcode
from PIL import Image

import telegram
from telegram.ext import Updater, CommandHandler, Filters

# =========================
# Config por entorno
# =========================
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "").strip()
AUTHORIZED_USERS = {
    u.strip() for u in os.environ.get("AUTHORIZED_USERS", "").split(",") if u.strip()
}
WG_DOCKER_CONTAINER = os.environ.get("WG_DOCKER_CONTAINER", "wireguard").strip()
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0").strip()
PING_INTERVAL = int(os.environ.get("PING_INTERVAL", "600"))
WG_MTU = os.environ.get("WG_MTU", "1420").strip() or "1420"
WG_CLIENT_DNS = os.environ.get("WG_CLIENT_DNS", "1.1.1.1").strip() or "1.1.1.1"
WG_DEBUG_SCRIPT = os.environ.get("WG_DEBUG_SCRIPT", "/config/bin/wg-peer-debug.sh").strip() or "/config/bin/wg-peer-debug.sh"

ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID", "").strip()

# Cloudflare
USE_CLOUDFLARE = os.environ.get("USE_CLOUDFLARE", "false").lower() == "true"
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "").strip()
CF_ZONE_ID = os.environ.get("CF_ZONE_ID", "").strip()
CF_RECORD_NAME = os.environ.get("CF_RECORD_NAME", "").strip()

# Rutas montadas en el BOT (según docker-compose)
DEFAULT_WG_CONFIG = "/config/wg_confs/wg0.conf"


def _normalize_path(path: str) -> str:
    if not path:
        return ""
    return os.path.realpath(os.path.abspath(os.path.expanduser(path)))


_raw_server_conf = (os.environ.get("WG_CONFIG_PATH") or "").strip()
if not _raw_server_conf:
    _raw_server_conf = DEFAULT_WG_CONFIG
SERVER_WG0 = _normalize_path(_raw_server_conf) or _normalize_path(DEFAULT_WG_CONFIG)


def _candidate_server_paths(filename: str):
    seen = set()
    results = []

    env_override = os.environ.get(
        "WG_SERVER_PUBLICKEY_PATH" if filename == "publickey-server" else "WG_SERVER_PRIVATEKEY_PATH",
        ""
    ).strip()
    if env_override:
        path = _normalize_path(env_override)
        if path and path not in seen:
            results.append(path)
            seen.add(path)

    conf_dir = os.path.dirname(SERVER_WG0)
    if conf_dir:
        for candidate in [
            os.path.join(conf_dir, filename),
            os.path.join(os.path.dirname(conf_dir), filename),
            os.path.join(os.path.dirname(conf_dir), "server", filename),
        ]:
            path = _normalize_path(candidate)
            if path and path not in seen:
                results.append(path)
                seen.add(path)

    for candidate in [
        os.path.join("/config", filename),
        os.path.join("/config", "server", filename),
        os.path.join(os.getcwd(), "configs", "server", filename),
    ]:
        path = _normalize_path(candidate)
        if path and path not in seen:
            results.append(path)
            seen.add(path)

    return results


def _resolve_conf_dir() -> str:
    env_value = os.environ.get("WG_CLIENTS_DIR")
    if env_value is not None:
        env_value = env_value.strip()
        if env_value:
            return _normalize_path(env_value)

    candidate = os.path.dirname(SERVER_WG0)
    if candidate:
        return _normalize_path(candidate)

    return _normalize_path(os.path.dirname(DEFAULT_WG_CONFIG))

CONF_DIR = _resolve_conf_dir()

# =================
# Utilidades varias
# =================
def run(cmd, timeout=30):
    try:
        p = subprocess.run(
            cmd if isinstance(cmd, list) else shlex.split(cmd),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True
        )
        return p.stdout.strip(), p.stderr.strip(), p.returncode
    except Exception as e:
        return "", str(e), 1


def ensure_container_running():
    out, err, rc = run(["docker", "inspect", "-f", "{{.State.Running}}", WG_DOCKER_CONTAINER])
    if rc != 0:
        return False, f"Error consultando el contenedor {WG_DOCKER_CONTAINER}: {(err or out).strip()}"

    if out.strip().lower() == "true":
        return True, ""

    out, err, rc = run(["docker", "start", WG_DOCKER_CONTAINER])
    if rc != 0:
        return False, f"No pude iniciar {WG_DOCKER_CONTAINER}: {(err or out).strip()}"

    return True, ""


def ensure_wg_interface_ready():
    ok, message = ensure_container_running()
    if not ok:
        return False, message

    check_cmd = f"ip link show {shlex.quote(WG_INTERFACE)} >/dev/null 2>&1"
    _, _, rc = docker_exec(WG_DOCKER_CONTAINER, check_cmd)
    if rc == 0:
        return True, ""

    up_cmd = f"wg-quick up {shlex.quote(WG_INTERFACE)}"
    out, err, rc = docker_exec(WG_DOCKER_CONTAINER, up_cmd)
    if rc != 0:
        reason = (err or out or "wg-quick up falló").strip()
        return False, f"wg-quick up devolvió error: {reason}"

    return True, ""


def docker_exec(container, inner_cmd, timeout=30):
    cmd = ["docker", "exec", "-i", container, "sh", "-lc", inner_cmd]
    return run(cmd, timeout=timeout)

def is_authorized(user_id: int) -> bool:
    if not AUTHORIZED_USERS:
        return True
    return str(user_id) in AUTHORIZED_USERS

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ===========================
# WireGuard: lectura de estado
# ===========================
WG_PEER_BLOCK = re.compile(r"^peer:\s*(?P<key>[A-Za-z0-9+/=]+)$", re.M)
WG_LATEST  = re.compile(r"latest handshake:\s*(?P<text>.+)")
WG_TRANSFER= re.compile(r"transfer:\s*(?P<text>.+)")
WG_ENDPOINT= re.compile(r"endpoint:\s*(?P<text>.+)")
WG_ALLOWED = re.compile(r"allowed ips:\s*(?P<text>.+)")

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

def get_wg_show():
    out, err, rc = docker_exec(WG_DOCKER_CONTAINER, "wg show")
    if rc != 0:
        return f"Error ejecutando wg show: {err or out}".strip()
    return out or "(sin salida)"

def parse_connections(wg_text: str):
    lines = wg_text.splitlines()
    peers, current = [], []
    for line in lines:
        if line.startswith("peer: "):
            if current:
                peers.append("\n".join(current))
                current = []
        if line.strip():
            current.append(line)
    if current:
        peers.append("\n".join(current))

    result = []
    for block in peers:
        mkey = WG_PEER_BLOCK.search(block)
        if not mkey:
            continue
        key = mkey.group("key")
        endpoint = (WG_ENDPOINT.search(block).group("text") if WG_ENDPOINT.search(block) else "—")
        allowed  = (WG_ALLOWED.search(block).group("text")  if WG_ALLOWED.search(block)  else "—")
        latest   = (WG_LATEST.search(block).group("text")   if WG_LATEST.search(block)   else "—")
        transfer = (WG_TRANSFER.search(block).group("text") if WG_TRANSFER.search(block) else "—")
        result.append({"key": key, "endpoint": endpoint, "allowed": allowed, "latest": latest, "transfer": transfer})
    return result

# =======================
# Mapear nombres e IPs
# =======================
def list_client_files():
    if not os.path.isdir(CONF_DIR):
        return []
    return sorted(p for p in glob.glob(os.path.join(CONF_DIR, "*.conf")) if os.path.isfile(p))

def parse_client_address(conf_path):
    try:
        with open(conf_path, "r", encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"(?mi)^Address\s*=\s*([0-9./]+)", text)
        if m:
            ip = m.group(1).split("/")[0].strip()
            return ip
    except Exception:
        pass
    return ""

def build_name_map():
    """ip -> name usando los ficheros de cliente almacenados en CONF_DIR"""
    mapping = {}
    for p in list_client_files():
        name = os.path.splitext(os.path.basename(p))[0]
        ip = parse_client_address(p)
        if ip:
            mapping[ip] = name
    return mapping

def find_pubkey_by_allowed_ip(wg_peers, ip):
    for p in wg_peers:
        allowed = p.get("allowed", "")
        if ip and ip in allowed:
            return p.get("key", "")
    return ""

# =======================
# Info del servidor WG
# =======================
def get_server_info():
    """
    Devuelve (public_key, listen_port).
    """
    txt = get_wg_show()
    pub = ""
    port = ""

    if txt and not txt.startswith("Error ejecutando wg show"):
        m_pub = re.search(r"public key:\s*([A-Za-z0-9+/=]+)", txt)
        m_port = re.search(r"listening port:\s*(\d+)", txt)
        if m_pub:
            pub = m_pub.group(1)
        if m_port:
            port = m_port.group(1)

    if not port and os.path.exists(SERVER_WG0):
        try:
            with open(SERVER_WG0, "r", encoding="utf-8") as f:
                for line in f:
                    m = re.search(r"(?mi)^ListenPort\s*=\s*(\d+)", line)
                    if m:
                        port = m.group(1)
                        break
        except Exception:
            port = ""

    if not pub:
        for path in _candidate_server_paths("publickey-server"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                if content:
                    pub = content.splitlines()[0].strip()
                    if pub:
                        break
            except Exception:
                continue

    if not pub:
        for path in _candidate_server_paths("privatekey-server"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    priv = f.read().strip().splitlines()[0].strip()
            except Exception:
                priv = ""
            if not priv:
                continue
            pub_cmd = f"printf %s {shlex.quote(priv)} | wg pubkey"
            out, err, rc = docker_exec(WG_DOCKER_CONTAINER, pub_cmd)
            if rc == 0 and out.strip():
                pub = out.strip().splitlines()[0].strip()
                if pub:
                    break

    return pub, (port or "51820")

def get_server_network():
    """Devuelve (network, server_ip) a partir del Address del servidor."""
    default_network = ipaddress.ip_network("10.0.0.0/24")
    default_ip = ipaddress.ip_address("10.0.0.1")

    try:
        with open(SERVER_WG0, "r", encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"(?mi)^Address\s*=\s*([0-9.:/]+)", text)
        if m:
            iface = ipaddress.ip_interface(m.group(1).strip())
            return iface.network, iface.ip
    except Exception:
        pass

    return default_network, default_ip

def find_next_free_ip():
    """
    Busca una IP libre dentro de la /24:
    - Revisa wg show (AllowedIPs) y ficheros .conf existentes
    - Empieza en .2 (asumimos .1 es servidor)
    """
    network, server_ip = get_server_network()
    used = {str(server_ip)}

    # wg show
    for p in parse_connections(get_wg_show()):
        m = IP_RE.search(p.get("allowed", ""))
        if m:
            used.add(m.group(1))

    # conf locales
    for p in list_client_files():
        ip = parse_client_address(p)
        if ip:
            used.add(ip)

    for host in network.hosts():
        candidate = str(host)
        if candidate not in used:
            return candidate
    return ""

# =======================
# Render visual del estado
# =======================
def human_last_seen(latest: str):
    t = (latest or "").lower().strip()
    if not t or t in ("—", "never"):
        return "🔴", "sin conexión"
    if "now" in t or "ahora" in t:
        return "🟢", "ahora"

    mins = secs = 0
    h = re.search(r"(\d+)\s*hour", t);   mins += (int(h.group(1))*60 if h else 0)
    m = re.search(r"(\d+)\s*minute", t); mins += (int(m.group(1)) if m else 0)
    s = re.search(r"(\d+)\s*second", t); secs += (int(s.group(1)) if s else 0)
    seconds = mins*60 + secs or (30 if any(x in t for x in ["second","minute","hour"]) else 999999)

    if seconds <= 120:  return "🟢", f"hace ~{seconds}s"
    if seconds <= 900:  return "🟡", f"hace ~{seconds//60}m"
    return "🔴", f"hace ~{max(1, seconds//60)}m"

def summarize_visual(wg_text: str, public_ip: str, domain: str, started_action: str) -> str:
    peers = parse_connections(wg_text)
    ip2name = build_name_map()

    active, recent, inactive = [], [], []
    for p in peers:
        m = IP_RE.search(p.get("allowed",""))
        ip = m.group(1) if m else ""
        name = ip2name.get(ip, None)
        display = f"`{name}`" if name else f"`{p['key'][:10]}…`"
        emoji, seen = human_last_seen(p["latest"])
        line = f"{emoji} {display} — {seen}"
        if emoji == "🟢": active.append(line)
        elif emoji == "🟡": recent.append(line)
        else: inactive.append(line)

    parts = []
    parts.append(f"✅ *WireGuard {started_action}*")
    parts.append(f"📅 {now_str()}")
    if public_ip: parts.append(f"🌐 IP pública: [{public_ip}](https://{public_ip})")
    if domain:    parts.append(f"🔗 Dominio: [{domain}](https://{domain})")

    parts.append(f"\n📡 *Peers configurados:* {len(peers)}")
    if active:
        parts.append(f"🟢 *Activos ({len(active)})*")
        parts.extend([f"• {x}" for x in active])
    if recent:
        parts.append(f"🟡 *Recientes ({len(recent)})*")
        parts.extend([f"• {x}" for x in recent])
    if inactive:
        parts.append(f"🔴 *Inactivos ({len(inactive)})*")
        parts.extend([f"• {x}" for x in inactive])
    return "\n".join(parts)

# =========================
# Cloudflare & IP pública
# =========================
def http_json(method, url, headers=None, body=None, timeout=20):
    req = Request(url, method=method)
    if headers:
        for k,v in (headers or {}).items(): req.add_header(k,v)
    data = body.encode("utf-8") if body is not None else None
    try:
        with urlopen(req, data=data, timeout=timeout) as resp:
            txt = resp.read().decode("utf-8")
            try: return json.loads(txt), None
            except Exception: return {"raw": txt}, None
    except HTTPError as e:
        try: return json.loads(e.read().decode("utf-8")), f"HTTP {e.code}"
        except Exception: return None, f"HTTP {e.code}"
    except URLError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)

def get_public_ip():
    try:
        data, _ = http_json("GET", "https://api.ipify.org?format=json")
        if data and "ip" in data: return data["ip"]
    except Exception: pass
    try:
        data, _ = http_json("GET", "https://ifconfig.me")
        if data and "raw" in data: return data["raw"].strip()
    except Exception: pass
    return ""

def cf_get_record_ip():
    if not (CF_API_TOKEN and CF_ZONE_ID and CF_RECORD_NAME): return None, ""
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records?type=A&name={CF_RECORD_NAME}"
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    data, _ = http_json("GET", url, headers=headers)
    if not data or not data.get("success"): return None, ""
    result = data.get("result") or []
    if not result: return None, ""
    rec = result[0]
    return rec.get("id"), rec.get("content", "")

def cf_update_record_ip(record_id, new_ip):
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{record_id}"
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    body = json.dumps({"type": "A", "name": CF_RECORD_NAME, "content": new_ip, "ttl": 120, "proxied": False})
    data, _ = http_json("PUT", url, headers=headers, body=body)
    return bool(data and data.get("success"))

# =====================
# Generación de peers
# =====================
def gen_keypair():
    priv, err, rc = docker_exec(WG_DOCKER_CONTAINER, "wg genkey")
    if rc != 0 or not priv:
        return "", ""
    priv = priv.strip()
    pub_cmd = f"printf %s {shlex.quote(priv)} | wg pubkey"
    pub, err2, rc2 = docker_exec(WG_DOCKER_CONTAINER, pub_cmd)
    if rc2 != 0 or not pub:
        return "", ""
    return priv, pub.strip()

def create_client_conf(name, client_ip, server_pub, endpoint, port, dns=None, mtu=None):
    dns = dns or WG_CLIENT_DNS
    mtu = mtu or WG_MTU
    return (
        "[Interface]\n"
        f"Address = {client_ip}/32\n"
        f"PrivateKey = {{CLIENT_PRIVATE}}\n"
        f"DNS = {dns}\n"
        f"MTU = {mtu}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {endpoint}:{port}\n"
        "PersistentKeepalive = 25\n"
    )

def save_qr_and_conf(name, text_conf):
    # Guarda .conf en disco
    conf_path = os.path.join(CONF_DIR, f"{name}.conf")
    with open(conf_path, "w", encoding="utf-8") as f:
        f.write(text_conf)
    try:
        os.chmod(conf_path, 0o600)
    except Exception:
        pass

    # Genera QR en memoria y en disco
    img = qrcode.make(text_conf)
    png_path = os.path.join(CONF_DIR, f"{name}.png")
    img.save(png_path)

    # Stream para enviar por Telegram
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    bio.seek(0)
    return conf_path, png_path, bio

def ensure_dir():
    os.makedirs(CONF_DIR, exist_ok=True)

def next_peer_name():
    existing = {os.path.splitext(os.path.basename(p))[0] for p in list_client_files()}
    i = 1
    while True:
        n = f"peer{i}"
        if n not in existing:
            return n
        i += 1

# =====================
# Comandos de Telegram
# =====================
def cmd_help(update, context):
    if not is_authorized(update.effective_user.id):
        return
    text = (
        "🤖 *WireGuardControlBot — Comandos*\n\n"
        "/start — Resumen *visual*\n"
        "/summary — Resumen *visual* sin tocar contenedor\n"
        "/status — `wg show` crudo\n"
        "/connections — Peers por estado (emoji) con nombre si existe\n"
        "/listpeers — Nombre ↔ IP ↔ PublicKey (corto)\n"
        "/addpeer [nombre] — Crear peer automático (si no hay nombre usa peerN)\n"
        "/delpeer <nombre> — Eliminar peer por nombre\n"
        "/stop — Parar WireGuard\n"
        "/restart — Reiniciar WireGuard\n"
        "/rebootbot — Reiniciar este bot\n"
        "/logs — Últimos logs del contenedor WireGuard\n"
        "/uptime — Uptime aproximado\n"
        "/rebootpi — Intentar reiniciar la Raspberry\n"
        "/debugpeer <peer> — Diagnóstico rápido (handshake/NAT)\n"
    )
    context.bot.send_message(chat_id=update.effective_chat.id, text=text, parse_mode="Markdown")

def cmd_status(update, context):
    if not is_authorized(update.effective_user.id):
        return
    wg = get_wg_show()
    context.bot.send_message(chat_id=update.effective_chat.id, text=f"```\n{wg}\n```", parse_mode="Markdown")

def cmd_summary(update, context):
    if not is_authorized(update.effective_user.id):
        return
    wg_status = get_wg_show()
    pub_ip = get_public_ip()
    domain = CF_RECORD_NAME if CF_RECORD_NAME else ""
    visual = summarize_visual(wg_status, pub_ip, domain, "en marcha")
    context.bot.send_message(chat_id=update.effective_chat.id, text=visual, parse_mode="Markdown")

def cmd_connections(update, context):
    if not is_authorized(update.effective_user.id):
        return
    wg_text = get_wg_show()
    peers = parse_connections(wg_text)
    ip2name = build_name_map()
    if not peers:
        context.bot.send_message(chat_id=update.effective_chat.id, text="No hay peers configurados.")
        return
    lines = ["📡 *Peers / Conexiones*"]
    for i, p in enumerate(peers, 1):
        allowed = p.get("allowed", "")
        m = IP_RE.search(allowed); ip = m.group(1) if m else ""
        name = ip2name.get(ip, "")
        emoji, seen = human_last_seen(p["latest"])
        who = f"`{name}`" if name else f"`{p['key'][:10]}…`"
        ip_hint = f"({ip})" if ip else ""
        lines.append(f"{i}. {emoji} {who} — {seen} {ip_hint}")
    context.bot.send_message(chat_id=update.effective_chat.id, text="\n".join(lines), parse_mode="Markdown")

def cmd_listpeers(update, context):
    if not is_authorized(update.effective_user.id):
        return
    wg_text = get_wg_show()
    peers = parse_connections(wg_text)
    ip2name = build_name_map()
    if not peers:
        context.bot.send_message(chat_id=update.effective_chat.id, text="No hay peers configurados.")
        return
    lines = ["📄 *Nombre ↔ IP ↔ PublicKey (corto)*"]
    for p in peers:
        m = IP_RE.search(p.get("allowed","")); ip = m.group(1) if m else ""
        name = ip2name.get(ip, "—")
        shortkey = p["key"][:14] + "…"
        lines.append(f"• `{name}`  —  {ip or '—'}  —  `{shortkey}`")
    context.bot.send_message(chat_id=update.effective_chat.id, text="\n".join(lines), parse_mode="Markdown")

def cmd_addpeer(update, context):
    if not is_authorized(update.effective_user.id):
        return
    ensure_dir()

    ready, error_msg = ensure_wg_interface_ready()
    if not ready:
        context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ No pude preparar la interfaz `{WG_INTERFACE}`: {error_msg}",
            parse_mode="Markdown",
        )
        return

    # Nombre
    name = (context.args[0].strip() if context.args else "").lower()
    if not name:
        name = next_peer_name()
    if not re.match(r"^[a-z0-9_-]{1,32}$", name):
        context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Nombre inválido. Usa [a-z0-9_-], máx 32 chars.")
        return
    if os.path.exists(os.path.join(CONF_DIR, f"{name}.conf")):
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"❌ Ya existe un peer llamado `{name}`.", parse_mode="Markdown")
        return

    # IP libre
    client_ip = find_next_free_ip()
    if not client_ip:
        context.bot.send_message(chat_id=update.effective_chat.id, text="❌ No encontré IP libre en la subred.")
        return

    # Claves
    priv, pub = gen_keypair()
    if not priv or not pub:
        context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Error generando claves.")
        return

    # Info servidor
    server_pub, listen_port = get_server_info()
    if not server_pub:
        context.bot.send_message(chat_id=update.effective_chat.id, text="❌ No pude leer la clave pública del servidor.")
        return
    endpoint = CF_RECORD_NAME or get_public_ip()
    if not endpoint:
        context.bot.send_message(chat_id=update.effective_chat.id, text="❌ No pude determinar endpoint (dominio/IP).")
        return

    # 1) Añadir al servidor (en caliente)
    add_cmd = f"wg set {WG_INTERFACE} peer {shlex.quote(pub)} allowed-ips {client_ip}/32"
    out, err, rc = docker_exec(WG_DOCKER_CONTAINER, add_cmd)
    if rc != 0:
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"❌ Error añadiendo peer al servidor:\n{err or out}")
        return
    docker_exec(WG_DOCKER_CONTAINER, f"wg-quick save {WG_INTERFACE} || true")

    # 2) Crear .conf cliente
    conf_tpl = create_client_conf(name, client_ip, server_pub, endpoint, listen_port)
    conf_text = conf_tpl.replace("{CLIENT_PRIVATE}", priv)
    conf_path, png_path, png_stream = save_qr_and_conf(name, conf_text)

    try:
        if os.path.exists(SERVER_WG0):
            with open(SERVER_WG0, "a", encoding="utf-8") as f:
                f.write(
                    "\n[Peer]\n"
                    f"PublicKey = {pub}\n"
                    f"AllowedIPs = {client_ip}/32\n"
                )
    except Exception:
        pass

    # 3) Enviar resultado
    msg = (
        f"✅ *Peer creado:* `{name}`\n"
        f"IP: `{client_ip}`\n"
        f"PublicKey: `{pub}`\n"
        f"Endpoint: `{endpoint}:{listen_port}`"
    )
    context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="Markdown")
    # QR
    context.bot.send_photo(chat_id=update.effective_chat.id, photo=png_stream, caption=f"QR para `{name}`")
    # .conf
    with open(conf_path, "rb") as f:
        context.bot.send_document(chat_id=update.effective_chat.id, document=f, filename=os.path.basename(conf_path))


def cmd_debugpeer(update, context):
    if not is_authorized(update.effective_user.id):
        return
    if not context.args:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Uso: /debugpeer <nombre|ip>")
        return

    target = context.args[0].strip()
    if not target:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Uso: /debugpeer <nombre|ip>")
        return

    ready, error_msg = ensure_wg_interface_ready()
    if not ready:
        context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ No pude preparar la interfaz `{WG_INTERFACE}`: {error_msg}",
            parse_mode="Markdown",
        )
        return

    script = shlex.quote(WG_DEBUG_SCRIPT)
    argument = shlex.quote(target)
    out, err, rc = docker_exec(WG_DOCKER_CONTAINER, f"{script} {argument}")
    text = out or err or "(sin salida)"
    if rc != 0:
        text = f"Error {rc}:\n{text}"
    if len(text) > 3900:
        text = text[:3900] + "…"
    context.bot.send_message(chat_id=update.effective_chat.id, text=f"```\n{text}\n```", parse_mode="Markdown")


def cmd_delpeer(update, context):
    if not is_authorized(update.effective_user.id):
        return
    if not context.args:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Uso: /delpeer <nombre>")
        return
    name = context.args[0]
    client_path = os.path.join(CONF_DIR, f"{name}.conf")
    if not os.path.exists(client_path):
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"❌ No existe {client_path}")
        return

    ready, error_msg = ensure_wg_interface_ready()
    if not ready:
        context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ No pude preparar la interfaz `{WG_INTERFACE}`: {error_msg}",
            parse_mode="Markdown",
        )
        return

    # 1) IP del peer
    ip = parse_client_address(client_path)
    if not ip:
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"❌ No pude obtener la IP de {name}.conf")
        return

    # 2) PublicKey desde wg show
    wg_text = get_wg_show()
    peers = parse_connections(wg_text)
    pub = find_pubkey_by_allowed_ip(peers, ip)

    # 3) Quitar del servidor y guardar
    if pub:
        docker_exec(WG_DOCKER_CONTAINER, f"wg set {WG_INTERFACE} peer {shlex.quote(pub)} remove || true")
        docker_exec(WG_DOCKER_CONTAINER, f"wg-quick save {WG_INTERFACE} || true")

    # 4) Borrar ficheros
    try: os.remove(client_path)
    except Exception: pass
    try:
        png = os.path.join(CONF_DIR, f"{name}.png")
        if os.path.exists(png): os.remove(png)
    except Exception: pass

    # 5) Limpiar [Peer] de SERVER_WG0 por AllowedIPs
    try:
        if os.path.exists(SERVER_WG0):
            with open(SERVER_WG0, "r") as f: text = f.read()
            pattern = r"(?ms)^\[Peer\][^\[]*?AllowedIPs\s*=\s*%s/32\s*$" % re.escape(ip)
            new_text = re.sub(pattern, "", text)
            if new_text != text:
                with open(SERVER_WG0, "w") as f: f.write(new_text)
    except Exception:
        pass

    context.bot.send_message(chat_id=update.effective_chat.id, text=f"🗑️ Peer `{name}` eliminado (IP {ip}).", parse_mode="Markdown")

def cmd_start(update, context):
    if not is_authorized(update.effective_user.id):
        return
    out, err, rc = run(["docker", "inspect", "-f", "{{.State.Running}}", WG_DOCKER_CONTAINER])
    running_already = (rc == 0 and out.strip().lower() == "true")
    started_action = "en marcha" if running_already else "iniciado"
    if not running_already:
        out, err, rc = run(["docker", "start", WG_DOCKER_CONTAINER])
        if rc != 0:
            context.bot.send_message(chat_id=update.effective_chat.id, text=f"❌ *Error al iniciar WireGuard*\n\n{err or out}", parse_mode="Markdown")
            return
    wg_status = get_wg_show()
    pub_ip = get_public_ip()
    domain = CF_RECORD_NAME if CF_RECORD_NAME else ""
    visual = summarize_visual(wg_status, pub_ip, domain, started_action)
    context.bot.send_message(chat_id=update.effective_chat.id, text=visual, parse_mode="Markdown")

def cmd_stop(update, context):
    if not is_authorized(update.effective_user.id):
        return
    out, err, rc = run(["docker", "inspect", "-f", "{{.State.Running}}", WG_DOCKER_CONTAINER])
    if rc == 0 and out.strip().lower() == "false":
        context.bot.send_message(chat_id=update.effective_chat.id, text="🟡 *WireGuard ya estaba detenido*", parse_mode="Markdown")
        return
    out, err, rc = run(["docker", "stop", WG_DOCKER_CONTAINER])
    msg = "🛑 *WireGuard detenido correctamente*" if rc == 0 else f"❌ *Error al detener WireGuard*\n\n{err or out}"
    context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="Markdown")

def cmd_restart(update, context):
    if not is_authorized(update.effective_user.id):
        return
    context.bot.send_message(chat_id=update.effective_chat.id, text="🔄 *Reiniciando WireGuard...*", parse_mode="Markdown")
    out, err, rc = run(["docker", "restart", WG_DOCKER_CONTAINER])
    if rc == 0:
        wg_status = get_wg_show()
        pub_ip = get_public_ip()
        domain = CF_RECORD_NAME if CF_RECORD_NAME else ""
        visual = summarize_visual(wg_status, pub_ip, domain, "reiniciado")
        context.bot.send_message(chat_id=update.effective_chat.id, text=visual, parse_mode="Markdown")
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"❌ *Error al reiniciar WireGuard*\n\n{err or out}", parse_mode="Markdown")

def cmd_rebootbot(update, context):
    if not is_authorized(update.effective_user.id):
        return
    this = os.environ.get("HOSTNAME", "wireguardcontrolbot").strip()
    context.bot.send_message(chat_id=update.effective_chat.id, text=f"Reiniciando bot `{this}`...", parse_mode="Markdown")
    run(["docker", "restart", this])

def cmd_logs(update, context):
    if not is_authorized(update.effective_user.id):
        return
    out, err, rc = run(["docker", "logs", "--tail", "120", WG_DOCKER_CONTAINER])
    text = out or err or "(sin logs)"
    if len(text) > 3800: text = "…(recortado)\n" + text[-3500:]
    context.bot.send_message(chat_id=update.effective_chat.id, text=f"```\n{text}\n```", parse_mode="Markdown")

def cmd_uptime(update, context):
    if not is_authorized(update.effective_user.id):
        return
    out, err, rc = run(["cat", "/proc/uptime"])
    if rc != 0 or not out:
        context.bot.send_message(chat_id=update.effective_chat.id, text="No pude leer el uptime.")
        return
    try: seconds = float(out.split()[0])
    except Exception: seconds = 0.0
    td = timedelta(seconds=int(seconds))
    context.bot.send_message(chat_id=update.effective_chat.id, text=f"⏱️ *Uptime aproximado del sistema/bot:* {td}", parse_mode="Markdown")

def cmd_rebootpi(update, context):
    if not is_authorized(update.effective_user.id):
        return
    out, err, rc = run(["sh", "-lc", "reboot || shutdown -r now || systemctl reboot || echo 'Sin permisos para reiniciar'"])
    if rc == 0 and not err and "Sin permisos" not in (out or ""):
        msg = "♻️ *Intento de reinicio enviado.* Si el sistema tiene permisos, se reiniciará."
    else:
        msg = "❌ *No tengo permisos para reiniciar la Raspberry desde el contenedor.*"
    context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="Markdown")

# ===========================
# Monitorización y alertas
# ===========================
def send_admin(bot, text, markdown=False):
    if not ADMIN_CHAT_ID: return
    kwargs = {"chat_id": int(ADMIN_CHAT_ID), "text": text}
    if markdown: kwargs["parse_mode"] = "Markdown"
    bot.send_message(**kwargs)

def get_public_ip_safe():
    try: return get_public_ip()
    except Exception: return ""

def monitor_loop(bot: telegram.Bot):
    last_running = None
    last_handshake_digest = ""
    last_public_ip = ""
    last_status_change_time = 0
    last_uptime = 0

    public_ip = get_public_ip_safe()
    last_public_ip = public_ip or ""
    msg = f"✅ *Bot iniciado*\nFecha: {now_str()}\nIP pública: [{public_ip or '—'}](https://{public_ip or ''})"
    if CF_RECORD_NAME: msg += f"\nDominio: [{CF_RECORD_NAME}](https://{CF_RECORD_NAME})"
    send_admin(bot, msg, markdown=True)

    while True:
        try:
            # 1) Reinicio de Pi
            out, err, rc = run(["cat", "/proc/uptime"])
            if rc == 0 and out:
                try: current_uptime = float(out.split()[0])
                except Exception: current_uptime = 0.0
                if last_uptime and current_uptime < last_uptime:
                    send_admin(bot, f"⚠️ *Raspberry Pi se ha reiniciado*\nFecha: {now_str()}\nUptime actual: {int(current_uptime/60)} min", markdown=True)
                last_uptime = current_uptime

            # 2) Estado WireGuard
            out, err, rc = run(["docker", "inspect", "-f", "{{.State.Running}}", WG_DOCKER_CONTAINER])
            running = (out.strip().lower() == "true") if rc == 0 else False
            now_ts = time.time()
            if last_running is None:
                last_running = running
            elif running != last_running:
                last_running = running
                if running:
                    if now_ts - last_status_change_time < 60:
                        send_admin(bot, "🔄 *WireGuard se ha reiniciado automáticamente*", markdown=True)
                    else:
                        send_admin(bot, "🟢 *WireGuard se ha iniciado automáticamente*", markdown=True)
                else:
                    send_admin(bot, "🔴 *WireGuard se ha detenido*", markdown=True)
                last_status_change_time = now_ts

            # 3) Cambios en handshakes
            wg_text = get_wg_show()
            digest = ""
            for p in parse_connections(wg_text):
                digest += f"{p['key']}|{p['latest']}|"
            if digest and digest != last_handshake_digest:
                if last_handshake_digest != "":
                    send_admin(bot, "🔔 Cambios en conexiones (handshakes). Usa /connections para ver detalle.")
                last_handshake_digest = digest

            # 4) IP + Cloudflare
            if USE_CLOUDFLARE and CF_API_TOKEN and CF_ZONE_ID and CF_RECORD_NAME:
                current_ip = get_public_ip_safe()
                if current_ip and current_ip != last_public_ip:
                    rec_id, rec_ip = cf_get_record_ip()
                    if rec_id and rec_ip != current_ip:
                        ok = cf_update_record_ip(rec_id, current_ip)
                        if ok:
                            send_admin(bot, f"⚠️ *IP pública cambiada* y Cloudflare actualizado ✅\nNueva IP: `{current_ip}`\nRegistro: `{CF_RECORD_NAME}`", markdown=True)
                        else:
                            send_admin(bot, f"❌ Error actualizando Cloudflare.\nIP deseada: {current_ip}\nRegistro: {CF_RECORD_NAME}")
                    last_public_ip = current_ip

        except Exception as e:
            send_admin(bot, f"Monitor error: {e}")
        finally:
            time.sleep(max(60, min(PING_INTERVAL, 600)))

# =======
# Main
# =======
def main():
    if not TELEGRAM_TOKEN:
        print("ERROR: TELEGRAM_TOKEN no definido")
        return

    updater = Updater(token=TELEGRAM_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("help",        cmd_help,        filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("status",      cmd_status,      filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("summary",     cmd_summary,     filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("connections", cmd_connections, filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("listpeers",   cmd_listpeers,   filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("addpeer",     cmd_addpeer,     filters=Filters.chat_type.private, pass_args=True))
    dp.add_handler(CommandHandler("delpeer",     cmd_delpeer,     filters=Filters.chat_type.private, pass_args=True))
    dp.add_handler(CommandHandler("start",       cmd_start,       filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("stop",        cmd_stop,        filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("restart",     cmd_restart,     filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("rebootbot",   cmd_rebootbot,   filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("logs",        cmd_logs,        filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("uptime",      cmd_uptime,      filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("rebootpi",    cmd_rebootpi,    filters=Filters.chat_type.private))
    dp.add_handler(CommandHandler("debugpeer",   cmd_debugpeer,   filters=Filters.chat_type.private, pass_args=True))

    t = threading.Thread(target=monitor_loop, args=(updater.bot,), daemon=True)
    t.start()

    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
