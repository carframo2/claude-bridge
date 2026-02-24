"""
features/notion_daemon.py
─────────────────────────
Plug-and-play feature que arranca un daemon en background.

Solo activo en el bridge PRIMARIO. Se autoidentifica via:
  - Variable de entorno IS_PRIMARY=true  (recomendado, setear solo en primary en Render)
  - O bien RENDER_EXTERNAL_URL conteniendo "claude-bridge-i43j" (fallback)

Funciones del daemon:
  1. Keep-alive: pinga al bridge SECUNDARIO cada DAEMON_PING_INTERVAL segundos
     para que Render no duerma ninguno de los dos.
  2. Notion polling: llama al relay en el bridge SECUNDARIO cada
     DAEMON_POLL_INTERVAL segundos. Si test_bridge tiene URL nueva,
     el relay la ejecuta y guarda respuesta en test_bridge_response.
     Si no hay novedad, el relay retorna rapido (keep-alive ligero).

Variables de entorno:
  IS_PRIMARY            "true" solo en el bridge principal
  DAEMON_SECONDARY_URL  URL del bridge secundario
                        (default: https://claude-bridge2.onrender.com)
  DAEMON_TOKEN          Token de autenticacion (default: kienzan)
  DAEMON_POLL_INTERVAL  Segundos entre polls (default: 10)
  DAEMON_PING_INTERVAL  Segundos entre pings keep-alive (default: 25)
  DAEMON_RESPONSE_PAGE  Page ID de test_bridge_response en Notion
                        (default: 310161400fd5816da2d1e85be9a0ffa7)

Instalacion: solo copiar este fichero en features/. No tocar nada mas.
"""

import os
import time
import threading
import logging

import requests
from flask import Blueprint, jsonify

log = logging.getLogger("notion_daemon")

# -- Soy el bridge primario? --------------------------------------------------
_is_primary_env = os.environ.get("IS_PRIMARY", "").lower() == "true"
_render_url     = os.environ.get("RENDER_EXTERNAL_URL", "")
IS_PRIMARY      = _is_primary_env or "claude-bridge-i43j" in _render_url

# -- Config -------------------------------------------------------------------
SECONDARY_URL = os.environ.get("DAEMON_SECONDARY_URL", "https://claude-bridge2.onrender.com")
TOKEN         = os.environ.get("DAEMON_TOKEN", "kienzan")
POLL_INTERVAL = int(os.environ.get("DAEMON_POLL_INTERVAL", "10"))
PING_INTERVAL = int(os.environ.get("DAEMON_PING_INTERVAL", "25"))
RESPONSE_PAGE = os.environ.get("DAEMON_RESPONSE_PAGE", "310161400fd5816da2d1e85be9a0ffa7")

RELAY_URL = (
    f"{SECONDARY_URL}/notion/relay_test_bridge"
    f"?run=1"
    f"&response_in_notion=1"
    f"&token={TOKEN}"
    f"&response_page_id={RESPONSE_PAGE}"
)

HEALTH_URL = f"{SECONDARY_URL}/health"

# -- Blueprint ----------------------------------------------------------------
bp = Blueprint("notion_daemon", __name__, url_prefix="/daemon")

_stats = {"polls": 0, "pings": 0, "errors": 0, "last_error": None}


@bp.route("/status", methods=["GET"])
def status():
    return jsonify({
        "ok": True,
        "is_primary": IS_PRIMARY,
        "daemon_running": IS_PRIMARY,
        "secondary_url": SECONDARY_URL,
        "poll_interval_s": POLL_INTERVAL,
        "ping_interval_s": PING_INTERVAL,
        "relay_url": RELAY_URL,
        "polls": _stats["polls"],
        "pings": _stats["pings"],
        "errors": _stats["errors"],
        "last_error": _stats["last_error"],
    })


# -- Daemon -------------------------------------------------------------------
def _poll_notion():
    try:
        url = f"{RELAY_URL}&_dc={int(time.time())}"
        r = requests.get(url, timeout=30)
        _stats["polls"] += 1
        log.debug(f"[daemon] poll #{_stats['polls']} -> {r.status_code}")
        _stats["last_error"] = None
    except Exception as e:
        _stats["errors"] += 1
        _stats["last_error"] = str(e)
        log.warning(f"[daemon] poll error: {e}")


def _ping():
    try:
        r = requests.get(HEALTH_URL, timeout=10)
        _stats["pings"] += 1
        log.debug(f"[daemon] ping #{_stats['pings']} -> {r.status_code}")
    except Exception as e:
        _stats["errors"] += 1
        _stats["last_error"] = str(e)
        log.warning(f"[daemon] ping error: {e}")


def _daemon_loop():
    log.info(f"[daemon] arrancado — poll cada {POLL_INTERVAL}s, ping cada {PING_INTERVAL}s -> {SECONDARY_URL}")
    last_ping = 0
    last_poll = 0

    while True:
        now = time.time()

        if now - last_poll >= POLL_INTERVAL:
            _poll_notion()
            last_poll = now

        if now - last_ping >= PING_INTERVAL:
            _ping()
            last_ping = now

        time.sleep(1)


def _start_daemon():
    t = threading.Thread(target=_daemon_loop, daemon=True, name="notion-daemon")
    t.start()
    log.info("[daemon] thread iniciado")


# -- Arranque automatico al importar ------------------------------------------
if IS_PRIMARY:
    _start_daemon()
else:
    log.info("[daemon] bridge secundario — daemon no arranca")
