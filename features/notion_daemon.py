"""
features/notion_daemon.py
─────────────────────────
Plug-and-play Blueprint que arranca un daemon en background al importarse.

Funciones:
  1. Keep-alive: llama al propio bridge cada PING_INTERVAL segundos para
     que Render no lo ponga a dormir.
  2. Notion polling: llama al endpoint relay de Notion cada POLL_INTERVAL
     segundos. Si hay una URL nueva en test_bridge, el relay la ejecuta y
     guarda la respuesta en test_bridge_response.
     (Si no hay mensaje nuevo, el relay no hace nada → keep-alive ligero)

Configuración por variables de entorno:
  DAEMON_BRIDGE_URL     URL base del propio bridge
                        (default: http://localhost:5000)
  DAEMON_TOKEN          Token para autenticar las llamadas al relay
                        (default: kienzan)
  DAEMON_POLL_INTERVAL  Segundos entre polls de Notion (default: 10)
  DAEMON_PING_INTERVAL  Segundos entre pings keep-alive (default: 25)
  DAEMON_RESPONSE_PAGE  ID de la página de respuesta en Notion
                        (default: 310161400fd5816da2d1e85be9a0ffa7)

Registro en factory.py (única línea añadir):
  from features.notion_daemon import bp as notion_daemon_bp
  app.register_blueprint(notion_daemon_bp)
"""

import os
import time
import threading
import logging

import requests
from flask import Blueprint, jsonify

log = logging.getLogger("notion_daemon")

# ── Config ────────────────────────────────────────────────────────────────────
BRIDGE_URL      = os.environ.get("DAEMON_BRIDGE_URL", "http://localhost:5000")
TOKEN           = os.environ.get("DAEMON_TOKEN", "kienzan")
POLL_INTERVAL   = int(os.environ.get("DAEMON_POLL_INTERVAL", "10"))
PING_INTERVAL   = int(os.environ.get("DAEMON_PING_INTERVAL", "25"))
RESPONSE_PAGE   = os.environ.get(
    "DAEMON_RESPONSE_PAGE",
    "310161400fd5816da2d1e85be9a0ffa7"
)

# URL del relay — al llamarlo sin mensaje nuevo hace solo keep-alive
RELAY_URL = (
    f"{BRIDGE_URL}/notion/relay_test_bridge"
    f"?run=1"
    f"&response_in_notion=1"
    f"&token={TOKEN}"
    f"&response_page_id={RESPONSE_PAGE}"
)

# ── Blueprint (endpoints de control) ─────────────────────────────────────────
bp = Blueprint("notion_daemon", __name__, url_prefix="/daemon")


@bp.route("/status", methods=["GET"])
def status():
    """Devuelve el estado actual del daemon."""
    return jsonify({
        "ok": True,
        "daemon": "running",
        "poll_interval_s": POLL_INTERVAL,
        "ping_interval_s": PING_INTERVAL,
        "relay_url": RELAY_URL,
    })


# ── Daemon ────────────────────────────────────────────────────────────────────
_poll_count   = 0
_ping_count   = 0
_last_error   = None


def _poll_notion():
    """
    Llama al relay de Notion.
    - Si test_bridge tiene URL nueva → el relay la ejecuta y guarda respuesta
    - Si no hay novedad → el relay devuelve rápido (keep-alive ligero)
    Añadimos &_dc=<timestamp> para que cada llamada sea distinta y no se
    cachee en Anthropic (aunque aquí lo hace el servidor, no Claude).
    """
    global _poll_count, _last_error
    try:
        url = f"{RELAY_URL}&_dc={int(time.time())}"
        r = requests.get(url, timeout=30)
        _poll_count += 1
        log.debug(f"[daemon] poll #{_poll_count} → {r.status_code}")
        _last_error = None
    except Exception as e:
        _last_error = str(e)
        log.warning(f"[daemon] poll error: {e}")


def _ping():
    """Ping keep-alive al propio bridge."""
    global _ping_count, _last_error
    try:
        r = requests.get(f"{BRIDGE_URL}/health", timeout=10)
        _ping_count += 1
        log.debug(f"[daemon] ping #{_ping_count} → {r.status_code}")
    except Exception as e:
        _last_error = str(e)
        log.warning(f"[daemon] ping error: {e}")


def _daemon_loop():
    log.info(f"[daemon] arrancado — poll cada {POLL_INTERVAL}s, ping cada {PING_INTERVAL}s")
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

        time.sleep(1)  # granularidad 1s para respetar ambos intervalos


def _start_daemon():
    t = threading.Thread(target=_daemon_loop, daemon=True, name="notion-daemon")
    t.start()
    log.info("[daemon] thread iniciado")


# ── Arranque automático al importar ──────────────────────────────────────────
_start_daemon()
