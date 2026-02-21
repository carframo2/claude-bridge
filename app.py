from flask import Flask, request, jsonify
import os
import json
import requests

app = Flask(__name__)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
DEFAULT_MAX_TOKENS = int(os.environ.get("GROQ_MAX_TOKENS", "300"))
DEFAULT_TEMPERATURE = float(os.environ.get("GROQ_TEMPERATURE", "0.3"))

@app.get("/")
def home():
    return "OK"

@app.get("/api/message")
def message():
    text = request.args.get("text", "")
    if not text:
        return jsonify({"content": "Falta parámetro ?text=..."}), 400

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return jsonify({"content": "(sin GROQ_API_KEY)"}), 500

    payload = {
        "model": DEFAULT_MODEL,
        "messages": [{"role": "user", "content": text}],
        "max_tokens": DEFAULT_MAX_TOKENS,
        "temperature": DEFAULT_TEMPERATURE,
    }

    try:
        resp = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "claude-bridge/1.0",
            },
            data=json.dumps(payload),
            timeout=30,
        )

        # Si hay 400, devuelve el body de Groq para ver el motivo exacto
        if resp.status_code >= 400:
            return jsonify({
                "content": f"(Groq HTTP {resp.status_code}) {resp.text}"
            }), 500

        data = resp.json()
        out = data["choices"][0]["message"]["content"].strip()
        return jsonify({"content": out})

    except Exception as e:
        return jsonify({"content": f"(error llamando a Groq) {type(e).__name__}: {e}"}), 500

if __name__ == "__main__":
    # Render usa $PORT; gunicorn no usa este bloque, pero no molesta.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
