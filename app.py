from flask import Flask, request, jsonify
import os
import json
import requests

app = Flask(__name__)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

DEFAULT_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
MAX_TOKENS = int(os.environ.get("GROQ_MAX_TOKENS", "600"))
TEMPERATURE = float(os.environ.get("GROQ_TEMPERATURE", "0.3"))

# Opcional: limitar modelos permitidos (seguridad)
ALLOWED_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
]

def call_groq(prompt, model=None):

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return "(sin GROQ_API_KEY)"

    chosen_model = model or DEFAULT_MODEL

    # Seguridad opcional
    if chosen_model not in ALLOWED_MODELS:
        return f"(modelo no permitido: {chosen_model})"

    payload = {
        "model": chosen_model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
    }

    resp = requests.post(
        GROQ_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        data=json.dumps(payload),
        timeout=60,
    )

    if resp.status_code >= 400:
        return f"(Groq HTTP {resp.status_code}) {resp.text}"

    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


@app.route("/api/message", methods=["GET", "POST"])
def message():

    # -------- GET --------
    if request.method == "GET":
        text = request.args.get("text", "")
        model = request.args.get("model")
        return jsonify({"content": call_groq(text, model)})

    # -------- POST JSON --------
    if request.is_json:
        data = request.get_json()
        text = data.get("text", "")
        context = data.get("context", "")
        model = data.get("model")

        prompt = f"{text}\n\nCONTEXTO:\n{context}" if context else text

        return jsonify({"content": call_groq(prompt, model)})

    # -------- POST multipart --------
    text = request.form.get("text", "")
    model = request.form.get("model")
    file = request.files.get("file")

    if file:
        content = file.read().decode("utf-8", errors="replace")[:15000]
        prompt = f"{text}\n\nCONTEXTO:\n{content}"
        return jsonify({"content": call_groq(prompt, model)})

    return jsonify({"content": "Formato no soportado"}), 400


@app.route("/")
def home():
    return "SUPER BRIDGE ONLINE 🔥"
