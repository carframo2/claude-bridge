from flask import Flask, request, jsonify
import os
import requests

app = Flask(__name__)

@app.get("/")
def home():
    return "OK"

@app.get("/api/message")
def message():
    text = request.args.get("text", "")

    # Si aún no has puesto la key en Render, no crashea:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return jsonify({"content": f"(sin GROQ_API_KEY) En el servidor he procesado este texto: {text}"})

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": os.environ.get("GROQ_MODEL", "llama3-8b-8192"),
                "messages": [{"role": "user", "content": text}],
                "temperature": 0,
                "max_tokens": int(os.environ.get("GROQ_MAX_TOKENS", "256")),
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        out = data["choices"][0]["message"]["content"]
        return jsonify({"content": out})
    except Exception as e:
        return jsonify({"content": f"(error llamando a Groq) {type(e).__name__}: {e}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
