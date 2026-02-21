@app.get("/api/message")
def message():
    text = request.args.get("text", "")

    # Si aún no tienes GROQ_API_KEY, esto evita crash
    if not os.environ.get("GROQ_API_KEY"):
        return jsonify({"content": f"(sin GROQ_API_KEY) recibido: {text}"}), 200

    resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {os.environ['GROQ_API_KEY']}"},
        json={
            "model": "llama3-8b-8192",
            "messages": [{"role": "user", "content": text}],
            "temperature": 0
        },
        timeout=30
    )
    data = resp.json()
    return jsonify({"content": data["choices"][0]["message"]["content"]})
