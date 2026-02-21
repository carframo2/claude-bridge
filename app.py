import requests
import os

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")


@app.get("/api/message")
def message():
    text = request.args.get("text", "")

    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": "llama3-70b-8192",
            "messages": [
                {"role": "user", "content": text}
            ]
        }
    )

    data = response.json()
    result = data["choices"][0]["message"]["content"]

    return jsonify({"content": result})
