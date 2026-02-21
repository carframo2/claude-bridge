from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.get("/")
def home():
    return "OK"

@app.get("/api/message")
def message():
    text = request.args.get("text", "")
    return jsonify({"content": f"En el servidor he procesado este texto: {text}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
