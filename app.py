from flask import Flask, request, jsonify

app = Flask(__name__)

@app.get("/api/message")
def message():
    text = request.args.get("text", "")
    return jsonify({"content": f"En el servidor he procesado este texto: {text}"})

@app.get("/")
def home():
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
