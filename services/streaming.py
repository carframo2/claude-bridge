import json

def sse_from_openai_compatible(resp):
    try:
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw:
                continue
            line = raw.strip()
            if not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
                delta = obj["choices"][0].get("delta", {}).get("content")
                if delta:
                    yield delta
            except Exception:
                continue
    finally:
        try:
            resp.close()
        except Exception:
            pass
