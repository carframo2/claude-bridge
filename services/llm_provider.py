import os, json
import requests
from typing import Optional, Tuple

def call_openai_compatible(
    base_url: str,
    api_key: str,
    prompt: str,
    model: str,
    temperature: float,
    max_tokens: int,
    stream: bool,
) -> Tuple[Optional[requests.Response], Optional[str], Optional[int]]:
    if not api_key:
        return None, "(sin API key)", 500

    url = f"{base_url}/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": stream,
    }
    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "super-bridge/1.0",
        },
        data=json.dumps(payload),
        stream=stream,
        timeout=90,
    )
    return resp, None, None

def dispatch(provider: str, prompt: str, model: str, temperature: float, max_tokens: int, stream: bool):
    provider = (provider or "").strip().lower()

    if provider == "groq":
        return call_openai_compatible(
            base_url="https://api.groq.com/openai/v1",
            api_key=os.environ.get("GROQ_API_KEY", "").strip(),
            prompt=prompt,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
        )

    if provider == "openai":
        return call_openai_compatible(
            base_url="https://api.openai.com/v1",
            api_key=os.environ.get("OPENAI_API_KEY", "").strip(),
            prompt=prompt,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
        )

    return None, f"(provider no soportado: {provider})", 400
