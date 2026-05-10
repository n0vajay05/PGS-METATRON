#!/usr/bin/env python3
"""
METATRON - llm.py
LM Studio interface for a local OpenAI-compatible chat model.
Builds prompts, handles AI responses, runs tool dispatch loop.
"""

import os
import re
import json
from pathlib import Path
import requests
from tools import run_tool_by_command, run_nmap, run_curl_headers
from search import handle_search_dispatch
from credential_store import (
    CLAUDE_API_KEY_TARGET,
    OPENAI_API_KEY_TARGET,
    read_secret,
    write_secret,
)
from platform_utils import local_app_data_dir

LM_STUDIO_BASE_URL = os.getenv("LM_STUDIO_BASE_URL", "http://localhost:1234/v1").rstrip("/")
MODEL_NAME = os.getenv("LM_STUDIO_MODEL", "")
CONFIG_PATH = local_app_data_dir() / "metatron_config.json"
AI_PROVIDER = os.getenv("METATRON_AI_PROVIDER", "local").strip().lower() or "local"
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "")
CLAUDE_BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1").rstrip("/")
CLAUDE_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.getenv("ANTHROPIC_MODEL", "")
DEFAULT_OPENAI_MODELS = ["gpt-4.1", "gpt-4.1-mini", "gpt-4o", "gpt-4o-mini"]
DEFAULT_CLAUDE_MODELS = [
    "claude-3-5-sonnet-latest",
    "claude-3-5-haiku-latest",
    "claude-3-opus-latest",
]
PROVIDER_LABELS = {
    "local": "Local LLM",
    "openai": "OpenAI",
    "claude": "Claude",
}
MAX_TOKENS = 65536
MAX_TOOL_LOOPS = 9   # max times AI can call tools per session
LM_STUDIO_TIMEOUT = 1200
MAX_RECON_CHARS = int(os.getenv("METATRON_MAX_RECON_CHARS", "24000"))
MAX_RETRY_RECON_CHARS = int(os.getenv("METATRON_RETRY_RECON_CHARS", "12000"))
MAX_TOOL_RESULT_CHARS = int(os.getenv("METATRON_MAX_TOOL_RESULT_CHARS", "12000"))
SECURITY_KEYWORDS = (
    "vuln",
    "cve-",
    "critical",
    "high",
    "medium",
    "low",
    "open",
    "port",
    "service",
    "server:",
    "x-powered-by",
    "missing",
    "exposed",
    "allowed",
    "risky",
    "warning",
    "error",
    "ssl",
    "tls",
    "certificate",
    "cert",
    "cipher",
    "heartbleed",
    "robot",
    "compression",
    "renegotiation",
    "fallback",
    "mozilla",
    "ocsp",
    "hsts",
    "http",
    "redirect",
    "admin",
    "login",
    "robots",
    ".git",
    ".env",
    "subdomain",
    "subfinder",
)

# ─────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are METATRON, an elite AI penetration testing assistant running on Windows with PowerShell-compatible local tools.
You are precise, technical, and direct. No fluff.

You have access to real tools. To use them, write tags in your response:

  [TOOL: nmap -sV 192.168.1.1]       → runs nmap or any CLI tool
  [SEARCH: CVE-2021-44228 exploit]   → searches the web via DuckDuckGo

Rules:
- Always analyze scan data thoroughly before suggesting exploits
- List vulnerabilities with: name, severity (critical/high/medium/low), port, service
- For each vulnerability, suggest a concrete fix
- For each vulnerability, include one EXPLOIT entry when there is a supported exploitation path, proof-of-concept check, or safe validation method. If direct exploitation is not supported by evidence, still include a non-destructive validation entry and explain the limitation in NOTES.
- If you need more information, use [SEARCH:] or [TOOL:]
- Format vulnerabilities clearly so they can be saved to a database
- Be specific about CVE IDs when you know them
- Always give a final risk rating: CRITICAL / HIGH / MEDIUM / LOW
- CMS, framework, plugin, theme, or server version disclosure by itself is always LOW severity. Do not rate version disclosure as HIGH or CRITICAL unless the scan also shows a specific evidence-backed exploitable CVE, active compromise path, exposed credentials, or authenticated access.
- When SSLyze/TLS output is present, summarize the site's SSL/TLS stack in the SUMMARY or AI analysis: certificate validity/issuer/expiry, supported TLS versions, notable cipher/protocol support, HTTP security headers, and Mozilla TLS compliance.
- For SSL/TLS weaknesses found by SSLyze, create VULN entries. Examples: expired/invalid certificate, hostname mismatch, SSLv2/SSLv3/TLSv1.0/TLSv1.1 support, weak ciphers, TLS compression, Heartbleed, ROBOT, insecure renegotiation, missing HSTS, or Mozilla non-compliance.
- Do not mark supported modern TLS versions such as TLS 1.2 or TLS 1.3 as vulnerabilities by themselves.

Output format for vulnerabilities (use this exactly):
VULN: <name> | SEVERITY: <level> | PORT: <port> | SERVICE: <service>
DESC: <description>
FIX: <fix recommendation>

Output format for exploits:
EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload or description>
RESULT: <expected result>
NOTES: <any notes>

End your analysis with:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <2-3 sentence overall summary>
IMPORTANT: Never use markdown bold (**text**) or 
headers (## text). Plain text only. No exceptions.
IMPORTANT RULES FOR ACCURACY:
- nmap filtered or no-response means INCONCLUSIVE not vulnerable
- Never assert a server version without seeing it in scan output
- Never infer CVEs from guessed versions
- Version disclosure alone, including CMS version disclosure, is LOW severity information disclosure.
- curl timeouts and HTTP_CODE=000 mean the host is unreachable not exploitable
- ab and stress tools are not Slowloris unless confirmed
- Only assign CRITICAL if there is direct evidence of exploitability
- If evidence is weak mark severity as LOW with note: unconfirmed
- Exploit entries must be tied to observed evidence. Prefer safe validation commands/checks over destructive payloads.
- If you are a reasoning model, put the final report in the normal assistant content. Do not return only hidden reasoning or thinking text.
- Return the final report once. Do not include review steps, drafts, checklists, headings, or duplicate copies of the same findings."""


INDIVIDUAL_TOOL_PROMPT = """You are METATRON, an elite AI penetration testing assistant running on Windows with PowerShell-compatible local tools. You are precise, technical, and direct. No fluff.
You will generate a precise summary of the findings from the specific tool that was run, in a user readable format.
Output Form: Text Summary"""


# ─────────────────────────────────────────────
# LM STUDIO API CALL
# ─────────────────────────────────────────────

def _read_app_config() -> dict:
    try:
        if CONFIG_PATH.exists():
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _write_app_config(data: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def lm_studio_url(path: str) -> str:
    return f"{LM_STUDIO_BASE_URL}/{path.lstrip('/')}"


def openai_url(path: str) -> str:
    return f"{OPENAI_BASE_URL}/{path.lstrip('/')}"


def claude_url(path: str) -> str:
    return f"{CLAUDE_BASE_URL}/{path.lstrip('/')}"


def normalize_lm_studio_base_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        text = "http://localhost:1234/v1"
    if "://" not in text:
        text = "http://" + text
    text = text.rstrip("/")
    if not text.endswith("/v1"):
        text += "/v1"
    return text


def normalize_openai_base_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        text = "https://api.openai.com/v1"
    if "://" not in text:
        text = "https://" + text
    text = text.rstrip("/")
    if not text.endswith("/v1"):
        text += "/v1"
    return text


def normalize_claude_base_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        text = "https://api.anthropic.com/v1"
    if "://" not in text:
        text = "https://" + text
    text = text.rstrip("/")
    if not text.endswith("/v1"):
        text += "/v1"
    return text


def normalize_provider(value: str) -> str:
    provider = str(value or "local").strip().lower()
    return provider if provider in PROVIDER_LABELS else "local"


def load_ai_settings() -> dict:
    data = _read_app_config()
    provider = normalize_provider(data.get("ai_provider", AI_PROVIDER))
    openai_credential = read_secret(OPENAI_API_KEY_TARGET)
    claude_credential = read_secret(CLAUDE_API_KEY_TARGET)
    changed = False
    if not openai_credential and data.get("openai_api_key"):
        openai_credential = str(data.get("openai_api_key") or "").strip()
        if openai_credential:
            try:
                write_secret(OPENAI_API_KEY_TARGET, openai_credential, "OpenAI")
                changed = True
            except Exception:
                openai_credential = ""
    if not claude_credential and data.get("claude_api_key"):
        claude_credential = str(data.get("claude_api_key") or "").strip()
        if claude_credential:
            try:
                write_secret(CLAUDE_API_KEY_TARGET, claude_credential, "Claude")
                changed = True
            except Exception:
                claude_credential = ""
    if "openai_api_key" in data:
        data.pop("openai_api_key", None)
        changed = True
    if "claude_api_key" in data:
        data.pop("claude_api_key", None)
        changed = True
    if changed:
        try:
            _write_app_config(data)
        except Exception:
            pass
    settings = {
        "ai_provider": provider,
        "lm_studio_base_url": normalize_lm_studio_base_url(
            data.get("lm_studio_base_url") or LM_STUDIO_BASE_URL
        ),
        "lm_studio_model": str(data.get("lm_studio_model") or "").strip(),
        "openai_base_url": normalize_openai_base_url(
            data.get("openai_base_url") or OPENAI_BASE_URL
        ),
        "openai_api_key": str(openai_credential or OPENAI_API_KEY or "").strip(),
        "openai_model": str(data.get("openai_model") or OPENAI_MODEL or "").strip(),
        "claude_base_url": normalize_claude_base_url(
            data.get("claude_base_url") or CLAUDE_BASE_URL
        ),
        "claude_api_key": str(claude_credential or CLAUDE_API_KEY or "").strip(),
        "claude_model": str(data.get("claude_model") or CLAUDE_MODEL or "").strip(),
    }
    if os.getenv("METATRON_AI_PROVIDER"):
        settings["ai_provider"] = normalize_provider(os.getenv("METATRON_AI_PROVIDER"))
    return settings


def apply_ai_settings(settings: dict | None = None) -> dict:
    global AI_PROVIDER, LM_STUDIO_BASE_URL, MODEL_NAME
    global OPENAI_BASE_URL, OPENAI_API_KEY, OPENAI_MODEL
    global CLAUDE_BASE_URL, CLAUDE_API_KEY, CLAUDE_MODEL

    settings = settings or load_ai_settings()
    AI_PROVIDER = normalize_provider(settings.get("ai_provider"))
    LM_STUDIO_BASE_URL = normalize_lm_studio_base_url(settings.get("lm_studio_base_url"))
    OPENAI_BASE_URL = normalize_openai_base_url(settings.get("openai_base_url"))
    OPENAI_API_KEY = str(settings.get("openai_api_key") or "").strip()
    OPENAI_MODEL = str(settings.get("openai_model") or "").strip()
    CLAUDE_BASE_URL = normalize_claude_base_url(settings.get("claude_base_url"))
    CLAUDE_API_KEY = str(settings.get("claude_api_key") or "").strip()
    CLAUDE_MODEL = str(settings.get("claude_model") or "").strip()

    local_model = str(settings.get("lm_studio_model") or "").strip()
    if AI_PROVIDER == "openai":
        MODEL_NAME = OPENAI_MODEL
    elif AI_PROVIDER == "claude":
        MODEL_NAME = CLAUDE_MODEL
    else:
        MODEL_NAME = local_model
    return current_ai_settings()


def current_ai_settings() -> dict:
    return {
        "ai_provider": AI_PROVIDER,
        "lm_studio_base_url": LM_STUDIO_BASE_URL,
        "lm_studio_model": MODEL_NAME if AI_PROVIDER == "local" else load_ai_settings().get("lm_studio_model", ""),
        "openai_base_url": OPENAI_BASE_URL,
        "openai_api_key": OPENAI_API_KEY,
        "openai_model": OPENAI_MODEL,
        "claude_base_url": CLAUDE_BASE_URL,
        "claude_api_key": CLAUDE_API_KEY,
        "claude_model": CLAUDE_MODEL,
    }


def save_ai_settings(**updates) -> dict:
    data = _read_app_config()
    settings = load_ai_settings()
    settings.update({key: value for key, value in updates.items() if value is not None})
    settings["ai_provider"] = normalize_provider(settings.get("ai_provider"))
    settings["lm_studio_base_url"] = normalize_lm_studio_base_url(settings.get("lm_studio_base_url"))
    settings["openai_base_url"] = normalize_openai_base_url(settings.get("openai_base_url"))
    settings["claude_base_url"] = normalize_claude_base_url(settings.get("claude_base_url"))
    if "openai_api_key" in updates and updates.get("openai_api_key"):
        write_secret(OPENAI_API_KEY_TARGET, str(updates["openai_api_key"]), "OpenAI")
    if "claude_api_key" in updates and updates.get("claude_api_key"):
        write_secret(CLAUDE_API_KEY_TARGET, str(updates["claude_api_key"]), "Claude")

    for key, value in settings.items():
        if key in ("openai_api_key", "claude_api_key"):
            continue
        data[key] = value
    data.pop("openai_api_key", None)
    data.pop("claude_api_key", None)
    _write_app_config(data)
    return apply_ai_settings(settings)


def load_saved_base_url() -> str:
    return load_ai_settings()["lm_studio_base_url"]


def set_lm_studio_base_url(value: str) -> str:
    global LM_STUDIO_BASE_URL
    LM_STUDIO_BASE_URL = normalize_lm_studio_base_url(value)
    return LM_STUDIO_BASE_URL


def current_base_url() -> str:
    if AI_PROVIDER == "openai":
        return OPENAI_BASE_URL
    if AI_PROVIDER == "claude":
        return CLAUDE_BASE_URL
    return LM_STUDIO_BASE_URL


def current_provider() -> str:
    return AI_PROVIDER


def current_provider_label() -> str:
    return PROVIDER_LABELS.get(AI_PROVIDER, "Local LLM")


def get_lm_studio_models() -> list[str]:
    resp = requests.get(lm_studio_url("models"), timeout=10)
    resp.raise_for_status()
    data = resp.json()
    models = []
    for item in data.get("data", []):
        model_id = item.get("id")
        if model_id:
            models.append(model_id)
    return models


def get_openai_models(base_url: str | None = None, api_key: str | None = None) -> list[str]:
    base = normalize_openai_base_url(base_url or OPENAI_BASE_URL)
    key = str(api_key if api_key is not None else OPENAI_API_KEY).strip()
    if not key:
        raise RuntimeError("Enter an OpenAI API key before loading online models.")
    resp = requests.get(
        f"{base}/models",
        headers={"Authorization": f"Bearer {key}"},
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()
    models = sorted({item.get("id") for item in data.get("data", []) if item.get("id")})
    return models or DEFAULT_OPENAI_MODELS


def get_claude_models(base_url: str | None = None, api_key: str | None = None) -> list[str]:
    base = normalize_claude_base_url(base_url or CLAUDE_BASE_URL)
    key = str(api_key if api_key is not None else CLAUDE_API_KEY).strip()
    if not key:
        raise RuntimeError("Enter a Claude API key before loading online models.")
    resp = requests.get(
        f"{base}/models",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
        timeout=20,
    )
    if resp.status_code == 404:
        return DEFAULT_CLAUDE_MODELS
    resp.raise_for_status()
    data = resp.json()
    models = sorted({item.get("id") for item in data.get("data", []) if item.get("id")})
    return models or DEFAULT_CLAUDE_MODELS


def get_models_for_provider(provider: str, base_url: str | None = None, api_key: str | None = None) -> list[str]:
    provider = normalize_provider(provider)
    if provider == "openai":
        return get_openai_models(base_url, api_key)
    if provider == "claude":
        return get_claude_models(base_url, api_key)
    if base_url:
        set_lm_studio_base_url(base_url)
    return get_lm_studio_models()


def load_saved_model() -> str:
    settings = load_ai_settings()
    provider = normalize_provider(settings.get("ai_provider"))
    if provider == "openai":
        return str(settings.get("openai_model") or "").strip()
    if provider == "claude":
        return str(settings.get("claude_model") or "").strip()
    return str(settings.get("lm_studio_model") or "").strip()


def save_selected_model(model: str) -> None:
    save_ai_settings(lm_studio_model=model)


def save_lm_studio_settings(model: str | None = None, base_url: str | None = None) -> None:
    updates = {"ai_provider": "local"}
    if base_url is not None:
        updates["lm_studio_base_url"] = set_lm_studio_base_url(base_url)
    if model is not None:
        updates["lm_studio_model"] = model
    elif MODEL_NAME:
        updates["lm_studio_model"] = MODEL_NAME
    save_ai_settings(**updates)


def configure_lm_studio_model(force_prompt: bool = False) -> bool:
    global MODEL_NAME

    try:
        models = get_lm_studio_models()
    except requests.exceptions.ConnectionError:
        print(f"[!] Cannot connect to LM Studio at {LM_STUDIO_BASE_URL}.")
        print("[!] Start LM Studio, open the Developer/Local Server tab, and start the server.")
        return False
    except requests.exceptions.Timeout:
        print("[!] LM Studio did not respond while listing models.")
        return False
    except Exception as e:
        print(f"[!] Could not list LM Studio models: {e}")
        return False

    if not models:
        print("[!] LM Studio is running, but no models were returned by /v1/models.")
        print("[!] Load a model in LM Studio or enable a model for the local server, then try again.")
        return False

    saved_model = load_saved_model()
    if saved_model in models and not force_prompt:
        MODEL_NAME = saved_model
        print(f"[+] LM Studio model selected: {MODEL_NAME}")
        return True

    if MODEL_NAME in models and not force_prompt:
        print(f"[+] LM Studio model selected: {MODEL_NAME}")
        return True

    if saved_model and saved_model not in models and not force_prompt:
        print(f"[!] Saved LM Studio model is not currently available: {saved_model}")

    print("\n[ LM STUDIO MODELS ]")
    for i, model in enumerate(models, 1):
        print(f"  [{i}] {model}")

    while True:
        choice = input(f"\nSelect model [1-{len(models)}] (Enter = 1): ").strip()
        if not choice:
            MODEL_NAME = models[0]
            break
        if choice.isdigit() and 1 <= int(choice) <= len(models):
            MODEL_NAME = models[int(choice) - 1]
            break
        print("[!] Invalid model selection.")

    print(f"[+] LM Studio model selected: {MODEL_NAME}")
    save_selected_model(MODEL_NAME)
    return True


def ensure_lm_studio_model() -> bool:
    return has_selected_model() or configure_lm_studio_model(force_prompt=False)


def ensure_ai_model() -> bool:
    return has_selected_model()


def has_selected_model() -> bool:
    if AI_PROVIDER == "openai":
        return bool(OPENAI_MODEL and OPENAI_API_KEY)
    if AI_PROVIDER == "claude":
        return bool(CLAUDE_MODEL and CLAUDE_API_KEY)
    return bool(MODEL_NAME)


def current_model_name() -> str:
    if AI_PROVIDER == "openai":
        return OPENAI_MODEL or "not selected"
    if AI_PROVIDER == "claude":
        return CLAUDE_MODEL or "not selected"
    return MODEL_NAME or "not selected"


def current_api_key_set() -> bool:
    if AI_PROVIDER == "openai":
        return bool(OPENAI_API_KEY)
    if AI_PROVIDER == "claude":
        return bool(CLAUDE_API_KEY)
    return False


def normalize_lm_studio_content(content) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content") or ""
                if text:
                    parts.append(str(text))
        return "\n".join(parts).strip()
    return ""


def extract_lm_studio_text(data: dict) -> tuple[str, str]:
    choices = data.get("choices", [])
    if not choices:
        return "", "LM Studio returned no choices."

    choice = choices[0]
    message = choice.get("message") or {}
    content = normalize_lm_studio_content(message.get("content"))
    if content:
        return content, ""

    reasoning = normalize_lm_studio_content(message.get("reasoning_content"))
    if reasoning:
        if any(marker in reasoning for marker in ("VULN:", "RISK_LEVEL:", "SUMMARY:", "EXPLOIT:")):
            return reasoning, "LM Studio returned analysis in reasoning_content instead of content."
        return "", "LM Studio returned only reasoning_content, with no final assistant content."

    text = normalize_lm_studio_content(choice.get("text"))
    if text:
        return text, ""

    finish_reason = choice.get("finish_reason", "unknown")
    return "", f"LM Studio returned empty content. finish_reason={finish_reason}"


def ai_http_error_message(error: requests.exceptions.HTTPError, provider_label: str | None = None) -> str:
    response = error.response
    label = provider_label or current_provider_label()
    details = ""
    if response is not None:
        body = (response.text or "").strip()
        if body:
            details = body[:1000]
    if details:
        return f"[!] {label} HTTP error: {error}\n[{label} response]\n{details}"
    return f"[!] {label} HTTP error: {error}"


def lm_studio_http_error_message(error: requests.exceptions.HTTPError) -> str:
    return ai_http_error_message(error, "LM Studio")


def compact_text_for_prompt(text: str, max_chars: int, label: str = "text") -> str:
    text = str(text or "")
    if len(text) <= max_chars:
        return text

    lines = text.splitlines()
    priority_lines = []
    for line in lines:
        lower = line.lower()
        if any(keyword in lower for keyword in SECURITY_KEYWORDS):
            priority_lines.append(line)

    priority = "\n".join(priority_lines[:220])
    if len(priority) > max_chars // 2:
        priority = priority[: max_chars // 2]

    remaining = max_chars - len(priority) - 260
    remaining = max(2000, remaining)
    head_len = remaining // 2
    tail_len = remaining - head_len

    return (
        f"[METATRON NOTE: {label} was compacted from {len(text)} to about {max_chars} characters "
        "to fit the local model context. Security-relevant lines were preserved first.]\n\n"
        f"[SECURITY-RELEVANT LINES]\n{priority or '-'}\n\n"
        f"[BEGINNING OF ORIGINAL {label.upper()}]\n{text[:head_len]}\n\n"
        f"[...OMITTED {len(text) - head_len - tail_len} CHARACTERS...]\n\n"
        f"[END OF ORIGINAL {label.upper()}]\n{text[-tail_len:]}"
    )


def compact_messages_for_retry(messages: list, max_recon_chars: int) -> list:
    compacted = []
    for message in messages:
        content = message.get("content", "")
        if isinstance(content, str) and "RECON DATA:" in content:
            before, after = content.split("RECON DATA:", 1)
            compacted_content = before + "RECON DATA:\n" + compact_text_for_prompt(after, max_recon_chars, "recon data")
            compacted.append({**message, "content": compacted_content})
        elif isinstance(content, str) and len(content) > max_recon_chars:
            compacted.append({**message, "content": compact_text_for_prompt(content, max_recon_chars, "message")})
        else:
            compacted.append(message)
    return compacted


def ask_openai_compatible(
    provider_label: str,
    base_url: str,
    model: str,
    messages: list,
    api_key: str = "",
    max_tokens: int = MAX_TOKENS,
    temperature: float = 0.7,
    timeout: int = LM_STUDIO_TIMEOUT,
    token_parameter: str = "max_tokens",
    include_sampling: bool = True,
) -> str:
    if not model:
        return f"[!] No {provider_label} model selected. Choose a model from the AI Model Settings menu first."

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        def build_payload(message_list: list, token_limit: int, token_key: str) -> dict:
            request_payload = {
                "model": model,
                "messages": message_list,
                "stream": False,
                token_key: token_limit,
            }
            if include_sampling:
                request_payload["temperature"] = temperature
                request_payload["top_p"] = 0.9
            return request_payload

        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
        }
        payload = build_payload(messages, max_tokens, token_parameter)
        print(f"\n[*] Sending to {provider_label}: {model}...")
        resp = requests.post(f"{base_url}/chat/completions", json=payload, headers=headers, timeout=timeout)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 400:
                body = (resp.text or "").lower()
                if "unsupported parameter" in body:
                    retry_token_parameter = None
                    if token_parameter == "max_tokens" and "max_tokens" in body:
                        retry_token_parameter = "max_completion_tokens"
                    elif token_parameter == "max_completion_tokens" and "max_completion_tokens" in body:
                        retry_token_parameter = "max_tokens"
                    if retry_token_parameter:
                        print(f"[!] {provider_label} rejected {token_parameter}. Retrying with {retry_token_parameter}...")
                        retry_payload = build_payload(messages, max_tokens, retry_token_parameter)
                        retry_resp = requests.post(
                            f"{base_url}/chat/completions",
                            json=retry_payload,
                            headers=headers,
                            timeout=timeout,
                        )
                        try:
                            retry_resp.raise_for_status()
                        except requests.exceptions.HTTPError as retry_error:
                            return ai_http_error_message(retry_error, provider_label)
                        data = retry_resp.json()
                        response, warning = extract_lm_studio_text(data)
                        if warning and response:
                            print(f"[!] {warning}")
                        if not response:
                            return f"[!] Model returned empty response. {warning}"
                        return response
                compacted_messages = compact_messages_for_retry(messages, MAX_RETRY_RECON_CHARS)
                if compacted_messages != messages:
                    print(f"[!] {provider_label} rejected the request. Retrying with compacted recon data...")
                    retry_payload = build_payload(compacted_messages, min(max_tokens, 4096), token_parameter)
                    retry_resp = requests.post(
                        f"{base_url}/chat/completions",
                        json=retry_payload,
                        headers=headers,
                        timeout=timeout,
                    )
                    try:
                        retry_resp.raise_for_status()
                    except requests.exceptions.HTTPError as retry_error:
                        return ai_http_error_message(retry_error, provider_label)
                    data = retry_resp.json()
                    response, warning = extract_lm_studio_text(data)
                    if warning and response:
                        print(f"[!] {warning}")
                    if not response:
                        return f"[!] Model returned empty response after compacted retry. {warning}"
                    return response
            return ai_http_error_message(e, provider_label)
        data = resp.json()
        response, warning = extract_lm_studio_text(data)
        if warning and response:
            print(f"[!] {warning}")
        if not response:
            return f"[!] Model returned empty response. {warning}"
        return response
    except requests.exceptions.ConnectionError:
        return f"[!] Cannot connect to {provider_label} at {base_url}."
    except requests.exceptions.Timeout:
        return f"[!] {provider_label} timed out. Try again or use a smaller/faster model."
    except requests.exceptions.HTTPError as e:
        return ai_http_error_message(e, provider_label)
    except Exception as e:
        return f"[!] Unexpected error: {e}"


def split_claude_messages(messages: list) -> tuple[str, list]:
    system_parts = []
    claude_messages = []
    for message in messages:
        role = message.get("role", "user")
        content = normalize_lm_studio_content(message.get("content", ""))
        if not content:
            continue
        if role == "system":
            system_parts.append(content)
        elif role in ("assistant", "user"):
            claude_messages.append({"role": role, "content": content})
        else:
            claude_messages.append({"role": "user", "content": content})
    if not claude_messages:
        claude_messages.append({"role": "user", "content": "Analyze the available scan data."})
    return "\n\n".join(system_parts), claude_messages


def extract_claude_text(data: dict) -> str:
    parts = []
    for item in data.get("content", []):
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(str(item.get("text") or ""))
    return "\n".join(part.strip() for part in parts if part.strip()).strip()


def ask_claude(messages: list, max_tokens: int = MAX_TOKENS, temperature: float = 0.7, timeout: int = LM_STUDIO_TIMEOUT) -> str:
    if not CLAUDE_MODEL:
        return "[!] No Claude model selected. Choose a model from the AI Model Settings menu first."
    if not CLAUDE_API_KEY:
        return "[!] Claude API key is missing. Add it in AI Model Settings first."

    try:
        system_text, claude_messages = split_claude_messages(messages)
        payload = {
            "model": CLAUDE_MODEL,
            "messages": claude_messages,
            "max_tokens": min(max_tokens, 8192),
            "temperature": temperature,
        }
        if system_text:
            payload["system"] = system_text
        headers = {
            "x-api-key": CLAUDE_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        print(f"\n[*] Sending to Claude: {CLAUDE_MODEL}...")
        resp = requests.post(claude_url("messages"), json=payload, headers=headers, timeout=timeout)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 400:
                compacted = compact_messages_for_retry(messages, MAX_RETRY_RECON_CHARS)
                if compacted != messages:
                    system_text, claude_messages = split_claude_messages(compacted)
                    retry_payload = {**payload, "messages": claude_messages, "max_tokens": min(max_tokens, 4096)}
                    if system_text:
                        retry_payload["system"] = system_text
                    retry_resp = requests.post(claude_url("messages"), json=retry_payload, headers=headers, timeout=timeout)
                    try:
                        retry_resp.raise_for_status()
                    except requests.exceptions.HTTPError as retry_error:
                        return ai_http_error_message(retry_error, "Claude")
                    response = extract_claude_text(retry_resp.json())
                    return response or "[!] Claude returned an empty response after compacted retry."
            return ai_http_error_message(e, "Claude")
        response = extract_claude_text(resp.json())
        return response or "[!] Claude returned an empty response."
    except requests.exceptions.ConnectionError:
        return f"[!] Cannot connect to Claude at {CLAUDE_BASE_URL}."
    except requests.exceptions.Timeout:
        return "[!] Claude timed out. Try again or use a smaller/faster model."
    except Exception as e:
        return f"[!] Unexpected error: {e}"


def ask_ai_model(messages: list, max_tokens: int = MAX_TOKENS, temperature: float = 0.7, timeout: int = LM_STUDIO_TIMEOUT) -> str:
    if AI_PROVIDER == "openai":
        if not OPENAI_API_KEY:
            return "[!] OpenAI API key is missing. Add it in AI Model Settings first."
        return ask_openai_compatible(
            "OpenAI",
            OPENAI_BASE_URL,
            OPENAI_MODEL,
            messages,
            api_key=OPENAI_API_KEY,
            max_tokens=min(max_tokens, 16384),
            temperature=temperature,
            timeout=timeout,
            token_parameter="max_completion_tokens",
            include_sampling=False,
        )
    if AI_PROVIDER == "claude":
        return ask_claude(messages, max_tokens=max_tokens, temperature=temperature, timeout=timeout)
    return ask_openai_compatible(
        "LM Studio",
        LM_STUDIO_BASE_URL,
        MODEL_NAME,
        messages,
        max_tokens=max_tokens,
        temperature=temperature,
        timeout=timeout,
    )


def ask_lm_studio(messages: list, max_tokens: int = MAX_TOKENS, temperature: float = 0.7, timeout: int = LM_STUDIO_TIMEOUT) -> str:
    if AI_PROVIDER != "local":
        return ask_ai_model(messages, max_tokens=max_tokens, temperature=temperature, timeout=timeout)
    if not MODEL_NAME:
        return "[!] No LM Studio model selected. Choose a model from the main menu first."

    try:
        payload = {
            "model": MODEL_NAME,
            "messages": messages,
            "stream": False,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": 0.9,
        }
        print(f"\n[*] Sending to {MODEL_NAME}...")
        resp = requests.post(lm_studio_url("chat/completions"), json=payload, timeout=timeout)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 400:
                compacted_messages = compact_messages_for_retry(messages, MAX_RETRY_RECON_CHARS)
                if compacted_messages != messages:
                    print("[!] LM Studio rejected the request. Retrying with compacted recon data...")
                    retry_payload = {**payload, "messages": compacted_messages, "max_tokens": min(max_tokens, 4096)}
                    retry_resp = requests.post(lm_studio_url("chat/completions"), json=retry_payload, timeout=timeout)
                    try:
                        retry_resp.raise_for_status()
                    except requests.exceptions.HTTPError as retry_error:
                        return lm_studio_http_error_message(retry_error)
                    data = retry_resp.json()
                    response, warning = extract_lm_studio_text(data)
                    if warning and response:
                        print(f"[!] {warning}")
                    if not response:
                        return f"[!] Model returned empty response after compacted retry. {warning}"
                    return response
            return lm_studio_http_error_message(e)
        data = resp.json()
        response, warning = extract_lm_studio_text(data)
        if warning and response:
            print(f"[!] {warning}")
        if not response:
            return (
                f"[!] Model returned empty response. {warning} "
                "In LM Studio, try turning off 'Separate reasoning_content and content', "
                "or choose a non-reasoning/instruct model."
            )
        return response
    except requests.exceptions.ConnectionError:
        return f"[!] Cannot connect to LM Studio at {LM_STUDIO_BASE_URL}. Start LM Studio's local server."
    except requests.exceptions.Timeout:
        return "[!] LM Studio timed out. The model may still be loading; try again."
    except requests.exceptions.HTTPError as e:
        return lm_studio_http_error_message(e)
    except Exception as e:
        return f"[!] Unexpected error: {e}"


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

def extract_tool_calls(response: str) -> list:
    """
    Extract all [TOOL: ...] and [SEARCH: ...] tags from AI response.
    Returns list of tuples: [("TOOL", "nmap -sV x.x.x.x"), ("SEARCH", "CVE...")]
    """
    calls = []

    tool_matches   = re.findall(r'\[TOOL:\s*(.+?)\]',   response)
    search_matches = re.findall(r'\[SEARCH:\s*(.+?)\]', response)

    for m in tool_matches:
        calls.append(("TOOL", m.strip()))
    for m in search_matches:
        calls.append(("SEARCH", m.strip()))

    return calls

def summarize_tool_output(raw_output: str) -> str:
    """
    Compress raw tool output into security-relevant bullet points
    before injecting into the LLM context.
    Keeps context size manageable across rounds.
    """
    if len(raw_output) < 500:
        return raw_output

    try:
        summary = ask_ai_model(
            [
                {
                    "role": "system",
                    "content": "You are a security data compressor. Extract only security-relevant facts. Return maximum 15 bullet points. Plain text only. No markdown.",
                },
                {"role": "user", "content": f"Compress this tool output:\n{raw_output[:6000]}"},
            ],
            max_tokens=512,
            temperature=0.2,
            timeout=120,
        )
        if summary.startswith("[!]"):
            return raw_output
        return summary if summary else raw_output
    except Exception:
        return raw_output
def run_tool_calls(calls: list) -> str:
    """
    Execute all tool/search calls and return combined results string.
    """
    if not calls:
        return ""

    results = ""
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")

        if call_type == "TOOL":
            output = run_tool_by_command(call_content)
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"

        compressed = summarize_tool_output(output.strip())
        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += compressed + "\n"

    return results


# ─────────────────────────────────────────────
# PARSER — extract structured data from AI output
# ─────────────────────────────────────────────
def _clean(line: str) -> str:
    return re.sub(r'\*+', '', line).strip()


def _append_field(target: dict, field: str, value: str) -> None:
    value = value.strip()
    if not value:
        return
    if target.get(field):
        target[field] = f"{target[field]}\n{value}"
    else:
        target[field] = value


def _normalized_key(*values) -> tuple[str, ...]:
    return tuple(re.sub(r"\s+", " ", str(value or "").strip()).lower() for value in values)


def _dedupe_vulnerabilities(vulns: list[dict]) -> list[dict]:
    unique = []
    seen = set()
    for vuln in vulns:
        key = _normalized_key(
            vuln.get("vuln_name"),
            vuln.get("severity"),
            vuln.get("port"),
            vuln.get("service"),
            vuln.get("description"),
            vuln.get("fix"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(vuln)
    return unique


def normalize_vulnerability_severity(vuln: dict) -> dict:
    combined = " ".join(
        str(vuln.get(field) or "")
        for field in ("vuln_name", "description", "service")
    ).lower()
    version_disclosure = (
        "version disclosure" in combined
        or ("disclosure" in combined and "version" in combined)
        or ("cms" in combined and "version" in combined)
    )
    exploit_evidence = any(
        marker in combined
        for marker in ("cve-", "credential", "authenticated", "remote code execution", "rce", "sql injection", "exploit")
    )
    if version_disclosure and not exploit_evidence:
        vuln["severity"] = "low"
    return vuln


def _dedupe_exploits(exploits: list[dict]) -> list[dict]:
    unique = []
    seen = set()
    for exploit in exploits:
        key = _normalized_key(
            exploit.get("exploit_name"),
            exploit.get("tool_used"),
            exploit.get("payload"),
            exploit.get("result"),
            exploit.get("notes"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(exploit)
    return unique


def format_structured_report(vulns: list[dict], exploits: list[dict], risk_level: str, summary: str) -> str:
    lines = []
    for vuln in vulns:
        lines.append(
            f"VULN: {vuln.get('vuln_name') or '-'} | "
            f"SEVERITY: {vuln.get('severity') or 'unknown'} | "
            f"PORT: {vuln.get('port') or 'n/a'} | "
            f"SERVICE: {vuln.get('service') or 'n/a'}"
        )
        lines.append(f"DESC: {vuln.get('description') or '-'}")
        lines.append(f"FIX: {vuln.get('fix') or '-'}")
        lines.append("")

    for exploit in exploits:
        lines.append(
            f"EXPLOIT: {exploit.get('exploit_name') or '-'} | "
            f"TOOL: {exploit.get('tool_used') or 'n/a'} | "
            f"PAYLOAD: {exploit.get('payload') or 'n/a'}"
        )
        lines.append(f"RESULT: {exploit.get('result') or 'n/a'}")
        lines.append(f"NOTES: {exploit.get('notes') or '-'}")
        lines.append("")

    lines.append(f"RISK_LEVEL: {risk_level or 'UNKNOWN'}")
    lines.append(f"SUMMARY: {summary or '-'}")
    return "\n".join(lines).strip()


def vulnerabilities_to_prompt(vulns: list[dict]) -> str:
    lines = []
    for idx, vuln in enumerate(vulns, 1):
        lines.append(
            f"{idx}. {vuln.get('vuln_name') or '-'} | "
            f"severity={vuln.get('severity') or 'unknown'} | "
            f"port={vuln.get('port') or 'n/a'} | "
            f"service={vuln.get('service') or 'n/a'}"
        )
        if vuln.get("description"):
            lines.append(f"   evidence={vuln['description']}")
    return "\n".join(lines)


def default_exploit_for_vulnerability(vuln: dict) -> dict:
    name = str(vuln.get("vuln_name") or "Vulnerability").strip()
    lower = name.lower()
    port = str(vuln.get("port") or "n/a").strip()
    service = str(vuln.get("service") or "n/a").strip()

    if "mysql" in lower or service.lower() == "mysql" or port == "3306":
        return {
            "exploit_name": "MySQL exposure validation",
            "tool_used": "mysql client / nmap",
            "payload": "Non-destructive connection and authentication check against the exposed MySQL service.",
            "result": "Confirms whether the database service is reachable from the scanning host and whether authentication or version disclosure is possible.",
            "notes": "Generated as a safe validation entry from the recorded vulnerability; do not attempt credential guessing without authorization.",
        }
    if "header" in lower or "hsts" in lower or "content-security-policy" in lower:
        return {
            "exploit_name": "Missing HTTP security header validation",
            "tool_used": "curl / browser developer tools",
            "payload": "Review response headers and confirm missing browser-side protections such as HSTS, CSP, X-Frame-Options, or X-Content-Type-Options.",
            "result": "Confirms whether browser protections against downgrade, framing, MIME-sniffing, or injection impact are absent.",
            "notes": "This is a configuration validation, not a destructive exploit. Actual impact depends on application behavior.",
        }
    if "certificate" in lower or "tls" in lower or "ssl" in lower:
        return {
            "exploit_name": "TLS/certificate validation",
            "tool_used": "sslyze / browser TLS inspection",
            "payload": "Validate certificate names, trust chain, supported protocol versions, and TLS policy findings.",
            "result": "Confirms whether clients may see trust warnings, hostname mismatch, weak protocol support, or policy non-compliance.",
            "notes": "Generated from SSL/TLS findings as a safe validation entry. Exploitability depends on client trust behavior and network position.",
        }
    if "information disclosure" in lower or "disclosure" in lower or "server" in lower:
        return {
            "exploit_name": "Information disclosure validation",
            "tool_used": "curl / web fingerprinting",
            "payload": "Collect headers and visible metadata to confirm exposed server, platform, framework, or version details.",
            "result": "Confirms whether the service leaks metadata that can aid targeted vulnerability research.",
            "notes": "This is a passive validation entry. Do not infer CVEs unless exact affected versions are observed.",
        }

    return {
        "exploit_name": f"{name} validation",
        "tool_used": "manual review",
        "payload": "Non-destructive validation based on the recorded scan evidence.",
        "result": "Confirms whether the finding is reproducible and has an observable security impact.",
        "notes": "No direct exploit was proven in the scan data; this entry preserves a safe validation path for report tracking.",
    }


def default_exploit_suggestions(vulns: list[dict]) -> list[dict]:
    return _dedupe_exploits([default_exploit_for_vulnerability(vuln) for vuln in vulns])


def generate_exploit_recommendations(target: str, raw_scan: str, vulns: list[dict]) -> list[dict]:
    if not vulns:
        return []

    print("\n[*] No exploits were parsed. Running focused exploit/validation pass...")
    messages = [
        {
            "role": "system",
            "content": """You create evidence-based exploit or validation entries for an authorized security report.
Use only the supplied vulnerabilities and scan evidence.
Do not invent CVEs, versions, open ports, credentials, shells, or successful compromise.
Prefer safe, non-destructive validation methods. If direct exploitation is not supported, create a validation entry and explain that limitation in NOTES.
Return only entries in this exact format:
EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload or validation description>
RESULT: <expected result>
NOTES: <evidence and caveats>
Plain text only.""",
        },
        {
            "role": "user",
            "content": f"""TARGET: {target}

RECORDED VULNERABILITIES:
{vulnerabilities_to_prompt(vulns)}

RAW SCAN EVIDENCE:
{compact_text_for_prompt(raw_scan, MAX_RETRY_RECON_CHARS, "raw scan evidence")}

Create one EXPLOIT or safe validation entry for each recorded vulnerability where possible.""",
        },
    ]
    response = ask_ai_model(messages, max_tokens=4096, temperature=0.2, timeout=LM_STUDIO_TIMEOUT)
    if response.startswith("[!]"):
        print(f"[!] Focused exploit pass failed: {response}")
        return default_exploit_suggestions(vulns)

    exploits = parse_exploits(response)
    if exploits:
        return exploits

    print("[!] Focused exploit pass returned no parseable EXPLOIT entries; using safe validation defaults.")
    return default_exploit_suggestions(vulns)


def parse_vulnerabilities(response: str) -> list:
    """
    Parse VULN: lines from AI response into dicts.
    Returns list of vulnerability dicts ready for db.save_vulnerability()
    """
    vulns = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("VULN:"):
            vuln = {
                "vuln_name":   "",
                "severity":    "medium",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         ""
            }

            # parse header line: VULN: name | SEVERITY: x | PORT: x | SERVICE: x
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("PORT:"):
                    vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"):
                    vuln["service"] = part.replace("SERVICE:", "").strip()

            current_field = None
            j = i + 1
            while j < len(lines):
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("DESC:"):
                    current_field = "description"
                    _append_field(vuln, current_field, next_line.replace("DESC:", "").strip())
                elif next_line.startswith("FIX:"):
                    current_field = "fix"
                    _append_field(vuln, current_field, next_line.replace("FIX:", "").strip())
                elif current_field and next_line:
                    _append_field(vuln, current_field, next_line)
                j += 1

            if vuln["vuln_name"]:
                vulns.append(normalize_vulnerability_severity(vuln))

        i += 1

    return _dedupe_vulnerabilities(vulns)


def parse_exploits(response: str) -> list:
    """
    Parse EXPLOIT: lines from AI response into dicts.
    Returns list of exploit dicts ready for db.save_exploit()
    """
    exploits = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("EXPLOIT:"):
            exploit = {
                "exploit_name": "",
                "tool_used":    "",
                "payload":      "",
                "result":       "unknown",
                "notes":        ""
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exploit["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exploit["payload"] = part.replace("PAYLOAD:", "").strip()

            current_field = None
            j = i + 1
            while j < len(lines):
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("RESULT:"):
                    current_field = "result"
                    exploit["result"] = ""
                    _append_field(exploit, current_field, next_line.replace("RESULT:", "").strip())
                elif next_line.startswith("NOTES:"):
                    current_field = "notes"
                    _append_field(exploit, current_field, next_line.replace("NOTES:", "").strip())
                elif current_field and next_line:
                    _append_field(exploit, current_field, next_line)
                j += 1

            if exploit["exploit_name"]:
                exploits.append(exploit)

        i += 1

    return _dedupe_exploits(exploits)


def parse_risk_level(response: str) -> str:
    """Extract RISK_LEVEL from AI response."""
    match = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(r'SUMMARY:\s*(.+)', response, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def run_mode_from_raw_scan(raw_scan: str) -> tuple[str, str]:
    mode_match = re.search(r"(?im)^mode:\s*(.+)$", str(raw_scan or ""))
    tool_match = re.search(r"(?im)^tool:\s*(.+)$", str(raw_scan or ""))
    mode = mode_match.group(1).strip().lower() if mode_match else "full"
    tool = tool_match.group(1).strip() if tool_match else ""
    return mode, tool


def is_single_tool_run(raw_scan: str) -> bool:
    mode, _ = run_mode_from_raw_scan(raw_scan)
    return mode == "single_tool"


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    if not ensure_ai_model():
        message = "[!] No AI model is available. Open AI Model Settings and select a model."
        return {
            "full_response": message,
            "vulnerabilities": [],
            "exploits": [],
            "risk_level": "UNKNOWN",
            "summary": message,
            "raw_scan": raw_scan,
        }

    prompt_scan = compact_text_for_prompt(raw_scan, MAX_RECON_CHARS, "recon data")
    if prompt_scan != raw_scan:
        print(f"[*] Recon data compacted before AI analysis: {len(raw_scan)} -> {len(prompt_scan)} characters")

    if is_single_tool_run(raw_scan):
        _, selected_tool = run_mode_from_raw_scan(raw_scan)
        messages = [
            {
                "role": "system",
                "content": INDIVIDUAL_TOOL_PROMPT
            },
            {
                "role": "user",
                "content": f"""TARGET: {target}
TOOL RUN: {selected_tool or 'single tool'}

RAW TOOL OUTPUT:
{prompt_scan}

Generate the text summary only."""
            }
        ]
        response = ask_ai_model(messages, max_tokens=4096, temperature=0.3, timeout=LM_STUDIO_TIMEOUT)
        print(f"\n{'─'*60}")
        print("[METATRON - Single Tool Summary]")
        print(f"{'─'*60}")
        print(response)
        summary = response if not response.startswith("[!]") else ""
        return {
            "full_response": response,
            "vulnerabilities": [],
            "exploits": [],
            "risk_level": "UNKNOWN",
            "summary": summary,
            "raw_scan": raw_scan,
        }

    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": f"""TARGET: {target}

RECON DATA:
{prompt_scan}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more information.
List all vulnerabilities and fixes. Also include one EXPLOIT entry for each vulnerability when an exploit, proof-of-concept, or safe validation method is supported by the evidence."""
        }
    ]

    final_response = ""

    for loop in range(MAX_TOOL_LOOPS):
        response = ask_ai_model(messages)

        print(f"\n{'─'*60}")
        print(f"[METATRON - Round {loop + 1}]")
        print(f"{'─'*60}")
        print(response)

        final_response = response

        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break

        tool_results = run_tool_calls(tool_calls)

        # add assistant response and tool results as new messages
        messages.append({
            "role": "assistant",
            "content": response
        })
        messages.append({
            "role": "user",
            "content": f"""[TOOL RESULTS]
{compact_text_for_prompt(tool_results, MAX_TOOL_RESULT_CHARS, "tool results")}

Continue your analysis with this new information.
If analysis is complete, give the final report with VULN, FIX, EXPLOIT, RISK_LEVEL, and SUMMARY entries."""
        })

    reviewed_response = final_response

    vulnerabilities = parse_vulnerabilities(reviewed_response)
    exploits        = parse_exploits(reviewed_response)
    if vulnerabilities and len(exploits) < len(vulnerabilities):
        generated_exploits = generate_exploit_recommendations(target, raw_scan, vulnerabilities)
        exploits = _dedupe_exploits(exploits + generated_exploits)
    risk_level      = parse_risk_level(reviewed_response)
    summary         = parse_summary(reviewed_response)
    if vulnerabilities or exploits or risk_level != "UNKNOWN" or summary:
        reviewed_response = format_structured_report(vulnerabilities, exploits, risk_level, summary)

    print(f"\n[+] Parsed: {len(vulnerabilities)} vulns, {len(exploits)} exploits | Risk: {risk_level}")

    return {
        "full_response":   reviewed_response,
        "vulnerabilities": vulnerabilities,
        "exploits":        exploits,
        "risk_level":      risk_level,
        "summary":         summary,
        "raw_scan":        raw_scan
    }
# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ llm.py test — direct AI query ]\n")

    if not configure_lm_studio_model():
        exit(1)

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
