"""What the agent's runtime looks like from the inside: possible ways around the gateway.

Only variable NAMES and provider host names are reported, never values. This detects a bypass risk;
it does not prevent one. Network egress rules (see docs/egress.md) are what enforce gateway-only access.
"""

from __future__ import annotations

import os
import socket
from typing import Optional
from urllib.parse import urlparse

# Environment variables that usually hold a direct model-provider credential.
PROVIDER_KEY_VARS = {
    "OPENAI_API_KEY": "OpenAI",
    "AZURE_OPENAI_API_KEY": "Azure OpenAI",
    "ANTHROPIC_API_KEY": "Anthropic",
    "GOOGLE_API_KEY": "Google",
    "GEMINI_API_KEY": "Google Gemini",
    "OLLAMA_API_KEY": "Ollama",
    "MISTRAL_API_KEY": "Mistral",
    "COHERE_API_KEY": "Cohere",
    "CO_API_KEY": "Cohere",
    "GROQ_API_KEY": "Groq",
    "TOGETHER_API_KEY": "Together AI",
    "OPENROUTER_API_KEY": "OpenRouter",
    "DEEPSEEK_API_KEY": "DeepSeek",
    "XAI_API_KEY": "xAI",
    "PERPLEXITY_API_KEY": "Perplexity",
    "HF_TOKEN": "Hugging Face",
    "HUGGINGFACEHUB_API_TOKEN": "Hugging Face",
    "AWS_BEARER_TOKEN_BEDROCK": "Amazon Bedrock",
}

# Variables that point a client library at a model endpoint.
PROVIDER_URL_VARS = ["OPENAI_BASE_URL", "OPENAI_API_BASE", "AZURE_OPENAI_ENDPOINT", "ANTHROPIC_BASE_URL", "OLLAMA_HOST", "OLLAMA_BASE_URL", "LLM_BASE_URL"]

# Hosts tried for the optional egress check: if a TCP connection succeeds, the runtime can reach a
# provider directly and nothing but convention stops it.
EGRESS_TARGETS = [("api.openai.com", 443), ("ollama.com", 443), ("api.anthropic.com", 443)]


def scan_environment(gateway_url: str, environ: Optional[dict] = None) -> list[dict]:
    env = os.environ if environ is None else environ
    gateway_host = urlparse(gateway_url).hostname or ""
    findings: list[dict] = []
    for name, provider in PROVIDER_KEY_VARS.items():
        if env.get(name, "").strip():
            findings.append({"name": name, "kind": "provider_key", "provider": provider, "detail": "a direct provider credential is present in the agent's environment"})
    for name in PROVIDER_URL_VARS:
        value = env.get(name, "").strip()
        if not value:
            continue
        host = urlparse(value if "://" in value else f"http://{value}").hostname or ""
        if host and host != gateway_host:
            findings.append({"name": name, "kind": "provider_url", "provider": host, "detail": f"points at {host}, not the Signet gateway"})
    return findings


def egress_check(timeout_s: float = 3.0) -> list[dict]:
    out = []
    for host, port in EGRESS_TARGETS:
        reachable = False
        try:
            with socket.create_connection((host, port), timeout=timeout_s):
                reachable = True
        except OSError:
            reachable = False
        out.append({"target": f"{host}:{port}", "reachable": reachable})
    return out
