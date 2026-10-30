"""Plane 5: direct LLM client (~no framework, so the trust boundary stays readable).

Backends
  deepseek  the project's provider (DEEPSEEK_API_KEY, model from DEEPSEEK_MODEL or --model).
            DeepSeek offers JSON-object mode but not JSON-schema mode, so the schema goes in
            the prompt and the validator is the only enforcement.
  none      template only; the demo floor never depends on a model
  ollama    local alternative; no telemetry leaves the host
  openai    any other OpenAI-compatible endpoint

For every cloud backend (deepseek, openai), internal IPs and asset names are replaced by
stable placeholders before egress, and every payload that leaves is logged.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import requests

from nids.assets import AssetRegistry
from nids.explain import prompt as P
from nids.explain import template
from nids.explain.validator import validate
from nids.models import Incident, Narrative

ChatFn = Callable[[str, str], str]  # (system, user) -> raw model text


@dataclass
class ExplainResult:
    narrative: Narrative
    validation_passed: bool
    source: str  # "llm" | "cache" | "template"
    reasons: list[str] = field(default_factory=list)
    template: Narrative | None = None  # always produced: ablation arm B and the fallback
    latency_ms: float | None = None  # model round trip, when a model was called

    def __post_init__(self) -> None:
        if self.template is None:
            self.template = self.narrative


# The model must return exactly this shape; the validator re-checks it regardless.
# Citations are required here because the validator rejects a narrative without them.
SCHEMA = Narrative.model_json_schema()
SCHEMA["required"] = [*SCHEMA["required"], "technical_evidence"]


def ollama_chat(model: str, base_url: str = "http://127.0.0.1:11434", timeout: float = 60) -> ChatFn:
    def chat(system: str, user: str) -> str:
        r = requests.post(
            f"{base_url}/api/chat",
            json={
                "model": model,
                "stream": False,
                "format": SCHEMA,  # Ollama >= 0.5 constrains decoding to the schema
                "options": {"temperature": 0},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            },
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json()["message"]["content"]

    return chat


DEEPSEEK_URL = "https://api.deepseek.com"
CLOUD_BACKENDS = {"deepseek", "openai"}
BACKENDS = ("deepseek", "none", "ollama", "openai")


def default_backend() -> str:
    """DeepSeek when a key is configured; otherwise the deterministic template."""
    return "deepseek" if os.environ.get("DEEPSEEK_API_KEY") else "none"


BREAKER_FAILURES = 3
BREAKER_PAUSE_S = 60.0
RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


def _post_with_backoff(url: str, headers: dict, body: dict, timeout: float, attempts: int = 3,
                       sleep: Callable[[float], None] = time.sleep) -> requests.Response:
    """POST, retrying transient failures (timeouts, connection errors, 429/5xx) with exponential backoff.

    A 4xx other than those (bad key, bad model, malformed request) raises at once: retrying cannot help.
    Honours Retry-After, capped at 30 s so a watch pass never stalls for long.
    """
    for attempt in range(attempts):
        try:
            r = requests.post(url, headers=headers, json=body, timeout=timeout)
            if r.status_code not in RETRYABLE_STATUS or attempt == attempts - 1:
                r.raise_for_status()
                return r
            retry_after = r.headers.get("Retry-After", "")
            wait = float(retry_after) if retry_after.isdigit() else 0
        except (requests.Timeout, requests.ConnectionError):
            if attempt == attempts - 1:
                raise
            wait = 0
        sleep(min(30.0, wait or 2.0 ** attempt))
    raise AssertionError("unreachable")


def deepseek_chat(model: str, base_url: str = DEEPSEEK_URL, timeout: float = 60, retries: int = 1) -> ChatFn:
    key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not key:
        raise ValueError("DEEPSEEK_API_KEY is not set")
    if not model:
        raise ValueError("no DeepSeek model set: pass --model or set DEEPSEEK_MODEL "
                         "(python -m nids llm-check lists the models your key can use)")

    def chat(system: str, user: str) -> str:
        for attempt in range(retries + 1):
            r = _post_with_backoff(
                f"{base_url}/chat/completions",
                {"Authorization": f"Bearer {key}"},
                {
                    "model": model,
                    "temperature": 0,
                    # JSON-object mode: valid JSON guaranteed, shape not. The system prompt
                    # contains the word "json" and the schema, as DeepSeek requires.
                    "response_format": {"type": "json_object"},
                    "stream": False,
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                },
                timeout,
            )
            content = (r.json()["choices"][0]["message"].get("content") or "").strip()
            if content or attempt == retries:
                return content  # an empty reply after the retry falls back to the template
        return ""

    return chat


def list_models(base_url: str = DEEPSEEK_URL, timeout: float = 20) -> list[str]:
    key = os.environ.get("DEEPSEEK_API_KEY", "")
    r = requests.get(f"{base_url}/models", headers={"Authorization": f"Bearer {key}"}, timeout=timeout)
    r.raise_for_status()
    return sorted(m["id"] for m in r.json().get("data", []))


def openai_chat(model: str, base_url: str = "https://api.openai.com/v1", timeout: float = 60) -> ChatFn:
    key = os.environ.get("OPENAI_API_KEY", "")

    def chat(system: str, user: str) -> str:
        r = requests.post(
            f"{base_url}/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "temperature": 0,
                "response_format": {"type": "json_schema",
                                    "json_schema": {"name": "incident_narrative", "schema": SCHEMA, "strict": False}},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            },
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    return chat


class Redactor:
    """Stable placeholders for internal addresses and asset names before cloud egress."""

    def __init__(self, assets: AssetRegistry):
        self.assets = assets
        self.fwd: dict[str, str] = {}

    def _alias(self, value: str, prefix: str) -> str:
        if value not in self.fwd:
            self.fwd[value] = f"{prefix}_{chr(ord('A') + len(self.fwd) % 26)}{len(self.fwd) // 26 or ''}"
        return self.fwd[value]

    def redact(self, evidence: dict) -> dict:
        out = {}
        for k, v in evidence.items():
            if isinstance(v, str):
                try:
                    if self.assets.is_internal(str(ipaddress.ip_address(v))):
                        v = self._alias(v, "INTERNAL_HOST")
                except ValueError:
                    if k == "asset_name":
                        v = self._alias(v, "ASSET")
            out[k] = v
        return out

    def restore(self, text: str) -> str:
        for real, alias in sorted(self.fwd.items(), key=lambda kv: -len(kv[1])):
            text = text.replace(alias, real)
        return text


class Explainer:
    def __init__(
        self,
        assets: AssetRegistry,
        backend: str = "none",
        model: str = "",
        chat: ChatFn | None = None,
        cache_get: Callable[[str], dict | None] | None = None,
        cache_put: Callable[[str, dict], None] | None = None,
        egress_log: Callable[[str, str, str], None] | None = None,
    ):
        self.assets = assets
        self.backend = backend
        self.model = model
        self.cache_get = cache_get or (lambda fp: None)
        self.cache_put = cache_put or (lambda fp, n: None)
        self.egress_log = egress_log or (lambda incident_id, backend, payload: None)
        self.failures = 0  # consecutive transport failures; at BREAKER_FAILURES the LLM is skipped for a while
        self.paused_until = 0.0
        if backend not in BACKENDS:
            raise ValueError(f"unknown LLM backend {backend!r}; choose from {BACKENDS}")
        if chat is not None:
            self.chat: ChatFn | None = chat
        elif backend == "deepseek":
            self.model = model or os.environ.get("DEEPSEEK_MODEL", "")
            self.chat = deepseek_chat(self.model, os.environ.get("DEEPSEEK_BASE_URL", DEEPSEEK_URL))
        elif backend == "ollama":
            self.chat = ollama_chat(model, os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
        elif backend == "openai":
            self.chat = openai_chat(model, os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"))
        else:
            self.chat = None

    def explain(self, incident: Incident, allowed_intents: list[str], default_intent: str) -> ExplainResult:
        fallback = template.render(incident, default_intent)
        if self.chat is None:
            return ExplainResult(fallback, False, "template", ["no LLM backend configured"], fallback)

        evidence = P.safe_evidence(incident)
        cls = P.classification(incident, allowed_intents)
        fp = P.fingerprint(evidence, cls, f"{self.backend}:{self.model}")
        cached = self.cache_get(fp)
        if cached:
            ok, narrative, reasons = validate(cached, incident, evidence, allowed_intents, default_intent)
            if ok and narrative:
                return ExplainResult(narrative, True, "cache", [], fallback)

        if time.monotonic() < self.paused_until:  # the service is failing: do not stall every incident on it
            return ExplainResult(fallback, False, "template", ["llm paused after repeated failures"], fallback)
        redactor = Redactor(self.assets) if self.backend in CLOUD_BACKENDS else None
        sent_evidence = redactor.redact(evidence) if redactor else evidence
        user = P.user_message(sent_evidence, cls, P.context(incident))
        if self.backend in CLOUD_BACKENDS:
            self.egress_log(incident.incident_id, self.backend, user)

        t0 = time.perf_counter()
        latency = None
        try:
            raw_text = self.chat(P.SYSTEM_PROMPT, user)
            self.failures = 0
            latency = round((time.perf_counter() - t0) * 1000, 1)
            if redactor:
                raw_text = redactor.restore(raw_text)
            raw = json.loads(raw_text)
            if not isinstance(raw, dict):
                raise ValueError("model did not return a JSON object")
        except (requests.RequestException, ValueError, KeyError) as exc:
            if isinstance(exc, requests.RequestException):
                self.failures += 1
                if self.failures >= BREAKER_FAILURES:
                    self.paused_until = time.monotonic() + BREAKER_PAUSE_S
                    self.failures = 0
            return ExplainResult(fallback, False, "template", [f"llm error: {type(exc).__name__}"], fallback, latency)

        ok, narrative, reasons = validate(raw, incident, evidence, allowed_intents, default_intent)
        if not ok or narrative is None:
            return ExplainResult(fallback, False, "template", reasons, fallback, latency)
        self.cache_put(fp, narrative.model_dump())
        return ExplainResult(narrative, True, "llm", [], fallback, latency)
