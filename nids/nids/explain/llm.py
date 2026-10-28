"""Plane 5: direct LLM client (~no framework, so the trust boundary stays readable).

Backends
  none    template only (default; the demo floor never depends on a model)
  ollama  local, e.g. llama3.1:8b. No telemetry leaves the host.
  openai  any OpenAI-compatible /chat/completions endpoint. Internal IPs and asset names
          are replaced by stable placeholders before egress, and every egress is logged.
"""
from __future__ import annotations

import ipaddress
import json
import os
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


def ollama_chat(model: str, base_url: str = "http://127.0.0.1:11434", timeout: float = 60) -> ChatFn:
    def chat(system: str, user: str) -> str:
        r = requests.post(
            f"{base_url}/api/chat",
            json={
                "model": model,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            },
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json()["message"]["content"]

    return chat


def openai_chat(model: str, base_url: str = "https://api.openai.com/v1", timeout: float = 60) -> ChatFn:
    key = os.environ.get("OPENAI_API_KEY", "")

    def chat(system: str, user: str) -> str:
        r = requests.post(
            f"{base_url}/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
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
        model: str = "llama3.1:8b",
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
        if chat is not None:
            self.chat: ChatFn | None = chat
        elif backend == "ollama":
            self.chat = ollama_chat(model, os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
        elif backend == "openai":
            self.chat = openai_chat(model, os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"))
        else:
            self.chat = None

    def explain(self, incident: Incident, allowed_intents: list[str], default_intent: str) -> ExplainResult:
        fallback = template.render(incident, default_intent)
        if self.chat is None:
            return ExplainResult(fallback, False, "template", ["no LLM backend configured"])

        evidence = P.safe_evidence(incident)
        cls = P.classification(incident, allowed_intents)
        fp = P.fingerprint(evidence, cls, f"{self.backend}:{self.model}")
        cached = self.cache_get(fp)
        if cached:
            ok, narrative, reasons = validate(cached, incident, evidence, allowed_intents, default_intent)
            if ok and narrative:
                return ExplainResult(narrative, True, "cache")

        redactor = Redactor(self.assets) if self.backend == "openai" else None
        sent_evidence = redactor.redact(evidence) if redactor else evidence
        user = P.user_message(sent_evidence, cls)
        if self.backend != "ollama":
            self.egress_log(incident.incident_id, self.backend, user)

        try:
            raw_text = self.chat(P.SYSTEM_PROMPT, user)
            if redactor:
                raw_text = redactor.restore(raw_text)
            raw = json.loads(raw_text)
            if not isinstance(raw, dict):
                raise ValueError("model did not return a JSON object")
        except (requests.RequestException, ValueError, KeyError) as exc:
            return ExplainResult(fallback, False, "template", [f"llm error: {type(exc).__name__}"])

        ok, narrative, reasons = validate(raw, incident, evidence, allowed_intents, default_intent)
        if not ok or narrative is None:
            return ExplainResult(fallback, False, "template", reasons)
        self.cache_put(fp, narrative.model_dump())
        return ExplainResult(narrative, True, "llm")
