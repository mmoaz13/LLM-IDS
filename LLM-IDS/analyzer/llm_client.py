"""Sends prompts to a local Ollama model. Three entry points, all sharing the
same fail-safe transport call:
  - classify()      : flow -> Benign/Suspicious/Attack verdict (JSON)
  - generate_json()  : any prompt -> parsed dict, or {} on failure
  - generate_text()  : any prompt -> free-form string, for prose like reports

Install Ollama separately (not a pip package) from https://ollama.com, then:
    ollama pull llama3.1:8b
    ollama serve          # usually starts automatically after install
"""

import json

import requests

import config
from analyzer.prompt_builder import build_prompt

VALID_CLASSIFICATIONS = {"Benign", "Suspicious", "Attack"}


class LLMClient:
    def __init__(self, host: str = config.OLLAMA_HOST, model: str = config.OLLAMA_MODEL):
        self.host = host.rstrip("/")
        self.model = model

    def _call(self, prompt: str, json_format: bool) -> str:
        """Raw call to Ollama's /api/generate. Raises on transport failure —
        callers decide how to fail safe."""
        payload = {"model": self.model, "prompt": prompt, "stream": False}
        if json_format:
            payload["format"] = "json"  # constrains Ollama's output to valid JSON
        response = requests.post(
            f"{self.host}/api/generate",
            json=payload,
            timeout=config.LLM_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return response.json().get("response", "{}" if json_format else "")

    def classify(self, features: dict) -> dict:
        prompt = build_prompt(features)
        try:
            verdict = json.loads(self._call(prompt, json_format=True))
        except (requests.RequestException, json.JSONDecodeError, ValueError) as exc:
            # Fail SAFE: an IDS that goes quiet on error is worse than one
            # that over-flags, so a broken LLM call becomes "Suspicious",
            # never "Benign".
            verdict = {
                "classification": "Suspicious",
                "confidence": 0.0,
                "explanation": f"LLM call failed, flagged for manual review ({exc})",
            }

        verdict.setdefault("classification", "Suspicious")
        verdict.setdefault("confidence", 0.0)
        verdict.setdefault("explanation", "No explanation returned.")

        if verdict["classification"] not in VALID_CLASSIFICATIONS:
            # Fail SAFE: an unrecognized label (model drift, malformed JSON
            # value) must not slip past the dashboard's known categories.
            verdict["explanation"] = (
                f"LLM returned unrecognized classification "
                f"{verdict['classification']!r}, flagged for manual review. "
                f"{verdict['explanation']}"
            )
            verdict["classification"] = "Suspicious"

        return verdict

    def generate_json(self, prompt: str) -> dict:
        """For structured-but-not-classification uses (e.g. parsing a natural
        language question into query filters). Fails safe to {} — callers
        must treat an empty dict as "no reliable structure came back",
        never as a set of filters that happens to be empty."""
        try:
            return json.loads(self._call(prompt, json_format=True))
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            return {}

    def generate_text(self, prompt: str, fallback: str = "") -> str:
        """For free-form prose (e.g. incident reports, NL answers). Fails
        safe to `fallback` (or a generic error string) rather than raising,
        so a broken LLM call degrades a report instead of crashing the
        dashboard."""
        try:
            return self._call(prompt, json_format=False).strip()
        except requests.RequestException as exc:
            return fallback or f"LLM call failed: {exc}"
