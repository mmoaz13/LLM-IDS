"""Sends a flow prompt to a local Ollama model and parses the JSON verdict.

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

    def classify(self, features: dict) -> dict:
        prompt = build_prompt(features)
        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",  # tells Ollama to constrain output to valid JSON
                },
                timeout=config.LLM_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            raw_text = response.json().get("response", "{}")
            verdict = json.loads(raw_text)
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