"""
=============================================================================
test_llm_client.py — Test suite for analyzer/llm_client.py
=============================================================================

Coverage areas
--------------
  1. Successful classification        (well-formed Ollama response is parsed)
  2. Fail-safe on transport errors     (network failure -> Suspicious, not Benign)
  3. Fail-safe on malformed responses  (bad JSON / non-2xx -> Suspicious)
  4. Missing-field defaults            (partial verdict dict gets filled in)
  5. Unrecognized classification guard (model drift -> coerced to Suspicious)
  6. Request construction              (host/model/endpoint wired correctly)

All tests mock `requests.post` — no real Ollama server or network access
is required.

Run
---
    pytest tests/test_llm_client.py -v

Requirements
------------
    pip install pytest
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.llm_client import LLMClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_FEATURES = {
    "flow_id": "10.0.0.1:5000->10.0.0.2:80/TCP",
    "statistics": {"duration_seconds": 1.0, "packet_count": 4, "byte_count": 400,
                    "avg_packet_size": 100.0, "packets_per_second": 4.0,
                    "fwd_packet_count": 2, "rev_packet_count": 2},
    "protocol_info": {"protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                       "src_port": 5000, "dst_port": 80},
    "flags": {"syn_count": 1, "ack_count": 3, "fin_count": 0, "rst_count": 0,
              "psh_count": 1, "urg_count": 0, "syn_without_ack": False},
}


def _mock_ollama_response(body_json: str, status_code: int = 200):
    """Build a MagicMock standing in for requests.Response from Ollama's
    /api/generate, where `body_json` is the *inner* string the model returned
    (Ollama wraps it in a {"response": "<json string>"} envelope)."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"response": body_json}
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error")
    else:
        resp.raise_for_status.return_value = None
    return resp


# ===========================================================================
# 1. Successful classification
# ===========================================================================

class TestSuccessfulClassification:

    @patch("analyzer.llm_client.requests.post")
    def test_well_formed_response_is_parsed(self, mock_post):
        mock_post.return_value = _mock_ollama_response(
            '{"classification": "Benign", "confidence": 0.92, "explanation": "Normal handshake."}'
        )
        client = LLMClient(host="http://localhost:11434", model="llama3.1:8b")
        verdict = client.classify(SAMPLE_FEATURES)

        assert verdict["classification"] == "Benign"
        assert verdict["confidence"] == 0.92
        assert verdict["explanation"] == "Normal handshake."

    @patch("analyzer.llm_client.requests.post")
    def test_attack_classification_is_parsed(self, mock_post):
        mock_post.return_value = _mock_ollama_response(
            '{"classification": "Attack", "confidence": 0.98, "explanation": "SYN flood pattern."}'
        )
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["classification"] == "Attack"


# ===========================================================================
# 2. Fail-safe on transport errors
# ===========================================================================

class TestTransportFailSafe:

    @patch("analyzer.llm_client.requests.post")
    def test_connection_error_falls_back_to_suspicious(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("connection refused")
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)

        assert verdict["classification"] == "Suspicious"
        assert verdict["confidence"] == 0.0
        assert "connection refused" in verdict["explanation"]

    @patch("analyzer.llm_client.requests.post")
    def test_timeout_falls_back_to_suspicious(self, mock_post):
        mock_post.side_effect = requests.Timeout("timed out")
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["classification"] == "Suspicious"

    @patch("analyzer.llm_client.requests.post")
    def test_http_error_status_falls_back_to_suspicious(self, mock_post):
        mock_post.return_value = _mock_ollama_response("{}", status_code=500)
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["classification"] == "Suspicious"

    @patch("analyzer.llm_client.requests.post")
    def test_transport_error_never_yields_benign(self, mock_post):
        """Regression guard for the project's core fail-safe design: a broken
        LLM call must never silently classify as Benign."""
        mock_post.side_effect = requests.RequestException("boom")
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["classification"] != "Benign"


# ===========================================================================
# 3. Fail-safe on malformed responses
# ===========================================================================

class TestMalformedResponseFailSafe:

    @patch("analyzer.llm_client.requests.post")
    def test_invalid_json_falls_back_to_suspicious(self, mock_post):
        mock_post.return_value = _mock_ollama_response("not valid json {{{")
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["classification"] == "Suspicious"
        assert verdict["confidence"] == 0.0

    @patch("analyzer.llm_client.requests.post")
    def test_empty_response_body_falls_back_to_suspicious(self, mock_post):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {}  # no "response" key at all
        resp.raise_for_status.return_value = None
        mock_post.return_value = resp

        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["classification"] == "Suspicious"


# ===========================================================================
# 4. Missing-field defaults
# ===========================================================================

class TestMissingFieldDefaults:

    @patch("analyzer.llm_client.requests.post")
    def test_missing_confidence_defaults_to_zero(self, mock_post):
        mock_post.return_value = _mock_ollama_response(
            '{"classification": "Benign", "explanation": "Looks fine."}'
        )
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["confidence"] == 0.0

    @patch("analyzer.llm_client.requests.post")
    def test_missing_explanation_gets_placeholder(self, mock_post):
        mock_post.return_value = _mock_ollama_response(
            '{"classification": "Benign", "confidence": 0.7}'
        )
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["explanation"] == "No explanation returned."

    @patch("analyzer.llm_client.requests.post")
    def test_missing_classification_defaults_to_suspicious(self, mock_post):
        mock_post.return_value = _mock_ollama_response(
            '{"confidence": 0.5, "explanation": "Ambiguous."}'
        )
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["classification"] == "Suspicious"


# ===========================================================================
# 5. Unrecognized classification guard
# ===========================================================================

class TestUnrecognizedClassificationGuard:

    @patch("analyzer.llm_client.requests.post")
    def test_unknown_label_is_coerced_to_suspicious(self, mock_post):
        mock_post.return_value = _mock_ollama_response(
            '{"classification": "Unknown", "confidence": 0.6, "explanation": "Unclear traffic."}'
        )
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["classification"] == "Suspicious"
        assert "Unknown" in verdict["explanation"]

    @patch("analyzer.llm_client.requests.post")
    def test_lowercase_variant_is_not_silently_accepted(self, mock_post):
        """Classification values are matched exactly against the known set —
        a case variation like 'benign' must not slip through as valid."""
        mock_post.return_value = _mock_ollama_response(
            '{"classification": "benign", "confidence": 0.9, "explanation": "ok"}'
        )
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["classification"] == "Suspicious"

    @pytest.mark.parametrize("valid_label", ["Benign", "Suspicious", "Attack"])
    @patch("analyzer.llm_client.requests.post")
    def test_valid_labels_pass_through_unchanged(self, mock_post, valid_label):
        mock_post.return_value = _mock_ollama_response(
            f'{{"classification": "{valid_label}", "confidence": 0.8, "explanation": "x"}}'
        )
        client = LLMClient()
        verdict = client.classify(SAMPLE_FEATURES)
        assert verdict["classification"] == valid_label


# ===========================================================================
# 6. Request construction
# ===========================================================================

class TestRequestConstruction:

    @patch("analyzer.llm_client.requests.post")
    def test_posts_to_generate_endpoint_with_trailing_slash_stripped(self, mock_post):
        mock_post.return_value = _mock_ollama_response(
            '{"classification": "Benign", "confidence": 0.9, "explanation": "x"}'
        )
        client = LLMClient(host="http://localhost:11434/", model="phi3")
        client.classify(SAMPLE_FEATURES)

        called_url = mock_post.call_args[0][0]
        assert called_url == "http://localhost:11434/api/generate"

    @patch("analyzer.llm_client.requests.post")
    def test_request_payload_includes_model_and_json_format(self, mock_post):
        mock_post.return_value = _mock_ollama_response(
            '{"classification": "Benign", "confidence": 0.9, "explanation": "x"}'
        )
        client = LLMClient(host="http://localhost:11434", model="mistral")
        client.classify(SAMPLE_FEATURES)

        payload = mock_post.call_args.kwargs["json"]
        assert payload["model"] == "mistral"
        assert payload["stream"] is False
        assert payload["format"] == "json"
        assert "flow_id" in payload["prompt"]
