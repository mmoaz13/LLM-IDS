"""
=============================================================================
test_query_parser.py — Test suite for analyzer/query_parser.py
=============================================================================

Coverage areas
--------------
  1. parse() field validation   (only recognized, well-typed keys survive)
  2. parse() fail-safe behavior (bad/missing LLM output -> safe default)
  3. summarize() behavior       (empty results, normal results, LLM failure)

All tests use a fake LLMClient stand-in (not the real network client) so
this module's own logic is what's under test, independent of llm_client.py.

Run
---
    pytest tests/test_query_parser.py -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer import query_parser

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeLLMClient:
    """Stands in for analyzer.llm_client.LLMClient. Returns whatever was
    configured, regardless of the prompt, so tests can focus on how
    query_parser processes the response."""

    def __init__(self, json_response=None, text_response="a summary"):
        self._json_response = json_response if json_response is not None else {}
        self._text_response = text_response
        self.last_prompt = None

    def generate_json(self, prompt):
        self.last_prompt = prompt
        return self._json_response

    def generate_text(self, prompt, fallback=""):
        self.last_prompt = prompt
        return self._text_response


# ===========================================================================
# 1. parse() field validation
# ===========================================================================

class TestParseFieldValidation:

    def test_valid_classification_is_kept(self):
        llm = FakeLLMClient(json_response={"classification": "Attack"})
        filters = query_parser.parse("show attacks", llm)
        assert filters["classification"] == "Attack"

    def test_invalid_classification_is_dropped(self):
        llm = FakeLLMClient(json_response={"classification": "Malicious"})
        filters = query_parser.parse("show bad stuff", llm)
        assert "classification" not in filters

    def test_protocol_is_uppercased_and_trimmed(self):
        llm = FakeLLMClient(json_response={"protocol": " tcp "})
        filters = query_parser.parse("tcp flows", llm)
        assert filters["protocol"] == "TCP"

    def test_blank_protocol_is_dropped(self):
        llm = FakeLLMClient(json_response={"protocol": "   "})
        filters = query_parser.parse("flows", llm)
        assert "protocol" not in filters

    def test_ip_fields_are_kept_when_present(self):
        llm = FakeLLMClient(json_response={"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"})
        filters = query_parser.parse("flows from 1.2.3.4", llm)
        assert filters["src_ip"] == "1.2.3.4"
        assert filters["dst_ip"] == "5.6.7.8"

    def test_non_string_ip_is_dropped(self):
        llm = FakeLLMClient(json_response={"src_ip": 12345})
        filters = query_parser.parse("flows", llm)
        assert "src_ip" not in filters

    def test_valid_port_is_kept_as_int(self):
        llm = FakeLLMClient(json_response={"port": 22})
        filters = query_parser.parse("port 22 traffic", llm)
        assert filters["port"] == 22
        assert isinstance(filters["port"], int)

    def test_out_of_range_port_is_dropped(self):
        llm = FakeLLMClient(json_response={"port": 99999})
        filters = query_parser.parse("flows", llm)
        assert "port" not in filters

    def test_zero_port_is_dropped(self):
        llm = FakeLLMClient(json_response={"port": 0})
        filters = query_parser.parse("flows", llm)
        assert "port" not in filters

    def test_boolean_port_is_dropped(self):
        """bool is a subclass of int in Python — must not slip through as a port."""
        llm = FakeLLMClient(json_response={"port": True})
        filters = query_parser.parse("flows", llm)
        assert "port" not in filters

    def test_since_minutes_ago_is_kept_as_int(self):
        llm = FakeLLMClient(json_response={"since_minutes_ago": 60})
        filters = query_parser.parse("last hour", llm)
        assert filters["since_minutes_ago"] == 60

    def test_negative_since_minutes_ago_is_dropped(self):
        llm = FakeLLMClient(json_response={"since_minutes_ago": -5})
        filters = query_parser.parse("flows", llm)
        assert "since_minutes_ago" not in filters

    def test_unrecognized_keys_are_ignored(self):
        llm = FakeLLMClient(json_response={"sql": "DROP TABLE flow_results", "classification": "Benign"})
        filters = query_parser.parse("flows", llm)
        assert "sql" not in filters
        assert filters["classification"] == "Benign"


# ===========================================================================
# 2. parse() fail-safe behavior
# ===========================================================================

class TestParseFailSafe:

    def test_empty_llm_response_yields_default_limit_only(self):
        llm = FakeLLMClient(json_response={})
        filters = query_parser.parse("anything", llm)
        assert filters == {"limit": query_parser.DEFAULT_LIMIT}

    def test_non_dict_llm_response_yields_default_limit_only(self):
        llm = FakeLLMClient(json_response=[1, 2, 3])
        filters = query_parser.parse("anything", llm)
        assert filters == {"limit": query_parser.DEFAULT_LIMIT}

    def test_custom_limit_is_capped_at_max(self):
        llm = FakeLLMClient(json_response={"limit": 999999})
        filters = query_parser.parse("everything", llm)
        assert filters["limit"] == query_parser.MAX_LIMIT

    def test_valid_custom_limit_is_kept(self):
        llm = FakeLLMClient(json_response={"limit": 10})
        filters = query_parser.parse("a few flows", llm)
        assert filters["limit"] == 10

    def test_invalid_limit_falls_back_to_default(self):
        llm = FakeLLMClient(json_response={"limit": "lots"})
        filters = query_parser.parse("flows", llm)
        assert filters["limit"] == query_parser.DEFAULT_LIMIT


# ===========================================================================
# 3. summarize()
# ===========================================================================

class TestSummarize:

    def test_empty_results_short_circuits_without_calling_llm(self):
        llm = FakeLLMClient(text_response="should not be used")
        answer = query_parser.summarize("anything", [], llm)
        assert answer == "No matching flows found."
        assert llm.last_prompt is None  # never called

    def test_non_empty_results_returns_llm_text(self):
        llm = FakeLLMClient(text_response="Found 3 attack flows targeting port 22.")
        results = [{"flow_id": "a", "classification": "Attack", "confidence": 0.9,
                    "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "dst_port": 22,
                    "protocol": "TCP", "explanation": "SYN flood"}]
        answer = query_parser.summarize("port 22 attacks?", results, llm)
        assert answer == "Found 3 attack flows targeting port 22."

    def test_prompt_includes_the_question_and_flow_data(self):
        llm = FakeLLMClient()
        results = [{"flow_id": "abc", "classification": "Benign", "confidence": 0.5,
                    "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dst_port": 443,
                    "protocol": "TCP", "explanation": "normal"}]
        query_parser.summarize("what happened?", results, llm)
        assert "what happened?" in llm.last_prompt
        assert "abc" in llm.last_prompt
