"""
=============================================================================
test_report_generator.py — Test suite for analyzer/report_generator.py
=============================================================================

Coverage areas
--------------
  1. build_report_prompt()  (features_json string is decoded and included)
  2. generate()             (delegates to llm_client.generate_text)
  3. Fail-safe fallback     (a broken LLM call still yields a usable report)

Run
---
    pytest tests/test_report_generator.py -v
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer import report_generator

# ---------------------------------------------------------------------------
# Fakes / helpers
# ---------------------------------------------------------------------------


class FakeLLMClient:
    def __init__(self, text_response="## Incident Report\n\nDetails here."):
        self._text_response = text_response
        self.last_prompt = None
        self.last_fallback = None

    def generate_text(self, prompt, fallback=""):
        self.last_prompt = prompt
        self.last_fallback = fallback
        if self._text_response is None:
            return fallback
        return self._text_response


def _sample_row(features_json_as_string=True):
    features = {
        "flow_id": "10.0.0.1:5000->10.0.0.2:80/TCP",
        "statistics": {"packet_count": 200, "packets_per_second": 500.0},
        "protocol_info": {"protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                           "src_port": 5000, "dst_port": 80},
        "flags": {"syn_count": 200, "ack_count": 0, "syn_without_ack": True},
    }
    return {
        "flow_id": "10.0.0.1:5000->10.0.0.2:80/TCP",
        "classification": "Attack",
        "confidence": 0.97,
        "explanation": "SYN flood pattern.",
        "features_json": json.dumps(features) if features_json_as_string else features,
    }


# ===========================================================================
# 1. build_report_prompt()
# ===========================================================================

class TestBuildReportPrompt:

    def test_prompt_includes_core_fields(self):
        row = _sample_row()
        prompt = report_generator.build_report_prompt(row)
        assert row["flow_id"] in prompt
        assert "Attack" in prompt
        assert "SYN flood pattern." in prompt

    def test_features_json_string_is_decoded_into_prompt(self):
        row = _sample_row()
        prompt = report_generator.build_report_prompt(row)
        assert '"syn_count": 200' in prompt

    def test_already_decoded_features_dict_is_handled(self):
        """flow_row['features_json'] might already be a dict (e.g. supplied
        directly rather than read back from SQLite) — must not crash."""
        row = _sample_row(features_json_as_string=False)
        prompt = report_generator.build_report_prompt(row)
        assert "syn_count" in prompt

    def test_malformed_features_json_does_not_raise(self):
        row = _sample_row()
        row["features_json"] = "not valid json {{{"
        prompt = report_generator.build_report_prompt(row)  # must not raise
        assert row["flow_id"] in prompt


# ===========================================================================
# 2. generate()
# ===========================================================================

class TestGenerate:

    def test_returns_llm_text(self):
        llm = FakeLLMClient(text_response="## Incident Report: x\n\nSome content.")
        row = _sample_row()
        report = report_generator.generate(row, llm)
        assert report == "## Incident Report: x\n\nSome content."

    def test_prompt_passed_to_llm_includes_flow_data(self):
        llm = FakeLLMClient()
        row = _sample_row()
        report_generator.generate(row, llm)
        assert row["flow_id"] in llm.last_prompt


# ===========================================================================
# 3. Fail-safe fallback
# ===========================================================================

class TestFailSafeFallback:

    def test_fallback_used_when_llm_returns_it(self):
        """generate_text() itself decides when to fall back (e.g. on a
        transport error) — this test simulates that by having the fake
        return whatever fallback it was given, and checks the fallback
        text is still a usable report referencing the stored verdict."""
        llm = FakeLLMClient(text_response=None)
        row = _sample_row()
        report = report_generator.generate(row, llm)
        assert row["flow_id"] in report
        assert "Attack" in report
        assert "SYN flood pattern." in report

    def test_fallback_handles_missing_fields_gracefully(self):
        llm = FakeLLMClient(text_response=None)
        row = {"flow_id": "unknown"}  # minimal row, missing most fields
        report = report_generator.generate(row, llm)  # must not raise
        assert "unknown" in report
