"""Lets the dashboard answer natural-language questions about stored flow
results ("show me attack flows targeting port 22 last night") without
letting the LLM anywhere near raw SQL.

Two stages:
  1. parse()     — LLM turns the question into a small filter JSON, which we
                    validate field-by-field against a known-safe shape.
  2. summarize()  — LLM turns the (already-filtered, already-fetched) rows
                    back into a short natural-language answer.

storage.db.query_results() is the only thing that ever touches SQL, and it
only accepts the specific keys this module produces — the LLM never
supplies query text, only values.
"""

import json
from collections import Counter

from analyzer.llm_client import VALID_CLASSIFICATIONS

DEFAULT_LIMIT = 50
MAX_LIMIT = 500

QUERY_SYSTEM_INSTRUCTIONS = f"""
You interpret a question typed into a network flow log search box. Return
ONLY a valid JSON object with these keys:

{{
  "is_flow_question": true if the question is actually asking about the
      captured network flow data — classifications, IPs, ports, protocols,
      attacks, time ranges, and similar. false for anything else: greetings,
      small talk, questions unrelated to network data, or requests that
      have nothing to do with the flow log (e.g. "how are you?", "what's
      the weather?", "tell me a joke", "write me a poem"). When in doubt
      between "genuinely about the flow data" and "not", prefer false.,
  "classification": one of {sorted(VALID_CLASSIFICATIONS)},
  "protocol": e.g. "TCP" or "UDP",
  "src_ip": a specific source IP mentioned in the question,
  "dst_ip": a specific destination IP mentioned in the question,
  "port": a specific port number mentioned (matches either side of the flow),
  "since_minutes_ago": how many minutes back the question implies
      (e.g. "last hour" -> 60, "today" -> 1440, "last night" -> 720,
      "this week" -> 10080). Omit if no time frame is mentioned.,
  "limit": max rows to return, default 50 if not specified
}}

Omit classification/protocol/src_ip/dst_ip/port/since_minutes_ago/limit
entirely unless is_flow_question is true AND the question gives clear
evidence for that specific key. Do not guess IP addresses or ports that
were not mentioned. Return nothing but the JSON object — no prose, no
markdown fences.
"""


def build_query_prompt(question: str) -> str:
    return f"{QUERY_SYSTEM_INSTRUCTIONS}\nQuestion: {question}\n"


def _validate_filters(raw: dict) -> dict:
    filters: dict = {}

    classification = raw.get("classification")
    if classification in VALID_CLASSIFICATIONS:
        filters["classification"] = classification

    protocol = raw.get("protocol")
    if isinstance(protocol, str) and protocol.strip():
        filters["protocol"] = protocol.strip().upper()

    for field in ("src_ip", "dst_ip"):
        value = raw.get(field)
        if isinstance(value, str) and value.strip():
            filters[field] = value.strip()

    port = raw.get("port")
    if isinstance(port, (int, float)) and not isinstance(port, bool) and 0 < int(port) <= 65535:
        filters["port"] = int(port)

    since = raw.get("since_minutes_ago")
    if isinstance(since, (int, float)) and not isinstance(since, bool) and since > 0:
        filters["since_minutes_ago"] = int(since)

    limit = raw.get("limit")
    if isinstance(limit, (int, float)) and not isinstance(limit, bool) and limit > 0:
        filters["limit"] = min(int(limit), MAX_LIMIT)
    else:
        filters["limit"] = DEFAULT_LIMIT

    return filters


def interpret(question: str, llm_client):
    """Single LLM call that both decides whether the question is actually
    about the captured flow data, and (regardless) extracts whatever
    filters it can. Returns (filters, is_flow_question).

    Fails safe to (limit-only filters, True) on a missing/malformed LLM
    response — an unnecessary query against real data is harmless; the
    worse failure mode is wrongly refusing a legitimate question. But when
    the model *does* respond and clearly says this isn't a flow question
    (e.g. "how are you?"), that must be honored — otherwise every
    off-topic message gets a real-data-flavored answer stitched onto it,
    which is worse than just declining.
    """
    raw = llm_client.generate_json(build_query_prompt(question))
    if not isinstance(raw, dict):
        raw = {}

    is_relevant = raw.get("is_flow_question", True)
    if not isinstance(is_relevant, bool):
        is_relevant = True

    filters = _validate_filters(raw)
    return filters, is_relevant


def parse(question: str, llm_client) -> dict:
    """Turn a natural-language question into a validated filter dict safe to
    pass to storage.db.query_results(). Fails safe to an unfiltered, capped
    query (limit only) if the LLM output is missing, malformed, or contains
    values outside the expected shape.

    This is the filters-only view of interpret() — prefer interpret()
    directly when you also need to know whether the question was actually
    about flow data (e.g. before running a query/summary pipeline at all).
    """
    filters, _ = interpret(question, llm_client)
    return filters


SUMMARY_SYSTEM_INSTRUCTIONS = """
You are a security analyst answering a colleague's direct question about
network flow data, out loud, in conversation. You're given the question,
some pre-computed statistics, and a sample of the actual matching records.

Answer the question directly in 2-3 sentences, as if speaking to the person
who asked — not writing documentation about the data. Use the specific
numbers, IPs, ports, and patterns provided; do not invent anything not
present. The statistics are already computed correctly — use them as-is
rather than recounting from the sample yourself.

Do NOT:
- Describe the JSON structure, field names, or what a "flow_id" or
  "classification" field means.
- Explain what the data "could be used for," or suggest analysis techniques
  (filtering, grouping, visualization, statistics) the person could run.
- Offer to help further, ask what they'd like to explore next, or add any
  closing remark beyond the answer itself.
- Repeat the question back before answering it.

Just answer it. If nothing matched, say that plainly in one sentence.
"""


def _aggregate_stats(results: list) -> dict:
    """Pre-computed, guaranteed-accurate numbers for the prompt — small
    models are unreliable at counting/grouping a few dozen JSON records
    themselves, and tend to fill that gap with generic commentary instead.
    Handing over the actual counts keeps the answer grounded and specific."""
    classifications = Counter(r.get("classification") for r in results if r.get("classification"))
    protocols = Counter(r.get("protocol") for r in results if r.get("protocol"))
    dst_ports = Counter(r.get("dst_port") for r in results if r.get("dst_port"))
    src_ips = Counter(r.get("src_ip") for r in results if r.get("src_ip"))
    return {
        "total_matching_flows": len(results),
        "count_by_classification": dict(classifications),
        "count_by_protocol": dict(protocols),
        "most_common_destination_ports": dst_ports.most_common(5),
        "most_common_source_ips": src_ips.most_common(5),
    }


def build_summary_prompt(question: str, results: list) -> str:
    stats = _aggregate_stats(results)
    sample = [
        {
            "flow_id": r.get("flow_id"),
            "classification": r.get("classification"),
            "confidence": r.get("confidence"),
            "src_ip": r.get("src_ip"),
            "dst_ip": r.get("dst_ip"),
            "dst_port": r.get("dst_port"),
            "protocol": r.get("protocol"),
            "explanation": r.get("explanation"),
        }
        for r in results[:15]
    ]
    return (
        f"{SUMMARY_SYSTEM_INSTRUCTIONS}\n"
        f"Question: {question}\n\n"
        f"Statistics across all {len(results)} matching flows (already computed — use these numbers):\n"
        f"{json.dumps(stats, indent=2)}\n\n"
        f"Sample records ({len(sample)} of {len(results)} shown):\n"
        f"{json.dumps(sample, indent=2)}\n\n"
        f"Now answer this question in 2-3 sentences: {question}"
    )


def summarize(question: str, results: list, llm_client) -> str:
    if not results:
        return "No matching flows found."
    fallback = f"Found {len(results)} matching flow(s), but the summary could not be generated."
    return llm_client.generate_text(build_summary_prompt(question, results), fallback=fallback)
