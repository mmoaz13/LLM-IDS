"""Turns one already-classified flow_results row (as stored by storage/db.py)
into a written incident report — the same underlying data as the one-line
dashboard explanation, but expanded into something an analyst could actually
hand off: summary, evidence, potential impact, recommended remediation.
"""

import json

REPORT_SYSTEM_INSTRUCTIONS = """
You are a security analyst writing an incident report for one network flow
that has already been classified by an automated system. Use only the data
provided — do not invent additional evidence, IPs, or context.

Write the report in Markdown with exactly these sections:

## Incident Report: <flow_id>

### Summary
One or two sentences: what happened and the classification.

### Evidence
Bullet points citing the specific statistics/flags that support the
classification (packet counts, rates, flags, ports — whatever is relevant
from the supplied data).

### Potential Impact
1-2 sentences on what this traffic pattern could mean if it were a genuine
attack (or, if Benign, briefly note why it's low-risk).

### Recommended Remediation
2-4 concrete, actionable bullet points appropriate to the classification and
severity. For Benign flows, a brief "no action needed" is enough.

Keep the whole report concise — it should be readable in under a minute.
"""


def build_report_prompt(flow_row: dict) -> str:
    features = flow_row.get("features_json")
    if isinstance(features, str):
        try:
            features = json.loads(features)
        except (json.JSONDecodeError, ValueError):
            features = {}

    data = {
        "flow_id": flow_row.get("flow_id"),
        "classification": flow_row.get("classification"),
        "confidence": flow_row.get("confidence"),
        "explanation": flow_row.get("explanation"),
        "features": features,
    }
    return f"{REPORT_SYSTEM_INSTRUCTIONS}\nFlow data:\n{json.dumps(data, indent=2)}\n"


def generate(flow_row: dict, llm_client) -> str:
    flow_id = flow_row.get("flow_id", "unknown flow")
    fallback = (
        f"## Incident Report: {flow_id}\n\n"
        f"Report generation failed. Stored verdict: "
        f"**{flow_row.get('classification', 'Unknown')}** "
        f"({flow_row.get('explanation', 'no explanation available')})."
    )
    return llm_client.generate_text(build_report_prompt(flow_row), fallback=fallback)
