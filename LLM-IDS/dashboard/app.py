"""Streamlit dashboard — two tabs:
  • Live Monitor  : reads results written by main.py in real time
  • Upload PCAP   : upload a .pcap file, analyze it on the spot, show results
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from storage import db
from sniffer.pcap_reader import process_pcap
from analyzer.llm_client import LLMClient
from storage.db import save_result

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="LLM-IDS Dashboard", layout="wide")

st.markdown(
    """
    <style>
    .app-header {
        display: flex;
        flex-direction: column;
        gap: 0.15rem;
        margin-bottom: 1.25rem;
    }
    .app-header h1 {
        font-size: 1.6rem;
        font-weight: 600;
        margin: 0;
    }
    .app-header p {
        color: rgba(255,255,255,0.55);
        font-size: 0.9rem;
        margin: 0;
    }
    .status-pill {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .status-benign     { background-color: #16321f; color: #4ade80; }
    .status-suspicious { background-color: #3a2f0d; color: #facc15; }
    .status-attack      { background-color: #3a1414; color: #f87171; }
    </style>
    <div class="app-header">
        <h1>LLM-Powered Intrusion Detection System</h1>
        <p>Network flow classification via local LLM analysis</p>
    </div>
    """,
    unsafe_allow_html=True,
)

db.init_db()
llm = LLMClient()

TAB_LIVE, TAB_UPLOAD = st.tabs(["Live Monitor", "Upload PCAP"])

# ── Shared helpers ────────────────────────────────────────────────────────────

ROW_COLORS = {"Benign": "#132015", "Suspicious": "#26200c", "Attack": "#2a1414"}
PILL_CLASS = {"Benign": "status-benign", "Suspicious": "status-suspicious", "Attack": "status-attack"}


def _status_pill(label: str) -> str:
    cls = PILL_CLASS.get(label, "")
    return f'<span class="status-pill {cls}">{label}</span>'


def _highlight(row):
    color = ROW_COLORS.get(row["classification"], "")
    return [f"background-color: {color}"] * len(row)


def _render_metrics(df: pd.DataFrame):
    counts = df["classification"].value_counts()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total flows", len(df))
    c2.metric("Benign", int(counts.get("Benign", 0)))
    c3.metric("Suspicious", int(counts.get("Suspicious", 0)))
    c4.metric("Attack", int(counts.get("Attack", 0)))


def _render_table(df: pd.DataFrame, cols=None):
    cols = cols or ["timestamp", "flow_id", "classification", "confidence", "explanation"]
    existing = [c for c in cols if c in df.columns]
    st.dataframe(
        df[existing].style.apply(_highlight, axis=1),
        use_container_width=True,
        height=480,
    )


# ── Tab 1: Live Monitor ───────────────────────────────────────────────────────

with TAB_LIVE:
    st.subheader("Real-time flow analysis from network interfaces")
    st.caption("Results are written here by `main.py`. Click Refresh to pull the latest.")

    col_refresh, col_limit = st.columns([1, 3])
    with col_refresh:
        if st.button("Refresh"):
            st.rerun()
    with col_limit:
        limit = st.slider("Rows to show", 10, 500, 100, key="live_limit")

    results = db.get_recent_results(limit=limit)

    if not results:
        st.info("No flows yet. Make sure `main.py` is running and traffic is being generated.")
    else:
        df = pd.DataFrame(results)
        df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")

        _render_metrics(df)
        st.divider()

        filter_opt = st.selectbox(
            "Filter by classification",
            ["All", "Attack", "Suspicious", "Benign"],
            key="live_filter"
        )
        if filter_opt != "All":
            df = df[df["classification"] == filter_opt]

        _render_table(df, ["timestamp", "flow_id", "classification", "confidence", "explanation"])


# ── Tab 2: Upload PCAP ────────────────────────────────────────────────────────

with TAB_UPLOAD:
    st.subheader("Analyze a .pcap / .pcapng capture file")
    st.caption(
        "Packets are extracted, grouped into flows, and classified by the local LLM — "
        "the same pipeline as live capture."
    )

    uploaded = st.file_uploader(
        "Drop a .pcap or .pcapng file here",
        type=["pcap", "pcapng", "cap"],
        help="Standard Wireshark / tcpdump capture files are supported.",
    )

    col_timeout, col_btn = st.columns([2, 1])
    with col_timeout:
        timeout = st.slider(
            "Flow idle timeout (seconds)",
            min_value=5, max_value=120, value=15,
            help="How long a flow can be idle before it is considered finished.",
        )
    with col_btn:
        st.write("")
        analyze = st.button(
            "Analyze File",
            disabled=(uploaded is None),
            use_container_width=True,
        )

    if uploaded and analyze:
        file_bytes = uploaded.read()
        st.info(f"**{uploaded.name}**  ({len(file_bytes) / 1024:.1f} KB)")

        results_live = []
        progress_bar = st.progress(0, text="Reading packets…")
        status_box   = st.empty()
        table_box    = st.empty()

        def on_flow_ready(features: dict):
            """Called once per completed flow — classify, store, update UI."""
            verdict = llm.classify(features)
            save_result(features, verdict)

            label = verdict["classification"]
            results_live.append({
                "flow_id":        features["flow_id"],
                "classification": label,
                "confidence":     round(verdict["confidence"], 2),
                "explanation":    verdict["explanation"],
            })

            status_box.markdown(
                f"**Latest:** `{features['flow_id']}` → "
                f"{_status_pill(label)} "
                f"({verdict['confidence']:.0%} confidence)",
                unsafe_allow_html=True,
            )

            if results_live:
                live_df = pd.DataFrame(results_live)
                table_box.dataframe(
                    live_df.style.apply(_highlight, axis=1),
                    use_container_width=True,
                    height=320,
                )

        def on_progress(done: int, total: int):
            progress_bar.progress(done / total, text=f"Parsing packets… {done}/{total}")

        with st.spinner("Analyzing — may take a minute depending on file size and model speed…"):
            try:
                summary = process_pcap(
                    file_bytes,
                    on_flow_ready=on_flow_ready,
                    timeout_seconds=timeout,
                    progress_callback=on_progress,
                )
                progress_bar.progress(1.0, text="Done")
            except Exception as exc:
                st.error(f"Failed to parse file: {exc}")
                st.stop()

        st.success(
            f"Analyzed **{summary['total_packets']}** packets → "
            f"**{summary['total_flows']}** flows classified."
        )

        if results_live:
            st.divider()
            st.subheader("Summary")
            df_result = pd.DataFrame(results_live)
            _render_metrics(df_result)

            st.divider()
            st.subheader("Flow-by-flow results")
            st.dataframe(
                df_result.style.apply(_highlight, axis=1),
                use_container_width=True,
                height=400,
            )

            csv = df_result.to_csv(index=False).encode()
            st.download_button(
                "Download results as CSV",
                data=csv,
                file_name=f"{uploaded.name}_analysis.csv",
                mime="text/csv",
            )