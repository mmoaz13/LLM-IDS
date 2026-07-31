"""Streamlit dashboard — four tabs:
  • Live Capture      : pick a network adapter and start/stop capture (runs
                        entirely inside this process, needs admin/root),
                        plus the real-time results table for whatever
                        main.py or this capture has written, with per-flow
                        search, incident reports, and analyst feedback
  • Upload PCAP       : upload a .pcap file, analyze it on the spot, show results
  • Simulate Attacks  : generate synthetic traffic on the fly and analyze it
  • Ask               : ask a natural-language question over stored results
"""

import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from storage import db
from sniffer.capture import list_interfaces
from sniffer.live_session import LiveCaptureSession
from sniffer.pcap_reader import process_pcap
from analyzer.llm_client import LLMClient
from analyzer.report_generator import generate as generate_report
from analyzer.query_parser import parse as parse_query, summarize as summarize_query
from simulator.traffic_generator import SCENARIOS, packets_to_pcap_bytes
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

TAB_CAPTURE, TAB_UPLOAD, TAB_SIMULATE, TAB_ASK = st.tabs(
    ["Live Capture", "Upload PCAP", "Simulate Attacks", "Ask"]
)

# ── Shared helpers ────────────────────────────────────────────────────────────

ROW_COLORS = {"Benign": "#132015", "Suspicious": "#26200c", "Attack": "#2a1414"}
PILL_CLASS = {"Benign": "status-benign", "Suspicious": "status-suspicious", "Attack": "status-attack"}

FEEDBACK_LABELS = {
    "Correct": "correct",
    "False positive (should be less severe)": "false_positive",
    "False negative (should be more severe)": "false_negative",
}


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


def _run_scenario_and_collect(scenario: dict, timeout_seconds: float = 15):
    """Generate one simulator scenario, run it through the same
    flow -> feature -> LLM pipeline as a real upload, and return the
    per-flow results plus the process_pcap summary."""
    packets = scenario["generator"]()
    pcap_bytes = packets_to_pcap_bytes(packets)

    sim_results = []
    progress_bar = st.progress(0, text="Building packets…")

    def on_flow_ready(features: dict):
        verdict = llm.classify(features)
        save_result(features, verdict)
        sim_results.append({
            "flow_id": features["flow_id"],
            "src_ip": features["protocol_info"]["src_ip"],
            "classification": verdict["classification"],
            "confidence": round(verdict["confidence"], 2),
            "explanation": verdict["explanation"],
        })

    def on_progress(done, total):
        progress_bar.progress(done / total, text=f"Analyzing… {done}/{total}")

    summary = process_pcap(
        pcap_bytes, on_flow_ready=on_flow_ready,
        timeout_seconds=timeout_seconds, progress_callback=on_progress,
    )
    progress_bar.progress(1.0, text="Done")
    return len(packets), sim_results, summary


# ── Tab 1: Live Capture ────────────────────────────────────────────────────────

with TAB_CAPTURE:
    st.subheader("Capture live traffic from a network adapter")
    st.caption(
        "Runs the same sniff → flow → feature → LLM pipeline as `main.py`, but started "
        "and stopped right here. Capturing raw packets needs admin/root privileges — "
        "if this Streamlit process wasn't launched elevated, starting capture will fail "
        "with a clear error rather than silently doing nothing."
    )

    session = st.session_state.get("capture_session")

    if session is None or not session.running:
        interfaces = list_interfaces()
        if not interfaces:
            st.error("No network interfaces detected.")
        else:
            iface_labels = [entry["label"] for entry in interfaces]
            selected_label = st.selectbox("Network adapter", iface_labels, key="capture_iface_select")
            selected_iface = next(e["iface"] for e in interfaces if e["label"] == selected_label)

            if st.button("Start Capture", key="start_capture_btn", type="primary"):
                new_session = LiveCaptureSession(
                    interface=selected_iface,
                    interface_label=selected_label,
                    llm_client=llm,
                )
                try:
                    new_session.start()
                    st.session_state["capture_session"] = new_session
                    st.rerun()
                except Exception as exc:
                    st.error(
                        f"Failed to start capture on **{selected_label}**: {exc}\n\n"
                        "This usually means the process wasn't launched with admin/root "
                        "privileges, or (Windows) Npcap isn't installed."
                    )
    else:
        st.success(f"Capturing on **{session.interface_label}**")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Packets seen", session.packets_seen)
        col2.metric("Active flows", session.active_flow_count)
        col3.metric("Flows classified", session.flows_classified)
        col4.metric("Elapsed", f"{int(time.time() - session.started_at)}s")

        if session.last_error:
            st.warning(f"Last error in the background classify loop: {session.last_error}")

        st.caption(
            "Capture keeps running in the background even if you switch tabs or navigate "
            "away — click Stop Capture to end it. Classified flows appear in the results "
            "below."
        )

        col_refresh, col_stop = st.columns(2)
        with col_refresh:
            if st.button("Refresh status", key="refresh_capture_btn"):
                st.rerun()
        with col_stop:
            if st.button("Stop Capture", key="stop_capture_btn"):
                session.stop()
                st.session_state["capture_session"] = None
                st.rerun()

    st.divider()
    st.subheader("Real-time flow analysis")
    st.caption(
        "Results written by `main.py` or the capture above. Click Refresh to pull the latest."
    )

    col_refresh, col_limit = st.columns([1, 3])
    with col_refresh:
        if st.button("Refresh", key="refresh_results_btn"):
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

        st.divider()
        st.subheader("Flow tools")
        st.caption(
            "Search to find a specific flow among however many are stored — this queries "
            "the database directly, independent of the 'Rows to show' limit above — then "
            "write a full incident report or record analyst feedback on its verdict."
        )

        col_search, col_class = st.columns([3, 1])
        with col_search:
            flow_search = st.text_input(
                "Search by flow ID, IP, or port",
                key="flow_search",
                placeholder="e.g. 10.0.0.5, 443, or part of a flow ID",
            )
        with col_class:
            tools_classification = st.selectbox(
                "Classification", ["All", "Attack", "Suspicious", "Benign"],
                key="tools_classification",
            )

        tools_filters = {"search": flow_search}
        if tools_classification != "All":
            tools_filters["classification"] = tools_classification
        matching_flows = db.query_results(tools_filters, limit=200)

        if not matching_flows:
            st.info("No flows match that search.")
        else:
            st.caption(f"{len(matching_flows)} matching flow(s) — newest first, capped at 200.")
            flow_options = {f"#{r['id']} — {r['flow_id']} ({r['classification']})": r for r in matching_flows}
            selected_label = st.selectbox("Select a flow", list(flow_options.keys()), key="tools_flow_select")
            selected_row = flow_options[selected_label]

            col_report, col_feedback = st.columns(2)

            with col_report:
                st.markdown("**Incident report**")
                if st.button("Generate report", key="gen_report_btn"):
                    with st.spinner("Writing report…"):
                        st.session_state["last_report"] = generate_report(selected_row, llm)
                        st.session_state["last_report_flow"] = selected_row["flow_id"]

                if st.session_state.get("last_report"):
                    st.markdown(st.session_state["last_report"])
                    safe_name = st.session_state.get("last_report_flow", "flow").replace(":", "_").replace("/", "_")
                    st.download_button(
                        "Download report (.md)",
                        data=st.session_state["last_report"],
                        file_name=f"incident_{safe_name}.md",
                        mime="text/markdown",
                    )

            with col_feedback:
                st.markdown("**Analyst feedback**")
                feedback_choice = st.radio(
                    "Was this verdict correct?",
                    list(FEEDBACK_LABELS.keys()),
                    key="feedback_choice",
                )
                note = st.text_input("Note (optional)", key="feedback_note")
                if st.button("Submit feedback", key="submit_feedback_btn"):
                    db.save_feedback(
                        selected_row["id"], selected_row["classification"],
                        FEEDBACK_LABELS[feedback_choice], note,
                    )
                    st.success("Feedback recorded.")

                fb_summary = db.get_feedback_summary()
                if fb_summary:
                    st.caption(
                        f"Recorded so far — correct: {fb_summary.get('correct', 0)}, "
                        f"false positives: {fb_summary.get('false_positive', 0)}, "
                        f"false negatives: {fb_summary.get('false_negative', 0)}"
                    )


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


# ── Tab 3: Simulate Attacks ────────────────────────────────────────────────────

with TAB_SIMULATE:
    st.subheader("Generate synthetic traffic and analyze it instantly")
    st.caption(
        "Packets are built entirely offline with Scapy — nothing is ever sent over a "
        "real network — then run through the exact same flow → feature → LLM pipeline "
        "as a live capture or upload. Useful for demoing detection without needing "
        "live malicious traffic or admin/root privileges."
    )

    for key, scenario in SCENARIOS.items():
        with st.container(border=True):
            col_info, col_btn = st.columns([4, 1])
            with col_info:
                st.markdown(f"**{scenario['label']}**")
                st.caption(scenario["description"])
            with col_btn:
                st.write("")
                run_clicked = st.button("Generate & Analyze", key=f"sim_run_{key}", use_container_width=True)

            if run_clicked:
                with st.spinner(f"Classifying {scenario['label']} traffic…"):
                    packet_count, sim_results, summary = _run_scenario_and_collect(scenario)

                st.success(f"{packet_count} synthetic packets → {summary['total_flows']} flows classified.")

                if sim_results:
                    df_sim = pd.DataFrame(sim_results)
                    _render_metrics(df_sim)
                    st.dataframe(
                        df_sim.style.apply(_highlight, axis=1),
                        use_container_width=True,
                        height=320,
                    )

                    if len(df_sim) > 1:
                        st.markdown(
                            "**Grouped by source IP** — some patterns (like a port scan) only "
                            "become visible across many flows sharing a source, even though "
                            "each flow above was classified independently:"
                        )
                        grouped = (
                            df_sim.groupby("src_ip")
                            .agg(
                                flow_count=("flow_id", "count"),
                                attack_count=("classification", lambda s: int((s == "Attack").sum())),
                                suspicious_count=("classification", lambda s: int((s == "Suspicious").sum())),
                            )
                            .reset_index()
                            .sort_values("flow_count", ascending=False)
                        )
                        st.dataframe(grouped, use_container_width=True)


# ── Tab 4: Ask ─────────────────────────────────────────────────────────────────

with TAB_ASK:
    st.subheader("Ask a question about your flow history")
    st.caption(
        "Your question is translated into filters (classification, IP, port, time range) "
        "against storage/flows.db — the LLM only ever supplies filter *values*, never SQL."
    )

    question = st.text_input(
        "Ask something",
        placeholder="e.g. Show me attack flows targeting port 22 in the last hour",
        key="ask_question",
    )

    if st.button("Ask", key="ask_btn") and question.strip():
        with st.spinner("Interpreting question…"):
            filters = parse_query(question, llm)

        query_limit = filters.get("limit", 50)
        ask_results = db.query_results(filters, limit=query_limit)

        with st.spinner("Summarizing…"):
            answer = summarize_query(question, ask_results, llm)

        st.markdown(f"**Answer:** {answer}")

        with st.expander("Filters this question was translated into"):
            st.json(filters)

        if ask_results:
            df_ask = pd.DataFrame(ask_results)
            df_ask["timestamp"] = pd.to_datetime(df_ask["timestamp"], unit="s")
            _render_table(df_ask, ["timestamp", "flow_id", "classification", "confidence", "explanation"])
