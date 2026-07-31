# LLM-Powered Intrusion Detection System

Live packet capture via Scapy, flow summarization, and a local LLM that
classifies each network flow as **Benign**, **Suspicious**, or **Attack**
with a plain-English explanation — shown on a live Streamlit dashboard.

## Architecture

```
Network Interface → Scapy Sniffer → Packet Collection → Flow Generator
        → Feature Extraction (Statistics / Protocol Info / Flags)
        → Flow Summary → Local LLM Analyzer → Classification + Explanation
        → SQLite → Streamlit Dashboard
```

The detection pipeline (`main.py`) and the dashboard (`dashboard/app.py`)
are fully decoupled — they only communicate through `storage/flows.db`.
That means the dashboard can be rebuilt in something else entirely later
without touching any detection logic.

---

## Setup — Linux / macOS

### 1. Create a virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Install Ollama and pull a model

Ollama is not a pip package — install it from https://ollama.com, then:

```bash
ollama pull llama3.1:8b     # or: mistral, phi3 (lighter/faster)
```

Ollama serves itself at `http://localhost:11434` automatically after install.

### 3. Run

Open two terminals:

```bash
# Terminal 1 — detection pipeline (needs root to capture raw packets)
sudo python3 main.py

# Terminal 2 — live dashboard
streamlit run dashboard/app.py
```

---

## Setup — Windows

Windows needs one extra step before anything else: **Npcap**.
Scapy installs fine via pip on Windows but captures zero packets without it.

### 1. Install Npcap

Download and install from https://npcap.com  
During setup, check **"Install Npcap in WinPcap API-compatible mode"**.  
Reboot if prompted.

### 2. Create a virtual environment and install dependencies

Open **Command Prompt** or **PowerShell**:

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

> Note: use `python`, not `python3`, on most Windows installations.

### 3. Install Ollama and pull a model

Download from https://ollama.com — it installs as a background service automatically.

```bat
ollama pull llama3.1:8b
```

### 4. Run as Administrator

Packet capture on Windows requires Administrator privileges.  
**Right-click** Command Prompt or PowerShell → **"Run as administrator"**, then:

```bat
# Terminal 1 — detection pipeline
venv\Scripts\activate
python main.py

# Terminal 2 — live dashboard (no admin needed here)
venv\Scripts\activate
streamlit run dashboard/app.py
```

> There is no `sudo` on Windows — running the terminal as Administrator is the equivalent.

### 5. Finding your network interface name (Windows only)

On Linux/macOS the default interface is picked automatically.  
On Windows, Scapy uses long interface names like `\Device\NPF_{GUID}`.  
Run this once to find yours:

```python
from scapy.all import get_if_list
print(get_if_list())
```

Then set it in `config.py`:

```python
NETWORK_INTERFACE = "\\Device\\NPF_{your-guid-here}"
```

---

## Tests

No root, no Npcap, no Ollama needed — the test suite runs anywhere:

```bash
# Linux / macOS
pytest tests/test_flow_tracker.py -v

# Windows
pytest tests\test_flow_tracker.py -v
```

Expected output: **37 passed**.

---

## Project structure

```
llm-ids/
├── main.py               ← orchestrator — run this first
├── config.py             # shared settings (timeouts, model, interface)
├── requirements.txt
├── README.md
├── sniffer/
│   ├── capture.py        # Scapy sniffer
│   └── flow_tracker.py   # 5-tuple grouping, timeout logic
├── features/
│   └── extractor.py      # stats, protocol info, flags
├── analyzer/
│   ├── prompt_builder.py # flow → structured LLM prompt
│   └── llm_client.py     # Ollama API calls
├── storage/
│   └── db.py             # SQLite results store
├── dashboard/
│   └── app.py            # Streamlit viewer
└── tests/
    └── test_flow_tracker.py
```

---

## Design notes

- **Fail-safe LLM errors** — if the Ollama call fails or returns malformed
  JSON, the flow is marked `Suspicious` rather than silently dropped or called
  `Benign`. An IDS that goes quiet on error is worse than one that over-flags.
- **Bidirectional flow keying** — both directions of one TCP/UDP conversation
  map to the same flow, so request and response packets are analyzed together.
- **Flow close conditions** — a flow closes on a `FIN`/`RST` packet, or after
  `FLOW_TIMEOUT_SECONDS` of inactivity (configurable in `config.py`).
- **Decoupled pipeline and dashboard** — `main.py` only writes to
  `storage/flows.db`; the dashboard only reads from it. Both can run
  independently and the dashboard tech can be swapped without touching
  detection logic.