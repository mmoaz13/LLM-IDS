"""Central configuration for the LLM-IDS project."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

# Network capture
NETWORK_INTERFACE = None     # None = let Scapy pick the default interface
FLOW_TIMEOUT_SECONDS = 15    # seconds of inactivity before a flow is considered closed
EXPIRY_CHECK_INTERVAL = 5    # how often (seconds) the main loop checks for expired flows

# Local LLM (Ollama)
OLLAMA_HOST = "http://localhost:11434"
OLLAMA_MODEL = "llama3.1:8b"   # swap for "mistral" or "phi3" if you want faster/lighter
LLM_TIMEOUT_SECONDS = 120

# Storage
DB_PATH = str(PROJECT_ROOT / "storage" / "flows.db")