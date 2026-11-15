"""All numbers below come from the RASM-Vul paper (Sec. 3.3.2 and 4.4.2) unless marked ASSUMPTION or ENHANCEMENT."""
import copy
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

K_RRF = 60
TOP_K = 5                 # per retrieval channel
SIM_THRESHOLD = 0.15      # minimum cosine similarity for a hit to be kept
CONF_LOW = 0.30           # ASSUMPTION: below this top-1 similarity the verdict is flagged "doubtful"
WEIGHTS = {
    "statement": {"code": 0.35, "line": 0.25, "ast": 0.20, "knowledge": 0.15, "ast_change": 0.05},
    "structure": {"ast": 0.40, "ast_change": 0.30, "code": 0.15, "line": 0.10, "knowledge": 0.05},
}
LLM_PARAMS = {"max_tokens": 4096, "temperature": 0.3, "top_p": 0.9}

# ---- ENHANCEMENTS (not in the paper) -----------------------------------------------------------------
# Risk score = weighted average of independent signals, each in [0, 1] (1 = looks vulnerable).
# A signal that is unavailable (e.g. no LLM configured, no static tool installed) is left out and the
# remaining weights are re-normalised. The weights and the threshold can be tuned with `python -m app.cli tune`.
SIGNAL_WEIGHTS = {"llm": 0.55, "alignment": 0.20, "neighbor": 0.08, "knowledge": 0.07, "static": 0.10}
RISK_THRESHOLD = 0.50     # a function is flagged "Vulnerable" when risk_score >= threshold

MAX_CONTEXT_CHARS = 6000        # called-function bodies added to the prompt
MAX_CALLEES = 3                 # at most this many called functions are added per target function
SCAN_MAX_BYTES = 400_000        # largest file accepted by the file scan
SCAN_MAX_FUNCTIONS = 100        # hard cap on functions analysed per scan
SCAN_TIME_BUDGET_S = float(os.getenv("SCAN_TIME_BUDGET_S", "90"))

TUNED_PATH = Path(os.getenv("TUNED_PARAMS", ROOT / "data" / "tuned_params.json"))


def _load_tuned():
    """Apply weights written by `python -m app.cli tune` (if the file exists and is valid)."""
    global RISK_THRESHOLD
    if not TUNED_PATH.is_file():
        return
    try:
        t = json.loads(TUNED_PATH.read_text(encoding="utf-8"))
        for T in ("statement", "structure"):
            if set(t["wrrf"][T]) == set(WEIGHTS[T]):
                WEIGHTS[T].update({k: float(v) for k, v in t["wrrf"][T].items()})
        SIGNAL_WEIGHTS.update({k: float(v) for k, v in t["signals"].items() if k in SIGNAL_WEIGHTS})
        RISK_THRESHOLD = float(t["threshold"])
    except Exception as e:  # a broken tuning file must never stop the app
        print("Ignoring invalid tuned parameters:", type(e).__name__, e)


_load_tuned()


def current_params() -> dict:
    """A private copy of the live parameters (safe to modify while tuning)."""
    return {"wrrf": copy.deepcopy(WEIGHTS), "signals": dict(SIGNAL_WEIGHTS), "threshold": RISK_THRESHOLD}
