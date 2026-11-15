"""Make a fresh deploy work out of the box (run at build time:  python scripts/bootstrap.py).

1. If data/kb is missing, build a SMALL DEMO knowledge base from data/sample_pairs.jsonl (hash embeddings).
   -> Detect, Patch check, Scan and Review (approving feedback) all work.
2. If data/eval_results.json is missing and no real PrimeVul test file exists, write a clearly labelled
   DEMO evaluation so the Evaluation tab shows something. It is NOT a valid PrimeVul result (the KB was
   built from the same 3 pairs). With a real KB + data/primevul_test_paired.jsonl, run
   `python -m app.cli eval data/primevul_test_paired.jsonl` instead and this step is skipped.
Never overwrites existing files.
"""
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("EMBEDDER", "hash")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.detector import Detector          # noqa: E402
from app.evaluation import evaluate_pairs  # noqa: E402
from app.kb import KnowledgeBase           # noqa: E402

kb_dir, sample = ROOT / "data" / "kb", ROOT / "data" / "sample_pairs.jsonl"
res_path = ROOT / "data" / "eval_results.json"
real_test = ROOT / os.getenv("EVAL_DATASET", "data/primevul_test_paired.jsonl")

kb = KnowledgeBase(str(kb_dir))
pairs = [json.loads(l) for l in sample.read_text(encoding="utf-8").splitlines() if l.strip()]
if not kb.pairs:
    print("Building demo knowledge base from", sample.name, "->", kb.add_pairs(pairs), "pairs")
else:
    print("Knowledge base already present:", len(kb.pairs), "pairs (kept)")

if res_path.exists():
    print("eval_results.json already present (kept)")
elif real_test.is_file():
    print("Real test file found; run the eval via RUN_EVAL_ON_STARTUP=true or python -m app.cli eval")
else:
    os.environ.setdefault("STATIC_TOOLS", "off")
    result = evaluate_pairs(pairs, Detector(kb), "DEMO: sample_pairs.jsonl (NOT PrimeVul, KB built from same pairs)")
    result["demo"] = True
    res_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Wrote DEMO evaluation:", {k: round(result[k], 3) for k in ("accuracy", "precision", "recall", "f1")})
