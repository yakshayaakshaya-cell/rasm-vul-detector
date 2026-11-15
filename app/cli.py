"""Build the retrieval knowledge base, evaluate / tune it on paired data, or scan a C file from the command line."""
import argparse
import json
import sys
from pathlib import Path

from .config import ROOT, TUNED_PATH
from .data import load_pairs
from .kb import KnowledgeBase
from .detector import Detector
from .evaluation import evaluate_pairs


def _abs(p: str) -> Path:
    p = Path(p)
    return p if p.is_absolute() else ROOT / p


def cmd_scan(a):
    from .scanner import scan_file
    path = _abs(a.file)
    if not path.is_file():
        raise SystemExit(f"File not found: {path}")
    kb = KnowledgeBase(str(ROOT / "data" / "kb"))
    if not kb.pairs:
        raise SystemExit("Knowledge base is empty. Build data/kb first (python -m app.cli build ...).")
    lang = "c++" if path.suffix.lower() in {".cc", ".cpp", ".cxx", ".hpp"} else "c"
    out = scan_file(Detector(kb), path.read_text(encoding="utf-8", errors="replace"), lang, use_llm=a.llm, use_static=not a.no_static,
                    max_functions=a.max_functions, time_budget=a.time_budget)
    flagged = [f for f in out["functions"] if f["risk_score"] >= a.fail_above]
    for f in out["functions"][:a.top]:
        mark = "!!" if f["risk_score"] >= a.fail_above else "  "
        print(f"{mark} {f['risk_score']:.2f}  {f['name']}  (lines {f['start_line']}-{f['end_line']})  {f['cwe'] or ''}")
    s = out["stats"]
    print(f"\n{s['functions_scanned']}/{s['functions_found']} functions scanned in {s['seconds']}s; {len(flagged)} at or above {a.fail_above}")
    if a.json:
        _abs(a.json).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print("Report written to", _abs(a.json))
    if flagged and a.fail_above < 1.0:
        sys.exit(1)   # non-zero exit code lets a nightly CI job fail or notify on risky functions


def cmd_tune(a, pairs, kb):
    from .tune import run_tune, save_tuned
    if "test" in Path(a.file).name.lower() and not a.allow_test:
        raise SystemExit("Refusing to tune on a file whose name contains 'test'. Tune on the VALIDATION split (use --allow-test to override).")
    result = run_tune(Detector(kb), pairs, beta=a.beta, iters=a.iters, holdout=a.holdout, seed=a.seed,
                      use_llm=False if a.no_llm else None, use_static=a.static)
    print(json.dumps(result["meta"], indent=2))
    out = _abs(a.output) if a.output else TUNED_PATH
    if save_tuned(result, out, force=a.force):
        print("Saved tuned parameters to", out, "- restart the app to use them.")
    else:
        print("Tuned weights did NOT beat the current ones on the held-out pairs, so nothing was saved (use --force to save anyway).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["build", "eval", "scan", "tune"])
    ap.add_argument("file")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--llm-knowledge", action="store_true")
    ap.add_argument("--variants", action="store_true")
    ap.add_argument("--output", help="eval: results JSON (default data/eval_results.json); tune: tuned parameters (default data/tuned_params.json)")
    # scan
    ap.add_argument("--llm", action="store_true", help="scan: also call the configured LLM for every function (slower)")
    ap.add_argument("--no-static", action="store_true", help="scan: do not run flawfinder/cppcheck")
    ap.add_argument("--fail-above", type=float, default=0.70, help="scan: exit code 1 if any function scores at or above this risk")
    ap.add_argument("--max-functions", type=int, default=50)
    ap.add_argument("--time-budget", type=float, default=600)
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--json", help="scan: write the full report to this file")
    # tune
    ap.add_argument("--beta", type=float, default=2.0, help="tune: F-beta to maximise (2 = recall-first, as in the paper's F2)")
    ap.add_argument("--iters", type=int, default=200)
    ap.add_argument("--holdout", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--static", action="store_true", help="tune: include flawfinder/cppcheck findings")
    ap.add_argument("--allow-test", action="store_true")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    if a.cmd == "scan":
        cmd_scan(a)
        raise SystemExit(0)

    input_path = _abs(a.file)
    if not input_path.is_file():
        raise SystemExit(f"Input dataset not found: {input_path}")
    pairs = load_pairs(str(input_path), a.limit)
    if not pairs:
        raise SystemExit("No valid vulnerable/fixed pairs were found in the dataset.")

    kb = KnowledgeBase(str(ROOT / "data" / "kb"))
    if a.cmd == "build":
        print("added", kb.add_pairs(pairs, a.llm_knowledge, a.variants))
    elif a.cmd == "tune":
        cmd_tune(a, pairs, kb)
    else:
        result = evaluate_pairs(pairs, Detector(kb), input_path.name)
        output_path = _abs(a.output or "data/eval_results.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps({k: v for k, v in result.items() if k not in ("scores", "curve")}, indent=2))
        print(f"Saved evaluation results to: {output_path}")
