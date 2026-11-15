"""ENHANCEMENT 3: scan a whole C/C++ file - split it into functions and rank them by risk (nightly-CI style triage)."""
import time

from . import static_tools
from .config import MAX_CALLEES, MAX_CONTEXT_CHARS, SCAN_MAX_FUNCTIONS, SCAN_TIME_BUDGET_S
from .features import knowledge_features
from .splitter import callee_context, split_functions

MAX_FUNC_CHARS = 20000


def scan_file(detector, code: str, language: str = "c", use_llm: bool = False, use_static: bool = True,
              with_context: bool = True, max_functions: int = 25, time_budget: float | None = None) -> dict:
    t0 = time.time()
    budget = SCAN_TIME_BUDGET_S if time_budget is None else time_budget
    max_functions = max(1, min(int(max_functions), SCAN_MAX_FUNCTIONS))
    funcs = split_functions(code, language)
    table = {}
    for f in funcs:
        table.setdefault(f["name"], f)

    file_static = static_tools.run_static(code, language) if use_static else {"tools": [], "findings": [], "errors": []}
    for f in funcs:   # cheap pre-rank so that, when the file is big, the most suspicious functions are scanned first
        f["static"] = static_tools.findings_in_range(file_static, f["start_line"], f["end_line"])
        f["prerank"] = len(knowledge_features(f["code"])) + sum(x["weight"] for x in f["static"]["findings"])
    order = sorted(funcs, key=lambda f: (-f["prerank"], f["start_line"]))

    results, skipped_budget = [], 0
    for f in order:
        if len(results) >= max_functions or time.time() - t0 > budget:
            skipped_budget += 1
            continue
        ctx, callees = callee_context(f, table, MAX_CALLEES, MAX_CONTEXT_CHARS) if with_context else ("", [])
        text = f["code"][:MAX_FUNC_CHARS]
        res = detector.detect(text, language, context=ctx, static=f["static"] if use_static else False, use_llm=use_llm, callee_names=callees)
        top = res["evidence"][0] if res["evidence"] else None
        results.append({
            "name": f["name"], "start_line": f["start_line"], "end_line": f["end_line"], "code": text, "truncated": len(f["code"]) > MAX_FUNC_CHARS,
            "risk_score": res["risk_score"], "is_vul": res["is_vul"], "cwe": res["cwe"], "problem_type": res["problem_type"],
            "doubtful": res["doubtful"], "retrieval_confidence": res["retrieval_confidence"], "explanation": res["explanation"],
            "suspicious_lines": res["suspicious_lines"], "signals": res["signals"], "static_findings": res["static_findings"],
            "callees": callees, "knowledge_hints": res["knowledge_hints"],
            "best_case": {"pair_id": top["pair_id"], "cwe": top["cwe"], "description": top["description"]} if top else None,
        })
    results.sort(key=lambda r: (-r["risk_score"], r["start_line"]))
    return {
        "functions": results,
        "stats": {"functions_found": len(funcs), "functions_scanned": len(results), "not_scanned": skipped_budget,
                  "static_tools": file_static["tools"], "llm_used": bool(use_llm), "seconds": round(time.time() - t0, 2),
                  "flagged_at_default": sum(r["is_vul"] for r in results)},
    }
