from . import llm


def extract(pair: dict, use_llm: bool) -> dict:
    """Structured knowledge for one vuln/fixed pair (paper Appendix A.1). Training data only."""
    if use_llm and llm.available():
        for _ in range(2):  # simplified generate -> validate loop: retry on malformed output
            k = llm.parse_json(llm.chat(llm.KNOW_SYS, f"Vulnerable:\n{pair['vulnerable_code']}\n\nFixed:\n{pair['fixed_code']}\n\nCVE: {pair.get('description','')}"))
            if k and "vulnerability_behavior" in k and "solution" in k:
                return k
    return {"vulnerability_behavior": {"preconditions_for_vulnerability": "", "trigger_condition": "",
            "specific_code_behavior_causing_vulnerability": pair.get("description", "")},
            "solution": "Apply the change shown in the line diff of the fix."}


def as_text(k: dict) -> str:
    vb = k.get("vulnerability_behavior", {})
    return " ".join([*(str(v) for v in vb.values()), str(k.get("solution", ""))]).strip()
