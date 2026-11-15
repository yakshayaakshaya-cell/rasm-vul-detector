"""ENHANCEMENT: continuous risk score (0..1) from independent signals. The decision threshold is applied on top of it,
which is what makes the precision/recall slider and the weight-tuning script possible."""


def llm_signal(res):
    """P(vulnerable) from the LLM verdict + its self-reported confidence; None when there was no usable LLM answer."""
    if not res or "is_vul" not in res:
        return None
    vul = res["is_vul"] in (True, "True", "true")
    try:
        c = min(max(float(res.get("confidence")), 0.5), 1.0)
    except (TypeError, ValueError):
        c = 0.85
    return c if vul else 1.0 - c


def knowledge_signal(hints, callee_hints=()):
    """Dangerous-API hints in the function (and, at half weight, in the functions it calls)."""
    return round(min(1.0, (len(hints) + 0.5 * len(callee_hints)) / 3.0), 4)


def alignment_signal(al):
    """Looks like the vulnerable side (+1) or the fixed side (-1) of the closest historical fix."""
    return round(0.5 + 0.5 * (al["vuln_side"] - al["fix_side"]), 4)


def neighbor_signal(sim_vuln, sim_fixed):
    """Is the query closer to the vulnerable or the fixed code of the best-matching pair? (cosine gap, scaled)."""
    return round(0.5 + max(-0.5, min(0.5, (sim_vuln - sim_fixed) * 10.0)), 4)


def risk_score(signals: dict, weights: dict) -> float:
    num = den = 0.0
    for k, v in signals.items():
        w = float(weights.get(k, 0.0))
        if v is not None and w > 0:
            num += w * v
            den += w
    return round(num / den, 4) if den else 0.0


def signal_table(signals: dict, weights: dict) -> dict:
    """{name: {value, weight}} with weights re-normalised over the signals that are available (for display)."""
    den = sum(float(weights.get(k, 0.0)) for k, v in signals.items() if v is not None) or 1.0
    return {k: {"value": None if v is None else round(v, 3), "weight": 0.0 if v is None else round(float(weights.get(k, 0.0)) / den, 3)}
            for k, v in signals.items()}
