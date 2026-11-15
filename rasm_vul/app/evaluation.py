"""Shared evaluation logic for the CLI and deployed API."""
from datetime import datetime, timezone

from .config import current_params


def fbeta(p: float, r: float, beta: float) -> float:
    b2 = beta * beta
    return (1 + b2) * p * r / max(b2 * p + r, 1e-12)


def metrics_at(vuln_scores, fixed_scores, thr: float, beta: float = 2.0) -> dict:
    """vuln_scores[i] / fixed_scores[i] = risk scores of the two functions of pair i. Positive class = Vulnerable."""
    tp = sum(s >= thr for s in vuln_scores)
    fn = len(vuln_scores) - tp
    fp = sum(s >= thr for s in fixed_scores)
    tn = len(fixed_scores) - fp
    pair_ok = sum(v >= thr and f < thr for v, f in zip(vuln_scores, fixed_scores))
    total = tp + fn + fp + tn
    precision, recall = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "accuracy": (tp + tn) / max(total, 1), "precision": precision, "recall": recall,
            "f1": fbeta(precision, recall, 1.0), "f2": fbeta(precision, recall, 2.0), "fbeta": fbeta(precision, recall, beta),
            "pair_accuracy": pair_ok / max(len(vuln_scores), 1)}


def threshold_curve(vuln_scores, fixed_scores, steps: int = 20) -> list:
    out = []
    for k in range(steps + 1):
        m = metrics_at(vuln_scores, fixed_scores, k / steps)
        out.append({"threshold": round(k / steps, 3), **{x: round(m[x], 4) for x in ("precision", "recall", "f1", "f2")}})
    return out


def evaluate_pairs(pairs, detector, dataset_name="unknown"):
    if not detector.kb.pairs:
        raise RuntimeError(
            "The knowledge base is empty. Build and deploy data/kb before evaluation."
        )
    thr = current_params()["threshold"]
    vs, fs = [], []
    for pair in pairs:
        vs.append(detector.detect(pair["vulnerable_code"])["risk_score"])
        fs.append(detector.detect(pair["fixed_code"])["risk_score"])
    m = metrics_at(vs, fs, thr)
    total = 2 * len(pairs)
    return {
        "status": "complete",
        "dataset": dataset_name,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "pairs": len(pairs),
        "samples": total,
        "threshold": thr,
        "accuracy": m["accuracy"],
        "precision": m["precision"],
        "recall": m["recall"],
        "f1": m["f1"],
        "f2": m["f2"],
        "pair_accuracy": m["pair_accuracy"],
        "confusion_matrix": {
            "labels": ["Vulnerable", "Fixed/Safe"],
            "matrix": [[m["tp"], m["fn"]], [m["fp"], m["tn"]]],
        },
        # ENHANCEMENT: per-sample risk scores, so the Evaluation tab can move the threshold without re-running anything
        "scores": {"vulnerable": [round(x, 4) for x in vs], "fixed": [round(x, 4) for x in fs]},
        "curve": threshold_curve(vs, fs),
    }
