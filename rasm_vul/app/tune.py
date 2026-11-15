"""ENHANCEMENT 7: tune the fusion weights and the decision threshold on the VALIDATION split.

What is tuned
  * WRRF channel weights for statement-level and structure-level problems (paper Sec. 3.3.2 gives fixed values)
  * the signal weights of the risk score (llm / alignment / neighbor / knowledge / static)
  * the decision threshold (optimised exactly for every candidate weight set)
The slow part (LLM calls, retrieval, static tools) runs ONCE per function and is cached in a Trace; every candidate
weight set is then scored in milliseconds. Cached LLM answers come from the baseline run and are reused as-is.
"""
import json
import math
import random
from bisect import bisect_left
from datetime import datetime, timezone
from pathlib import Path

from .config import current_params
from .evaluation import fbeta, metrics_at

SIGNALS = ("llm", "alignment", "neighbor", "knowledge", "static")


def best_threshold(vs, fs, beta):
    """Exact search over every distinct score: returns (threshold, objective)."""
    allv = sorted(set(vs) | set(fs))
    if not allv:
        return 0.5, 0.0
    cands = [allv[0] - 1e-3] + [(a + b) / 2 for a, b in zip(allv, allv[1:])] + [allv[-1] + 1e-3]
    sv, sf = sorted(vs), sorted(fs)
    best = (-1.0, 0.0, 0.5)
    for thr in cands:
        tp = len(sv) - bisect_left(sv, thr)
        fp = len(sf) - bisect_left(sf, thr)
        p, r = tp / max(tp + fp, 1), tp / max(len(sv), 1)
        key = (fbeta(p, r, beta), -abs(thr - 0.5))
        if key > best[:2]:
            best = (key[0], key[1], thr)
    return round(best[2], 4), best[0]


def _normalise(d: dict) -> dict:
    s = sum(d.values()) or 1.0
    return {k: round(v / s, 4) for k, v in d.items()}


def _perturb(params: dict, rng: random.Random, sigma: float) -> dict:
    new = {"wrrf": {T: dict(w) for T, w in params["wrrf"].items()}, "signals": dict(params["signals"]), "threshold": params["threshold"]}
    groups = [("wrrf", "statement"), ("wrrf", "structure"), ("signals", None)]
    for g, T in rng.sample(groups, rng.randint(1, len(groups))):
        w = new[g][T] if T else new[g]
        for k in w:
            w[k] = max(1e-3, w[k] * math.exp(rng.gauss(0, sigma)))
        norm = _normalise(w)
        w.clear()
        w.update(norm)
    return new


def run_tune(detector, pairs, beta=2.0, iters=200, holdout=0.3, seed=0, use_llm=None, use_static=False, log=print) -> dict:
    rng = random.Random(seed)
    order = list(range(len(pairs)))
    rng.shuffle(order)
    n_hold = int(len(pairs) * holdout) if len(pairs) >= 10 else 0
    hold, train = order[:n_hold], order[n_hold:]
    log(f"{len(pairs)} validation pairs -> {len(train)} for tuning, {len(hold)} held out")

    traces = {}
    for n, i in enumerate(order, 1):
        p = pairs[i]
        traces[i] = tuple(detector.analyze(c, p.get("language", "c"), static=None if use_static else False, use_llm=use_llm)
                          for c in (p["vulnerable_code"], p["fixed_code"]))
        if n % 25 == 0:
            log(f"  analysed {n}/{len(pairs)} pairs")

    def scores(params, ids):
        return ([detector.score(traces[i][0], params)["risk_score"] for i in ids],
                [detector.score(traces[i][1], params)["risk_score"] for i in ids])

    def objective(params, ids):
        vs, fs = scores(params, ids)
        thr, val = best_threshold(vs, fs, beta)
        return thr, val

    base = current_params()
    best, (best_thr, best_val) = base, objective(base, train)
    best["threshold"] = best_thr
    log(f"baseline weights, best threshold {best_thr}: F{beta:g} = {best_val:.4f} (tuning split)")
    for it in range(1, iters + 1):
        cand = _perturb(best, rng, sigma=0.45 * (1 - it / (iters + 1)) + 0.05)
        thr, val = objective(cand, train)
        if val > best_val + 1e-9:
            cand["threshold"], best, best_val = thr, cand, val
            log(f"  iter {it}: F{beta:g} = {val:.4f} (threshold {thr})")

    def report(params, ids):
        if not ids:
            return None
        vs, fs = scores(params, ids)
        m = metrics_at(vs, fs, params["threshold"], beta)
        return {k: round(m[k], 4) for k in ("precision", "recall", "f1", "f2", "fbeta", "pair_accuracy")}

    deployed = current_params()
    result = {
        "wrrf": best["wrrf"], "signals": best["signals"], "threshold": best["threshold"],
        "meta": {"created_at": datetime.now(timezone.utc).isoformat(), "beta": beta, "iterations": iters, "seed": seed,
                 "pairs_total": len(pairs), "pairs_tuning": len(train), "pairs_holdout": len(hold),
                 "llm_used": bool(detector.score(traces[order[0]][0])["llm_used"]), "static_used": use_static,
                 "baseline": {"tuning": report(deployed, train), "holdout": report(deployed, hold)},
                 "tuned": {"tuning": report(best, train), "holdout": report(best, hold)}},
    }
    return result


def save_tuned(result: dict, path: Path, force: bool = False) -> bool:
    m = result["meta"]
    b, t = m["baseline"]["holdout"], m["tuned"]["holdout"]
    if b and t and t["fbeta"] < b["fbeta"] and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return True
