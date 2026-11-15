"""RASM-Vul pipeline: feature analysis (predict) -> 5-channel retrieval -> WRRF -> LLM re-rank -> knowledge-enhanced detection.

Enhancements on top of the paper (all optional, all off the critical path if unavailable):
  * analyze() / score() split: the slow part (LLM, retrieval, static tools) is cached in a Trace, scoring is cheap,
    so thresholds and weights can be tuned without re-running the LLM.            (enhancements 2, 7)
  * called-function bodies and static-analyzer findings are added to the LLM prompt. (enhancements 4, 5)
"""
import re
from dataclasses import dataclass, field

import numpy as np

from . import llm, static_tools
from .config import TOP_K, SIM_THRESHOLD, CONF_LOW, MAX_CONTEXT_CHARS, current_params
from .features import ast_sequence, knowledge_features, change_alignment, DANGEROUS_APIS
from .kb import KnowledgeBase, CHANNELS
from .knowledge import as_text
from .scoring import llm_signal, knowledge_signal, alignment_signal, neighbor_signal, risk_score, signal_table
from .wrrf import wrrf

_DANGER = re.compile(r"\b(" + "|".join(DANGEROUS_APIS) + r")\s*\(")
_EMPTY_STATIC = {"tools": [], "findings": [], "errors": []}


def heuristic_analyze(code: str) -> dict:
    ptype = "structure" if re.search(r"mutex|lock|goto|race|spin|atomic|rcu", code) else "statement"
    lines = [l.strip() for l in code.splitlines() if _DANGER.search(l)][:5]
    return {"problem_type": ptype, "problem_statements": lines, "ast_path": "", "analysis": "; ".join(knowledge_features(code))}


@dataclass
class Trace:
    """Everything expensive about one analysed function. score() turns it into a verdict without calling anything slow."""
    code: str
    language: str
    problem_type: str
    fa: dict
    stmts: list
    used_llm: bool
    ranked: dict
    qcode: np.ndarray
    static: dict
    context: str
    callee_names: list
    hints: list
    callee_hints: list
    llm_best: int | None = None      # pair index chosen by the LLM re-ranker (baseline weights)
    llm_res: dict | None = None      # parsed LLM detection answer (baseline weights)
    align: dict = field(default_factory=dict)


class Detector:
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb

    # ------------------------------------------------------------------ public API
    def detect(self, code: str, language: str = "c", context: str = "", static=None, use_llm=None, callee_names=None) -> dict:
        """static: None = run flawfinder/cppcheck if installed, False = skip, dict = findings supplied by the caller (file scan)."""
        res = self.score(self.analyze(code, language, context, static, use_llm, callee_names))
        res["verdict"] = "Vulnerable" if res["is_vul"] else "Fixed/Safe"
        return res

    def analyze(self, code: str, language: str = "c", context: str = "", static=None, use_llm=None, callee_names=None) -> Trace:
        used_llm = llm.available() if use_llm is None else bool(use_llm) and llm.available()
        context = (context or "").strip()[:MAX_CONTEXT_CHARS]
        st = _EMPTY_STATIC if static is False else (static_tools.run_static(code, language) if static is None else static)
        extra = self._extra(context, st)
        user = code + (f"\n\n{extra}" if extra else "")
        fa = (llm.parse_json(llm.chat(llm.ANALYZE_SYS, user)) if used_llm else None) or heuristic_analyze(code)
        T = "structure" if fa.get("problem_type") == "structure" else "statement"
        stmts = [str(s) for s in fa.get("problem_statements", [])]
        seq = " ".join(ast_sequence(code, language))
        # "predict-then-retrieve": predicted lines / AST path act as pseudo-change queries
        queries = {"code": code, "ast": seq, "knowledge": fa.get("analysis") or code,
                   "line": "\n".join(stmts) or code, "ast_change": fa.get("ast_path") or seq}
        qv = dict(zip(CHANNELS, self.kb.embedder.encode([queries[c] for c in CHANNELS])))
        ranked = {c: [h for h in self.kb.search(c, qv[c], TOP_K) if h["score"] >= SIM_THRESHOLD] for c in CHANNELS}
        t = Trace(code=code, language=language, problem_type=T, fa=fa, stmts=stmts, used_llm=used_llm, ranked=ranked, qcode=qv["code"],
                  static=st, context=context, callee_names=list(callee_names or []), hints=knowledge_features(code),
                  callee_hints=knowledge_features(context) if context else [])
        fused, _ = wrrf(ranked, T, current_params()["wrrf"])
        if used_llm and fused:
            cands = [i for i, _ in fused[:TOP_K]]
            best = cands[0]
            if len(cands) > 1:  # LLM re-rank
                txt = "\n".join(f"[{n}] {self.kb.pairs[i]['description']} | {as_text(self.kb.pairs[i]['knowledge'])}" for n, i in enumerate(cands, 1))
                r = llm.parse_json(llm.chat(llm.RERANK_SYS, f"TARGET:\n{code}\n\nCANDIDATES:\n{txt}"))
                try:
                    best = cands[int(r["best"]) - 1]
                except Exception:
                    pass
            t.llm_best = best
            ev = self._evidence(t, best, cands)
            t.llm_res = llm.parse_json(llm.chat(llm.DETECT_SYS, f"Code Snippet:\n{code}\n\nCode Analysis: {fa.get('analysis', '')}\n\nRelevant Knowledge:\n" +
                                                "\n".join(f"- {e['cwe']} {e['description']} | fix: {e['solution']}" for e in ev) + (f"\n\n{extra}" if extra else "")))
        return t

    def score(self, t: Trace, params: dict | None = None) -> dict:
        """Cheap and deterministic: re-fuses the cached retrieval hits with the given weights and applies the threshold."""
        p = params or current_params()
        thr = p["threshold"]
        fused, contrib = wrrf(t.ranked, t.problem_type, p["wrrf"])
        sig = {"llm": llm_signal(t.llm_res), "alignment": None, "neighbor": None,
               "knowledge": knowledge_signal(t.hints, t.callee_hints), "static": static_tools.static_signal(t.static)}
        base = {"problem_type": t.problem_type, "suspicious_lines": t.stmts, "llm_used": t.used_llm, "threshold": thr,
                "static_tools": t.static["tools"], "static_findings": t.static["findings"], "callees": t.callee_names,
                "knowledge_hints": t.hints}
        if not fused:
            risk = risk_score(sig, p["signals"])
            return {**base, "is_vul": risk >= thr, "cwe": None, "risk_score": risk, "signals": signal_table(sig, p["signals"]),
                    "explanation": "No similar historical case found; the verdict rests on the weaker signals (API hints, static analyzers, LLM).",
                    "retrieval_confidence": 0.0, "doubtful": True, "channel_contribution": {}, "evidence": []}
        cands = [i for i, _ in fused[:TOP_K]]
        best = t.llm_best if t.llm_best in cands else cands[0]
        sims = {c: next((h["score"] for h in t.ranked[c] if h["idx"] == best), 0.0) for c in CHANNELS}
        conf = round(max(sims["code"], sims["ast"]), 3)
        evidence = self._evidence(t, best, cands)
        al = evidence[0]["alignment"]
        if self.kb.pairs[best]["removed"] or self.kb.pairs[best]["added"]:
            sig["alignment"] = alignment_signal(al)
        sig["neighbor"] = neighbor_signal(*self.kb.pair_side_sims(best, t.qcode))
        risk = risk_score(sig, p["signals"])
        is_vul = risk >= thr
        res = t.llm_res
        if res and "is_vul" in res:
            cwe, why = res.get("cwe_id"), res.get("vul_desc", "")
        else:
            cwe = evidence[0]["cwe"] or None
            why = ("Heuristic mode (no LLM configured): the risk score combines how closely the code matches the lines the closest historical fix "
                   "removed or added, which side of that pair it is nearer to, dangerous-API hints and static-analyzer findings.")
        tot = sum(contrib[best].values()) or 1
        return {**base, "is_vul": is_vul, "cwe": (cwe or evidence[0]["cwe"] or None) if is_vul else None, "explanation": why,
                "risk_score": risk, "signals": signal_table(sig, p["signals"]), "retrieval_confidence": conf, "doubtful": conf < CONF_LOW,
                "channel_contribution": {c: round(v / tot, 3) for c, v in contrib[best].items()}, "evidence": evidence}

    # ------------------------------------------------------------------ helpers
    def _align(self, t: Trace, i: int) -> dict:
        if i not in t.align:
            p = self.kb.pairs[i]
            t.align[i] = change_alignment(t.code, p["removed"], p["added"])
        return t.align[i]

    def _evidence(self, t: Trace, best: int, cands: list) -> list:
        order = [best] + [i for i in cands if i != best]
        out = []
        for i in order[:3]:
            p = self.kb.pairs[i]
            out.append({"pair_id": p["pair_id"], "cwe": p["cwe"], "description": p["description"], "removed": p["removed"][:8], "added": p["added"][:8],
                        "solution": p["knowledge"].get("solution", ""), "alignment": self._align(t, i),
                        "vulnerable_code": p["vulnerable_code"][:1500], "fixed_code": p["fixed_code"][:1500]})
        return out

    @staticmethod
    def _extra(context: str, st: dict) -> str:
        parts = []
        if st.get("findings"):
            parts.append("Static analyzer findings (" + ", ".join(st["tools"]) + "):\n" + static_tools.prompt_text(st))
        if context:
            parts.append("Called functions (context only - judge the TARGET code, not these):\n" + context)
        return "\n\n".join(parts)
