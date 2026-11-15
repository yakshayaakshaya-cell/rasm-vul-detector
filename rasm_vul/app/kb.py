"""Five vector indices (paper Sec. 3.2.2): code, ast, knowledge, line (line changes), ast_change. Built from TRAINING pairs only."""
import json
import threading
from pathlib import Path
import numpy as np
from .embedder import Embedder
from .features import ast_sequence, line_changes, ast_diff_text
from . import knowledge as K

CHANNELS = ["code", "ast", "knowledge", "line", "ast_change"]
V, F = "Vulnerable", "Fixed/Safe"


class KnowledgeBase:
    def __init__(self, path: str = "data/kb", embedder: Embedder | None = None):
        self.dir = Path(path)
        self.embedder = embedder or Embedder()
        self.lock = threading.RLock()                  # guards readers while feedback is approved into the KB
        self._by_pair = None                           # lazy {pair_index: {side: [row numbers]}} for the code channel
        self.pairs: list[dict] = []
        self.rows = {c: [] for c in CHANNELS}          # per channel: (pair_index, side)
        self.vecs = {c: np.zeros((0, self.embedder.dim), np.float32) for c in CHANNELS}
        if (self.dir / "kb.json").exists():
            self.load()

    def add_pairs(self, pairs: list[dict], use_llm_knowledge=False, variants=False) -> int:
        """pair = {id, language, cwe, description, vulnerable_code, fixed_code}"""
        batch = {c: [] for c in CHANNELS}
        new_pairs, base = [], len(self.pairs)
        for n, p in enumerate(pairs):
            lang, vc, fc = p.get("language", "c"), p["vulnerable_code"], p["fixed_code"]
            lc = line_changes(vc, fc)
            va, fa = ast_sequence(vc, lang), ast_sequence(fc, lang)
            know = K.extract(p, use_llm_knowledge)
            i = base + n
            new_pairs.append({"pair_id": p["id"], "language": lang, "cwe": p.get("cwe", ""), "description": p.get("description", ""),
                              "vulnerable_code": vc, "fixed_code": fc, "removed": lc["removed"], "added": lc["added"], "knowledge": know})
            codes = [(V, vc, va), (F, fc, fa)]
            if variants:
                from .variants import mutate
                codes += [(s, mutate(c), None) for s, c, _ in codes[:2] if mutate(c) != c]
            for side, code, seq in codes:
                batch["code"].append((i, side, code))
                batch["ast"].append((i, side, " ".join(seq if seq is not None else ast_sequence(code, lang))))
            batch["knowledge"].append((i, "-", K.as_text(know)))
            batch["line"].append((i, "-", "\n".join(["- " + x for x in lc["removed"]] + ["+ " + x for x in lc["added"]])))
            batch["ast_change"].append((i, "-", ast_diff_text(va, fa)))
        encoded = {ch: self.embedder.encode([t for _, _, t in items]) for ch, items in batch.items() if items}   # slow part, outside the lock
        with self.lock:
            self.pairs += new_pairs
            for ch, items in batch.items():
                if items:
                    self.vecs[ch] = np.vstack([self.vecs[ch], encoded[ch]])
                    self.rows[ch] = self.rows[ch] + [(i, s) for i, s, _ in items]
            self._by_pair = None
            self.save()
        return len(pairs)

    def search(self, ch: str, q: np.ndarray, k: int = 5) -> list[dict]:
        with self.lock:
            rows, vecs = self.rows[ch], self.vecs[ch]
        if not rows:
            return []
        sims, best = vecs @ q, {}
        for r in np.argsort(-sims):
            i, side = rows[r]
            if i not in best:
                best[i] = {"idx": i, "score": float(sims[r]), "side": side}
            if len(best) == k:
                break
        return list(best.values())

    def pair_side_sims(self, i: int, q: np.ndarray):
        """ENHANCEMENT: similarity of the query to the vulnerable and to the fixed code of ONE pair (code channel)."""
        with self.lock:
            if self._by_pair is None:
                idx = {}
                for r, (pi, side) in enumerate(self.rows["code"]):
                    idx.setdefault(pi, {}).setdefault(side, []).append(r)
                self._by_pair = idx
            rows, vecs = self._by_pair.get(i, {}), self.vecs["code"]
            return tuple(float(max((vecs[r] @ q for r in rows.get(side, [])), default=0.0)) for side in (V, F))

    def save(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / "kb.json.tmp"
        tmp.write_text(json.dumps({"embedder": self.embedder.name, "pairs": self.pairs, "rows": self.rows}))
        tmp.replace(self.dir / "kb.json")
        np.savez_compressed(self.dir / "vecs.npz", **self.vecs)

    def load(self):
        meta = json.loads((self.dir / "kb.json").read_text())
        if meta["embedder"] != self.embedder.name:
            raise RuntimeError(f"KB built with '{meta['embedder']}' but current embedder is '{self.embedder.name}'. Rebuild the KB.")
        self.pairs, self.rows = meta["pairs"], {c: [tuple(r) for r in meta["rows"][c]] for c in CHANNELS}
        z = np.load(self.dir / "vecs.npz")
        self.vecs = {c: z[c] for c in CHANNELS}
