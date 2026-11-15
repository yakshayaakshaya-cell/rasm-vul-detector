from .config import K_RRF, WEIGHTS


def wrrf(ranked: dict[str, list[dict]], problem_type: str, weights: dict | None = None):
    """Score(s) = sum_c w_c(T) / (k + rank_c(s)).  ranked[channel] = hits sorted best-first.
    `weights` (ENHANCEMENT) lets the tuning script try other channel weights; default = paper values."""
    w = (weights or WEIGHTS)[problem_type]
    score, contrib = {}, {}
    for ch, hits in ranked.items():
        for rank, h in enumerate(hits, 1):
            v = w[ch] / (K_RRF + rank)
            score[h["idx"]] = score.get(h["idx"], 0) + v
            contrib.setdefault(h["idx"], {})[ch] = contrib.get(h["idx"], {}).get(ch, 0) + v
    return sorted(score.items(), key=lambda x: -x[1]), contrib
