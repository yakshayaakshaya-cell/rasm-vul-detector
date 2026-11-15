import json


def load_pairs(path: str, limit: int | None = None):
    """PrimeVul paired .jsonl -> [{id, language, cwe, description, vulnerable_code, fixed_code}].
    Pairs are formed from consecutive records of the same commit with opposite targets; anything else is skipped and counted."""
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    pairs, skipped, i = [], 0, 0
    while i < len(rows) - 1:
        a, b = rows[i], rows[i + 1]
        if a["commit_id"] == b["commit_id"] and a["project"] == b["project"] and a["target"] != b["target"]:
            v, f = (a, b) if a["target"] == 1 else (b, a)
            pairs.append({"id": f"{v['project']}-{v['idx']}", "language": "c", "cwe": ",".join(v.get("cwe") or []),
                          "description": v.get("cve_desc", ""), "vulnerable_code": v["func"], "fixed_code": f["func"]})
            i += 2
        else:
            skipped += 1
            i += 1
    print(f"{len(pairs)} pairs, {skipped} records skipped (not adjacent twins)")
    return pairs[:limit] if limit else pairs
