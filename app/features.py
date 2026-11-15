"""Feature extraction: code, AST, knowledge, line-change, AST-change."""
import ast
import difflib
import re
import textwrap
from collections import Counter

# ---- Knowledge features: dangerous APIs -> CWE hints -------------------------
DANGEROUS_APIS = {
    "strcpy": "CWE-120 unbounded copy", "strcat": "CWE-120 unbounded concat",
    "sprintf": "CWE-120/134 unbounded or format-string write", "gets": "CWE-242 unbounded read",
    "scanf": "CWE-120 unbounded read", "memcpy": "CWE-119/787 length must be validated",
    "memmove": "CWE-119/787 length must be validated", "malloc": "CWE-476/190 check NULL and size overflow",
    "realloc": "CWE-476/416 check NULL, old pointer", "free": "CWE-415/416 double free / use-after-free",
    "system": "CWE-78 OS command injection", "popen": "CWE-78 OS command injection",
    "exec": "CWE-95 code injection", "eval": "CWE-95 code injection",
    "loads": "CWE-502 unsafe deserialization", "execute": "CWE-89 SQL injection if string-built",
    "md5": "CWE-327 weak hash", "random": "CWE-338 weak PRNG", "printf": "CWE-134 format string",
}
GUARD_PATTERNS = {
    "bounds_check": r"(<=|>=|<|>)\s*(sizeof|len|size|max|limit)|sizeof|strn(cpy|cat)|snprintf|strlcpy|\blen\b|\bsize\b",
    "null_check": r"==\s*NULL|!=\s*NULL|\bif\s*\(\s*!\s*\w+\s*\)|is None|is not None",
    "sanitization": r"sanitize|escape|validate|quote|prepare|parameteri[sz]ed|shlex\.quote|allowlist|whitelist",
    "error_return": r"\breturn\s+(-\d+|NULL|false|None|ERR\w*)",
}
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "else", "case", "catch", "def", "elif"}


def normalize(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def code_features(code: str) -> dict:
    calls = Counter(c for c in re.findall(r"\b([A-Za-z_][\w\.]*)\s*\(", code) if c not in KEYWORDS)
    return {
        "n_lines": len([l for l in code.splitlines() if l.strip()]),
        "calls": dict(calls.most_common(15)),
        "guards": {name: bool(re.search(p, code)) for name, p in GUARD_PATTERNS.items()},
    }


def knowledge_features(code: str) -> list[str]:
    hints, seen = [], set()
    for call in re.findall(r"\b([A-Za-z_][\w\.]*)\s*\(", code):
        base = call.split(".")[-1]
        if base in DANGEROUS_APIS and base not in seen:
            seen.add(base)
            hints.append(f"{base}(): {DANGEROUS_APIS[base]}")
    return hints


# ---- AST features -------------------------------------------------------------
def _regex_skeleton(code: str) -> Counter:
    """Language-agnostic structural fallback when no real parser is available."""
    pats = {
        "if": r"\bif\b", "else": r"\belse\b", "for": r"\bfor\b", "while": r"\bwhile\b",
        "switch": r"\bswitch\b", "return": r"\breturn\b", "goto": r"\bgoto\b",
        "call": r"\b\w+\s*\(", "compare": r"==|!=|<=|>=|<|>", "assign": r"(?<![=!<>])=(?!=)",
        "index": r"\[[^\]]*\]", "deref": r"->|\*\w+", "cast": r"\(\s*(?:unsigned|int|char|long|size_t|void)\b[^)]*\)",
        "sizeof": r"\bsizeof\b", "null": r"\bNULL\b|\bNone\b", "logical": r"&&|\|\||\band\b|\bor\b",
    }
    return Counter({k: len(re.findall(p, code)) for k, p in pats.items() if re.search(p, code)})


def ast_summary(code: str, language: str = "c") -> dict:
    lang = language.lower()
    if lang in ("python", "py"):
        try:
            tree = ast.parse(textwrap.dedent(code))
            return dict(Counter(type(n).__name__ for n in ast.walk(tree)))
        except SyntaxError:
            pass
    try:  # optional real parser for C/C++/Java/JS...
        from tree_sitter_languages import get_parser
        tree = get_parser({"c++": "cpp", "cpp": "cpp"}.get(lang, lang)).parse(code.encode())
        counts, stack = Counter(), [tree.root_node]
        while stack:
            n = stack.pop()
            if n.is_named:
                counts[n.type] += 1
            stack.extend(n.children)
        return dict(counts)
    except Exception:
        return dict(_regex_skeleton(code))


# ---- Change features (used for KB pairs) --------------------------------------
def line_changes(vuln: str, fixed: str) -> dict:
    v = [normalize(l) for l in vuln.splitlines() if l.strip()]
    f = [normalize(l) for l in fixed.splitlines() if l.strip()]
    removed, added = [], []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, v, f).get_opcodes():
        if tag in ("replace", "delete"):
            removed += v[i1:i2]
        if tag in ("replace", "insert"):
            added += f[j1:j2]
    return {"removed": removed, "added": added}


def ast_changes(vuln_ast: dict, fixed_ast: dict) -> dict:
    keys = set(vuln_ast) | set(fixed_ast)
    return {k: fixed_ast.get(k, 0) - vuln_ast.get(k, 0) for k in keys if fixed_ast.get(k, 0) != vuln_ast.get(k, 0)}


def _present(line: str, qlines: list[str]) -> bool:
    return any(line == q or difflib.SequenceMatcher(None, line, q).ratio() >= 0.88 for q in qlines)


def change_alignment(query_code: str, removed: list[str], added: list[str]) -> dict:
    """How much the query looks like the vulnerable side (removed lines still present)
    vs the fixed side (added lines already present) of a historical fix."""
    q = [normalize(l) for l in query_code.splitlines() if l.strip()]
    vuln_hit = sum(_present(l, q) for l in removed) / len(removed) if removed else 0.0
    fix_hit = sum(_present(l, q) for l in added) / len(added) if added else 0.0
    return {"vuln_side": round(vuln_hit, 3), "fix_side": round(fix_hit, 3)}


def extract_all(code: str, language: str) -> dict:
    a = ast_summary(code, language)
    k = knowledge_features(code)
    c = code_features(code)
    top_ast = ", ".join(f"{n}:{v}" for n, v in sorted(a.items(), key=lambda x: -x[1])[:12])
    embed_text = f"{code}\n[AST] {top_ast}\n[KNOWLEDGE] {'; '.join(k)}\n[GUARDS] {c['guards']}"
    return {"code": c, "ast": a, "knowledge": k, "embed_text": embed_text}


# ---- RASM-Vul additions: AST node sequence (deep traversal) and AST diff -------
_SEQ_RE = re.compile(r"\b(if|else|for|while|do|switch|case|return|goto|break|continue|sizeof)\b|\w+(?=\s*\()|->|&&|\|\||[<>=!]=|[{}()\[\];=<>!&|*+\-/%]")


def ast_sequence(code: str, language: str = "c") -> list[str]:
    """Node sequence by depth-first traversal (tree-sitter if installed, else a token skeleton)."""
    lang = language.lower()
    try:
        from tree_sitter_languages import get_parser
        tree = get_parser({"c++": "cpp"}.get(lang, lang)).parse(code.encode())
        seq, stack = [], [tree.root_node]
        while stack:
            n = stack.pop()
            if n.is_named:
                seq.append(n.type)
            stack.extend(reversed(n.children))
        return seq
    except Exception:
        out = []
        for m in _SEQ_RE.finditer(code):
            t = m.group(0)
            out.append(t if (m.group(1) or not (t[0].isalpha() or t[0] == "_")) else "call")
        return out


def ast_diff_text(vseq: list[str], fseq: list[str]) -> str:
    out = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, vseq, fseq, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            out += ["- " + x for x in vseq[i1:i2]]
        if tag in ("replace", "insert"):
            out += ["+ " + x for x in fseq[j1:j2]]
    return "\n".join(out)
