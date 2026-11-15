"""ENHANCEMENTS 3 and 4: split a C/C++ file into functions, and collect the bodies of called functions."""
import re

_CONTROL = {"if", "for", "while", "switch", "catch", "return", "sizeof", "else", "do", "case"}
_TRANSPARENT = re.compile(r"^\s*(namespace\b[^{};]*|extern\s*(\"[^\"]*\")?\s*)$")
_ATTR = re.compile(r"__attribute__\s*\(\(.*?\)\)", re.S)
_TAIL = re.compile(r"(\s+(const|noexcept|override|final|volatile)\b)+\s*$")


def mask_source(code: str) -> str:
    """Blank out comments, string/char literals and preprocessor lines (same length, newlines kept)."""
    out, i, n = [], 0, len(code)
    at_line_start = True
    while i < n:
        c = code[i]
        if c == "/" and code[i:i + 2] == "//":
            j = code.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif c == "/" and code[i:i + 2] == "/*":
            j = code.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in code[i:j])); i = j
        elif c in "\"'":
            j = i + 1
            while j < n and code[j] != c and code[j] != "\n":
                j += 2 if code[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(c + " " * max(j - i - 2, 0) + (c if j - i >= 2 else "")); i = j
        elif c == "#" and at_line_start:
            j = i
            while j < n:
                k = code.find("\n", j)
                k = n if k < 0 else k
                cont = code[j:k].rstrip().endswith("\\")
                j = k
                if not cont:
                    break
                j += 1
            out.append(" " * (j - i)); i = j
        else:
            out.append(c)
            if c == "\n":
                at_line_start = True
            elif not c.isspace():
                at_line_start = False
            i += 1
            continue
        at_line_start = False if i > 0 and code[i - 1] != "\n" else at_line_start
    return "".join(out)


def _strip_parens(s: str) -> str:
    depth, out = 0, []
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _function_name(header: str):
    """Return the function name if `header` (text before a top-level '{') looks like a function signature."""
    h = _ATTR.sub(" ", header).strip()
    h = _TAIL.sub("", h).strip()
    if not h.endswith(")") or "(" not in h:
        return None
    if "=" in _strip_parens(h) or re.match(r"^(typedef|enum|union)\b", h):
        return None
    m = re.search(r"([A-Za-z_~][\w:~]*)\s*\(", h)
    if not m:
        return None
    name = m.group(1)
    return None if name in _CONTROL else name


def split_functions(code: str, language: str = "c") -> list[dict]:
    """Top-level function definitions: [{name, start_line, end_line, code}] in file order."""
    m = mask_source(code)
    funcs, depth, stack = [], 0, []
    boundary = 0
    i, n = 0, len(m)
    cur = None
    while i < n:
        ch = m[i]
        if ch == "{":
            if depth == 0:
                header = m[boundary:i]
                if _TRANSPARENT.match(header):
                    stack.append(i)
                    boundary = i + 1
                else:
                    name = _function_name(header)
                    cur = (name, boundary + (len(header) - len(header.lstrip())), i) if name else None
                    depth = 1
            else:
                depth += 1
        elif ch == "}":
            if depth > 1:
                depth -= 1
            elif depth == 1:
                depth = 0
                if cur:
                    name, s, _ = cur
                    funcs.append({"name": name, "start_line": code.count("\n", 0, s) + 1, "end_line": code.count("\n", 0, i) + 1, "code": code[s:i + 1]})
                    cur = None
                boundary = i + 1
            elif stack:
                stack.pop()
                boundary = i + 1
        elif ch == ";" and depth == 0:
            boundary = i + 1
        i += 1
    return funcs


def callee_context(func: dict, table: dict, max_callees: int = 3, max_chars: int = 6000):
    """ENHANCEMENT 4: bodies of functions defined in the same file and called by `func` (one level deep).
    Returns (text, [names]). The paper only looks at the single function in isolation."""
    body = mask_source(func["code"])
    names, seen = [], {func["name"]}
    for nm in re.findall(r"\b([A-Za-z_]\w*)\s*\(", body):
        if nm in table and nm not in seen:
            seen.add(nm)
            names.append(nm)
        if len(names) >= max_callees:
            break
    parts, used = [], 0
    for nm in names:
        c = table[nm]
        chunk = c["code"]
        room = max_chars - used
        if room < 200:
            break
        if len(chunk) > min(room, max_chars // max(len(names), 1) + 400):
            chunk = chunk[:min(room, max_chars // max(len(names), 1) + 400)] + "\n/* ... truncated ... */"
        parts.append(f"/* called function: {nm} (lines {c['start_line']}-{c['end_line']}) */\n{chunk}")
        used += len(chunk)
    return "\n\n".join(parts), [nm for nm in names][:len(parts)]
