"""ENHANCEMENT 5: run flawfinder / cppcheck (the paper's baselines) and feed their findings to the detector.

Both tools are optional. `pip install flawfinder` is enough on any host; cppcheck needs the OS package
(`apt install cppcheck`). If a tool is missing it is simply skipped and the static signal is left out.
"""
import csv
import io
import os
import re
import shutil
import subprocess
import tempfile

TOOLS = ("flawfinder", "cppcheck")
_FF_WEIGHT = {5: 1.0, 4: 1.0, 3: 0.7, 2: 0.4, 1: 0.2, 0: 0.1}
_CPP_WEIGHT = {"error": 1.0, "warning": 0.5, "portability": 0.2}
_CPP_SKIP_IDS = {"syntaxError", "cppcheckError", "internalAstError", "unknownMacro", "missingInclude", "missingIncludeSystem", "unusedFunction", "normalCheckLevelMaxBranches"}
_CPP_LINE = re.compile(r"^(\d+)\|(\w+)\|([\w.\-]+)\|(.*)$")


def available_tools() -> dict:
    if os.getenv("STATIC_TOOLS", "on").lower() in {"0", "off", "false", "no"}:
        return {t: False for t in TOOLS}
    return {t: shutil.which(t) is not None for t in TOOLS}


def _run(cmd, timeout):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
    return p.stdout, p.stderr


def parse_flawfinder_csv(text: str) -> list[dict]:
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        try:
            line, level = int(row.get("Line") or 0), int(row.get("Level") or 0)
        except ValueError:
            continue
        cwe = (row.get("CWEs") or "").split(",")[0].strip()
        out.append({"tool": "flawfinder", "line": line, "severity": f"level {level}", "weight": _FF_WEIGHT.get(level, 0.1),
                    "rule": row.get("Name") or row.get("Category") or "", "cwe": cwe,
                    "message": (row.get("Warning") or "").strip()})
    return out


def parse_cppcheck(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        m = _CPP_LINE.match(raw.strip())
        if not m:
            continue
        line, sev, rid, msg = int(m.group(1)), m.group(2), m.group(3), m.group(4).strip()
        if sev not in _CPP_WEIGHT or rid in _CPP_SKIP_IDS:
            continue
        out.append({"tool": "cppcheck", "line": line, "severity": sev, "weight": _CPP_WEIGHT[sev], "rule": rid, "cwe": "", "message": msg})
    return out


def run_static(code: str, language: str = "c", timeout: int = 20, tools=None) -> dict:
    """Returns {"tools": [tools that ran], "findings": [...], "errors": [...]}. Never raises."""
    avail = available_tools()
    wanted = [t for t in (tools or TOOLS) if avail.get(t)]
    res = {"tools": [], "findings": [], "errors": []}
    if not wanted:
        return res
    cpp = language.lower() in {"c++", "cpp", "cc", "cxx"}
    with tempfile.TemporaryDirectory(prefix="rasm_static_") as d:
        path = os.path.join(d, "target.cpp" if cpp else "target.c")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(code)
        for tool in wanted:
            try:
                if tool == "flawfinder":
                    out, _ = _run(["flawfinder", "--csv", "--quiet", "--minlevel=1", path], timeout)
                    res["findings"] += parse_flawfinder_csv(out)
                else:
                    _, err = _run(["cppcheck", "--quiet", "--enable=warning,portability", "--inline-suppr",
                                   "--language=" + ("c++" if cpp else "c"), "--template={line}|{severity}|{id}|{message}", path], timeout)
                    res["findings"] += parse_cppcheck(err)
                res["tools"].append(tool)
            except Exception as e:
                res["errors"].append(f"{tool}: {type(e).__name__}")
    res["findings"].sort(key=lambda f: (f["line"], -f["weight"]))
    return res


def findings_in_range(st: dict, start: int, end: int) -> dict:
    """Findings that fall on lines start..end (1-based) of a larger file, re-based to line 1 of the function."""
    f = [{**x, "line": x["line"] - start + 1} for x in st.get("findings", []) if start <= x["line"] <= end]
    return {"tools": st.get("tools", []), "findings": f, "errors": st.get("errors", [])}


def prompt_text(st: dict, limit: int = 8) -> str:
    rows = sorted(st.get("findings", []), key=lambda f: -f["weight"])[:limit]
    return "\n".join(f"- line {f['line']} [{f['tool']} {f['severity']}] {f['rule']}: {f['message']}" + (f" ({f['cwe']})" if f["cwe"] else "") for f in rows)


def static_signal(st: dict | None):
    """0..1 risk signal, or None when no tool ran (so the signal is left out instead of counting as 'safe')."""
    if not st or not st.get("tools"):
        return None
    return round(min(1.0, sum(f["weight"] for f in st["findings"]) / 2.0), 4)
