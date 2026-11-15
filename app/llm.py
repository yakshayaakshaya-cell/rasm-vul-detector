"""LLM access. Paper used DeepSeek-V3 / Qwen2.5-72B (OpenAI-compatible APIs). Set:
   LLM_BASE_URL (e.g. https://api.deepseek.com/v1), LLM_API_KEY, LLM_MODEL (e.g. deepseek-chat)
Without them the system runs in heuristic mode (no LLM)."""
import json
import os
import re
import urllib.request
from .config import LLM_PARAMS


def available() -> bool:
    return bool(os.getenv("LLM_BASE_URL") and os.getenv("LLM_API_KEY"))


def chat(system: str, user: str) -> str | None:
    if not available():
        return None
    body = {"model": os.getenv("LLM_MODEL", "deepseek-chat"), **LLM_PARAMS,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    req = urllib.request.Request(os.environ["LLM_BASE_URL"].rstrip("/") + "/chat/completions",
                                 json.dumps(body).encode(),
                                 {"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["LLM_API_KEY"]})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.load(r)["choices"][0]["message"]["content"]
    except Exception as e:
        print("LLM call failed:", e)
        return None


def parse_json(text):
    try:
        return json.loads(re.search(r"\{.*\}", text or "", re.S).group(0))
    except Exception:
        return None


# --- Prompts follow the paper's Appendix A.2 / A.3 -------------------------------
ANALYZE_SYS = ("You are a vulnerability detection expert and code analysis specialist. Decide whether a vulnerability (if any) is a "
    "statement-level issue or a structure-level issue. If caused by specific lines (e.g. missing check) set problem_type to 'statement' "
    "and list exact lines in problem_statements. If caused by AST/architectural issues set 'structure' and give a Tree-sitter style ast_path. "
    "Do not hallucinate AST paths or line numbers. Reply ONLY JSON: {\"problem_type\":\"statement|structure\",\"problem_statements\":[...],"
    "\"ast_path\":\"...\",\"analysis\":\"[BEHAVIOR]; [SOLUTION]; [PURPOSE]; [FUNCTION]\"}")
RERANK_SYS = ("You re-rank retrieved historical vulnerability cases. Given the target code and numbered candidates, pick the single candidate "
    "whose vulnerability behavior, solution pattern and functional context best match the target. Reply ONLY JSON: {\"best\": <number>}")
DETECT_SYS = ("You are a vulnerability detector and code expert. Determine whether the code is vulnerable code or fixed code. "
    "1) Analyze the code for security issues. 2) Use the retrieved knowledge and analysis only if relevant; otherwise ignore them. "
    "3) Vulnerable = missing checks, unsafe memory operations or exploitable logic; fixed = proper bounds/null checks or removed unsafe behavior. "
    "Static-analyzer findings and called-function bodies may be provided as extra context; use them only if they help, and judge ONLY the target code snippet. "
    "Reply ONLY JSON: {\"is_vul\": true|false, \"cwe_id\": \"CWE-ID\", \"vul_desc\": \"brief description of the vulnerability or the fix\", "
    "\"confidence\": <number 0.5-1.0, how sure you are of is_vul>}")
KNOW_SYS = ("You are a vulnerability detection expert. From the vulnerable/fixed pair and CVE description, summarise the generalizable code "
    "behavior that causes the vulnerability and the specific fix. Omit specific resource names. Reply ONLY JSON: "
    "{\"vulnerability_behavior\":{\"preconditions_for_vulnerability\":\"\",\"trigger_condition\":\"\",\"specific_code_behavior_causing_vulnerability\":\"\"},"
    "\"solution\":\"To mitigate the vulnerability, it is necessary to...\"}")
