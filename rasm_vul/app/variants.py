"""Semantics-preserving mutations (paper Table 1, rules 1 and 3 only; the paper uses an LLM for all 16). Training data only."""
import re

_TYPES = r"(?:int|char|long|short|size_t|ssize_t|unsigned(?:\s+int)?|u?int\d+_t)"


def mutate(code: str) -> str:
    out = re.sub(r"\b(\w+)\+\+\s*;", r"\1 += 1;", code)                     # rule 3: x++ -> x += 1
    names = re.findall(rf"\b{_TYPES}\s+\**(\w+)\s*(?:=|;|,)", out)         # rule 1: rename locals
    for i, n in enumerate(dict.fromkeys(names)):
        out = re.sub(rf"\b{n}\b", f"v_{i}", out)
    return out
