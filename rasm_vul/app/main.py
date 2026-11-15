import difflib
import hmac
import json
import os
from pathlib import Path
from typing import Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import static_tools
from .config import SCAN_MAX_BYTES, SCAN_MAX_FUNCTIONS, current_params
from .kb import KnowledgeBase
from .detector import Detector
from .data import load_pairs
from .evaluation import evaluate_pairs
from .feedback import FeedbackError, FeedbackStore
from .scanner import scan_file

ROOT = Path(__file__).resolve().parent.parent


def configured_path(env_name, default):
    value = Path(os.getenv(env_name, default))
    return value if value.is_absolute() else ROOT / value


KB_PATH = configured_path("KB_PATH", "data/kb")
EVAL_DATASET = configured_path("EVAL_DATASET", "data/primevul_test_paired.jsonl")
EVAL_RESULTS = configured_path("EVAL_RESULTS_PATH", "data/eval_results.json")
FEEDBACK_DIR = configured_path("FEEDBACK_DIR", "data/feedback")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")   # enables the Review tab (approve/reject analyst feedback). Unset = review disabled.

app = FastAPI(title="RASM-Vul")
kb = KnowledgeBase(str(KB_PATH))
detector = Detector(kb)
feedback = FeedbackStore(FEEDBACK_DIR, kb)
evaluation_error = None


class DetectReq(BaseModel):
    code: str = Field(min_length=1, max_length=20000)
    language: str = Field(default="c", max_length=12)
    context: str = Field(default="", max_length=20000)      # enhancement 4: bodies of called functions (optional)
    use_static: bool = True                                  # enhancement 5: flawfinder / cppcheck findings
    use_llm: Optional[bool] = None                           # None = use the LLM if one is configured


class PatchReq(BaseModel):
    old_code: str = Field(min_length=1, max_length=20000)
    new_code: str = Field(min_length=1, max_length=20000)
    language: str = Field(default="c", max_length=12)
    use_static: bool = True


class ScanReq(BaseModel):                                    # enhancement 3
    code: str = Field(min_length=1, max_length=SCAN_MAX_BYTES)
    language: str = Field(default="c", max_length=12)
    use_llm: bool = False
    use_static: bool = True
    with_context: bool = True
    max_functions: int = Field(default=25, ge=1, le=SCAN_MAX_FUNCTIONS)


class FeedbackReq(BaseModel):                                # enhancement 6
    kind: Literal["single", "pair"]
    code: Optional[str] = Field(default=None, max_length=20000)
    label: Optional[Literal["vulnerable", "safe"]] = None
    old_code: Optional[str] = Field(default=None, max_length=20000)
    new_code: Optional[str] = Field(default=None, max_length=20000)
    language: str = Field(default="c", max_length=12)
    cwe: str = Field(default="", max_length=40)
    note: str = Field(default="", max_length=1000)
    model_verdict: Optional[str] = Field(default=None, max_length=20)
    risk_score: Optional[float] = None


class ApproveReq(BaseModel):
    counterpart: Optional[str] = Field(default=None, max_length=20000)
    cwe: Optional[str] = Field(default=None, max_length=40)
    description: Optional[str] = Field(default=None, max_length=1000)


def require_admin(x_admin_token: Optional[str] = Header(default=None)):
    if not ADMIN_TOKEN:
        raise HTTPException(403, "Review is disabled. Set the ADMIN_TOKEN environment variable on the server to enable it.")
    if not x_admin_token or not hmac.compare_digest(x_admin_token, ADMIN_TOKEN):
        raise HTTPException(401, "Invalid review token.")


def _need_kb():
    if not kb.pairs:
        raise HTTPException(503, "Knowledge base is empty. Deploy the prebuilt data/kb folder.")


def run_configured_evaluation():
    global evaluation_error
    if not EVAL_DATASET.is_file():
        evaluation_error = (
            f"Test dataset not found at {EVAL_DATASET}. Add the PrimeVul test "
            "JSONL file to the deployed project and set EVAL_DATASET if needed."
        )
        return
    try:
        pairs = load_pairs(str(EVAL_DATASET))
        if not pairs:
            raise RuntimeError("The test dataset contains no valid adjacent vulnerable/fixed pairs.")
        result = evaluate_pairs(pairs, detector, EVAL_DATASET.name)
        EVAL_RESULTS.parent.mkdir(parents=True, exist_ok=True)
        EVAL_RESULTS.write_text(json.dumps(result, indent=2), encoding="utf-8")
        evaluation_error = None
    except Exception as exc:
        evaluation_error = str(exc)
        print("Evaluation failed:", evaluation_error)


@app.on_event("startup")
def optional_startup_evaluation():
    # Enable on Render with RUN_EVAL_ON_STARTUP=true after adding the test
    # dataset and the prebuilt training knowledge base to the deployment.
    if os.getenv("RUN_EVAL_ON_STARTUP", "").lower() in {"1", "true", "yes"}:
        run_configured_evaluation()


@app.get("/api/health")
def health():
    import app.llm as llm
    return {
        "kb_pairs": len(kb.pairs),
        "embedder": kb.embedder.name,
        "llm": llm.available(),
        "evaluation_results": EVAL_RESULTS.is_file(),
        "threshold": current_params()["threshold"],
        "static_tools": static_tools.available_tools(),
        "review_enabled": bool(ADMIN_TOKEN),
        "scan_limits": {"max_bytes": SCAN_MAX_BYTES, "max_functions": SCAN_MAX_FUNCTIONS},
    }


@app.post("/api/detect")
def detect(r: DetectReq):
    _need_kb()
    return detector.detect(r.code, r.language, context=r.context, static=None if r.use_static else False, use_llm=r.use_llm)


@app.post("/api/scan-file")
def scan(r: ScanReq):
    _need_kb()
    return scan_file(detector, r.code, r.language, use_llm=r.use_llm, use_static=r.use_static,
                     with_context=r.with_context, max_functions=r.max_functions)


def _diff_rows(old: str, new: str) -> list:
    a, b, rows = old.splitlines(), new.splitlines(), []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            rows += [{"t": " ", "s": x} for x in a[i1:i2]]
        else:
            rows += [{"t": "-", "s": x} for x in a[i1:i2]] + [{"t": "+", "s": x} for x in b[j1:j2]]
    return rows


@app.post("/api/patch-check")
def patch_check(r: PatchReq):
    _need_kb()
    st = None if r.use_static else False
    old_result = detector.detect(r.old_code, r.language, static=st)
    new_result = detector.detect(r.new_code, r.language, static=st)
    ov, nv = old_result["is_vul"], new_result["is_vul"]
    status = ("fix_confirmed" if ov and not nv else "still_vulnerable" if ov and nv else "regression" if nv else "no_issue_found")
    return {
        "old": old_result,
        "new": new_result,
        "patch_looks_correct": bool(ov and not nv),
        "status": status,
        "risk_drop": round(old_result["risk_score"] - new_result["risk_score"], 4),
        "diff": _diff_rows(r.old_code, r.new_code),
    }


@app.post("/api/feedback")
def submit_feedback(r: FeedbackReq):
    if r.kind == "single" and not (r.code and r.label):
        raise HTTPException(422, "A single-function report needs the code and a label (vulnerable or safe).")
    if r.kind == "pair" and not (r.old_code and r.new_code):
        raise HTTPException(422, "A fix report needs both the old and the new version.")
    try:
        return feedback.submit(r.model_dump() if hasattr(r, "model_dump") else r.dict())
    except FeedbackError as e:
        raise HTTPException(e.status, e.message)


@app.get("/api/feedback")
def list_feedback(status: str = "pending", _=Depends(require_admin)):
    return {"items": feedback.list(status), "counts": feedback.counts(), "kb_pairs": len(kb.pairs)}


@app.post("/api/feedback/{fid}/approve")
def approve_feedback(fid: str, r: ApproveReq, _=Depends(require_admin)):
    try:
        item = feedback.approve(fid, r.counterpart, r.cwe, r.description)
    except FeedbackError as e:
        raise HTTPException(e.status, e.message)
    return {"item": item, "kb_pairs": len(kb.pairs)}


@app.post("/api/feedback/{fid}/reject")
def reject_feedback(fid: str, _=Depends(require_admin)):
    try:
        return {"item": feedback.reject(fid)}
    except FeedbackError as e:
        raise HTTPException(e.status, e.message)


@app.get("/api/eval")
def eval_results():
    if EVAL_RESULTS.is_file():
        try:
            return json.loads(EVAL_RESULTS.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise HTTPException(500, "Evaluation results file exists but is unreadable.")
    return {
        "status": "not_run",
        "message": evaluation_error or (
            "Evaluation has not been run on this deployment yet. "
            "Set RUN_EVAL_ON_STARTUP=true and provide EVAL_DATASET, or run "
            "'python -m app.cli eval data/primevul_test_paired.jsonl' before deployment."
        ),
        "dataset_available": EVAL_DATASET.is_file(),
        "knowledge_base_pairs": len(kb.pairs),
    }


app.mount("/", StaticFiles(directory=ROOT / "frontend", html=True), name="ui")
