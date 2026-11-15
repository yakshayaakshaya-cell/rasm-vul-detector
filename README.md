# RASM-Vul (student implementation)
Pipeline (paper Fig. 2): feature analysis -> 5 indices (code, AST, knowledge, line changes, AST changes) -> WRRF -> LLM re-rank -> knowledge-enhanced verdict.


## Enhancements beyond the paper
All seven are optional and sit on top of the paper pipeline (the five-channel retrieval, WRRF and LLM steps are unchanged).

| # | Enhancement | Where |
|---|-------------|-------|
| 1 | **Patch check** with a line diff, before/after risk gauges and a clear verdict (fix confirmed / still vulnerable / regression / not flagged) | `POST /api/patch-check`, *Patch check* tab |
| 2 | **Threshold slider**: every result has a continuous `risk_score`; the slider moves the decision threshold (recall vs precision) live, and the Evaluation tab re-computes precision/recall/F1/F2 and the confusion matrix from saved per-sample scores | `app/scoring.py`, header slider |
| 3 | **Scan a whole `.c` file**: split into functions, rank by risk, export CSV/JSON. Also usable in CI: `python -m app.cli scan file.c --fail-above 0.7` exits with code 1 if any function is risky | `app/splitter.py`, `app/scanner.py`, `POST /api/scan-file` |
| 4 | **Called-function bodies in the prompt** (same file, one level deep, max 3). In the Detect tab you can also paste helper bodies yourself | `splitter.callee_context`, `Detector.analyze` |
| 5 | **flawfinder / cppcheck output in the prompt** and as a risk signal. Skipped automatically if a tool is not installed | `app/static_tools.py` |
| 6 | **Analyst feedback**: "Is this verdict wrong?" and "Confirm this fix" go to a review queue. A reviewer approves them in the *Review* tab and only then do they enter the knowledge base | `app/feedback.py`, `/api/feedback*` |
| 7 | **Weight tuning** of the WRRF channel weights, the risk-signal weights and the threshold on the VALIDATION split, with a held-out check | `app/tune.py`, `python -m app.cli tune` |

How the risk score works: a weighted average of up to five signals in [0,1] (LLM verdict, match with the unfixed lines of the closest historical fix, nearest side of that pair, risky API calls, static analyzers). Signals that are unavailable (no LLM, no analyzer) are left out and the rest are re-normalised, so the app also works in heuristic mode. Defaults are in `app/config.py`.

### Tune on the validation split
    python -m app.cli tune data/primevul_valid_paired.jsonl --limit 200 --iters 200 --beta 2
Writes `data/tuned_params.json`, which is loaded automatically at start-up. 30% of the pairs are held out and the file is only saved if the tuned weights do not do worse on them (`--force` overrides). The script refuses file names containing "test" so the test split is never used for tuning. Add `--no-llm` for a quick run, `--static` to include flawfinder/cppcheck.

### Scan a file from the command line / CI
    python -m app.cli scan path/to/file.c --fail-above 0.7 --json report.json

### Analyst review
Set `ADMIN_TOKEN` (a long random string) on the server to enable approving/rejecting feedback in the Review tab. Without it, review is off and nobody can change the knowledge base; anyone can still *send* feedback. Feedback is stored in `data/feedback/` (override with `FEEDBACK_DIR`). On hosts with an ephemeral disk, attach a persistent disk to `data/` or the queue and approved additions are lost on redeploy. A lone function cannot form a vulnerable/fixed pair, so it is kept as a labelled example unless the reviewer pastes the counterpart version.

### Environment variables added
`ADMIN_TOKEN`, `FEEDBACK_DIR`, `TUNED_PARAMS`, `STATIC_TOOLS=off` (disable analyzers), `SCAN_TIME_BUDGET_S` (default 90).

### Tests
    EMBEDDER=hash python -m unittest discover -s tests

## 1. Build the knowledge base (TRAINING split only)
Run in Colab with a GPU (UniXCoder), then download the `data/kb` folder into this project.
    pip install -r requirements.txt torch transformers
    python -m app.cli build data/primevul_train_paired.jsonl --variants          # add --llm-knowledge if LLM is configured
## 2. Configure the LLM (optional; paper used DeepSeek-V3)
    export LLM_BASE_URL=https://api.deepseek.com/v1  LLM_API_KEY=...  LLM_MODEL=deepseek-chat
## 3. Run
    uvicorn app.main:app --reload        # open http://localhost:8000
## 4. Evaluate on the TEST split (paper: 435 pairs)
    python -m app.cli eval data/primevul_test_paired.jsonl --limit 50
No GPU/internet? `export EMBEDDER=hash` uses hashing embeddings (demo quality only; build and run with the same setting).
## Deploy (Render / any host that runs Python)
Commit `app/`, `frontend/`, `data/kb/`, `requirements.txt`, `Procfile`. Build command: `pip install -r requirements.txt`. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`. Set the LLM_* variables as secrets. Prebuild the KB (do not build on the server). Use EMBEDDER=unixcoder only if the host has enough RAM for torch + the model; otherwise keep the hosted demo small.


## 5. Evaluation on Render

The Evaluation tab reads `data/eval_results.json`. The deployed service can generate
that file at startup when all required data is present:

1. Include the prebuilt training knowledge base (`data/kb/kb.json` and
   `data/kb/vecs.npz`) in the deployed project.
2. Include the paired PrimeVul test split as
   `data/primevul_test_paired.jsonl`, or set the Render environment variable
   `EVAL_DATASET` to its project-relative path.
3. In Render → your Web Service → Environment, set
   `RUN_EVAL_ON_STARTUP` to `true`.
4. Redeploy. The startup evaluation runs against the test pairs and writes
   `data/eval_results.json`; the Evaluation tab then displays the metrics.

The test split is intentionally not generated from `sample_pairs.jsonl`: that
would produce demo numbers, not a valid PrimeVul test evaluation. Do not use the
test split to build the knowledge base; build `data/kb` from the training split
only. If your Render service uses an ephemeral filesystem, generated results
may be lost on restart; keep the test dataset and knowledge base in the deploy
artifact, and enable startup evaluation so the results are regenerated.

For a local evaluation, from the repository root run:

    python -m app.cli eval data/primevul_test_paired.jsonl

You can also pass `--limit 50` for a small smoke test. The output is saved to
`data/eval_results.json` by default.

## 6. Quick deploy fix (Evaluation + Review)
* `python scripts/bootstrap.py` (already in `render.yaml` build command) builds a demo `data/kb` and a clearly labelled DEMO `data/eval_results.json` if they are missing.
* Set `ADMIN_TOKEN` (Render generates one via `render.yaml`) and open Review -> paste the token.
* Keep `EMBEDDER=hash` while using the demo KB; rebuild the KB with `unixcoder` for real results.
* For real numbers: build `data/kb` from the TRAIN split, add `data/primevul_test_paired.jsonl`, delete `data/eval_results.json`, run `python -m app.cli eval data/primevul_test_paired.jsonl`.
