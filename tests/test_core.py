"""Offline smoke tests (no GPU, LLM or network):  EMBEDDER=hash python -m unittest discover -s tests"""
import json, os, sys, tempfile, unittest
os.environ.setdefault("EMBEDDER", "hash")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import static_tools
from app.detector import Detector
from app.feedback import FeedbackStore
from app.kb import KnowledgeBase
from app.scanner import scan_file
from app.splitter import callee_context, split_functions

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAIRS = [json.loads(l) for l in open(os.path.join(ROOT, "data", "sample_pairs.jsonl"))]
SRC = "static void h(char *d, const char *s) { strcpy(d, s); }\nvoid run(const char *in) {\n    char b[8];\n    h(b, in);\n}\n"


class Core(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.kb = KnowledgeBase(cls.tmp + "/kb"); cls.kb.add_pairs(PAIRS)
        cls.det = Detector(cls.kb)

    def test_splitter_and_callees(self):
        fs = split_functions(SRC)
        self.assertEqual([f["name"] for f in fs], ["h", "run"])
        ctx, names = callee_context(fs[1], {f["name"]: f for f in fs})
        self.assertEqual(names, ["h"]); self.assertIn("strcpy", ctx)

    def test_vulnerable_scores_above_fixed(self):
        p = PAIRS[0]
        v, f = self.det.detect(p["vulnerable_code"], static=False), self.det.detect(p["fixed_code"], static=False)
        self.assertGreater(v["risk_score"], f["risk_score"])
        self.assertEqual(v["is_vul"], v["risk_score"] >= v["threshold"])

    def test_scan_returns_ranked_functions(self):
        out = scan_file(self.det, SRC, "c", use_static=False)
        fns = out["functions"]
        self.assertEqual({f["name"] for f in fns}, {"h", "run"})
        self.assertEqual([f["risk_score"] for f in fns], sorted((f["risk_score"] for f in fns), reverse=True))
        self.assertEqual(next(f for f in fns if f["name"] == "run")["callees"], ["h"])

    def test_static_parsers(self):
        csv = "File,Line,Level,Name,Warning,CWEs\nt.c,3,4,strcpy,Does not check,CWE-120\n"
        self.assertEqual(static_tools.parse_flawfinder_csv(csv)[0]["weight"], 1.0)
        self.assertEqual(static_tools.parse_cppcheck("5|warning|nullPointer|x\n6|style|unused|y\n")[0]["rule"], "nullPointer")

    def test_feedback_pair_reaches_kb_only_after_approval(self):
        fs = FeedbackStore(self.tmp + "/fb", self.kb)
        n = len(self.kb.pairs)
        item = fs.submit({"kind": "pair", "old_code": "void a(char*s){char b[4];strcpy(b,s);}", "new_code": "void a(char*s){char b[4];strncpy(b,s,3);}"})
        self.assertEqual(len(self.kb.pairs), n)
        fs.approve(item["id"]); self.assertEqual(len(self.kb.pairs), n + 1)


if __name__ == "__main__":
    unittest.main()
