import os
import re
import zlib
import numpy as np


class Embedder:
    """Paper: UniXCoder-base (768-d). Falls back to hashing embeddings so the demo runs without GPU/downloads."""

    def __init__(self):
        self.model = None
        self.dim, self.name = 1024, "hash-1024"
        if os.getenv("EMBEDDER", "unixcoder") == "unixcoder":
            try:
                import torch
                from transformers import AutoModel, AutoTokenizer
                self.torch = torch
                self.tok = AutoTokenizer.from_pretrained("microsoft/unixcoder-base")
                self.model = AutoModel.from_pretrained("microsoft/unixcoder-base").eval()
                self.dim, self.name = 768, "unixcoder-base"
            except Exception as e:
                print("UniXCoder unavailable, using hashing embeddings:", type(e).__name__)

    def encode(self, texts: list[str]) -> np.ndarray:
        if self.model is None:
            return self._hash(texts)
        out = []
        with self.torch.no_grad():
            for i in range(0, len(texts), 16):
                b = self.tok(texts[i:i + 16], padding=True, truncation=True, max_length=512, return_tensors="pt")
                h = self.model(**b).last_hidden_state
                m = b["attention_mask"].unsqueeze(-1)
                e = (h * m).sum(1) / m.sum(1)
                out.append(self.torch.nn.functional.normalize(e, dim=1).numpy())
        return np.vstack(out).astype(np.float32)

    def _hash(self, texts):
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, t in enumerate(texts):
            toks = re.findall(r"[A-Za-z_]\w*|\d+|[^\s\w]", t)
            for a, b in zip(toks, toks[1:] + [""]):
                out[i, zlib.crc32(a.encode()) % self.dim] += 1.0
                out[i, zlib.crc32(f"{a} {b}".encode()) % self.dim] += 0.5
            n = np.linalg.norm(out[i])
            out[i] /= n if n else 1.0
        return out
