"""Real CodeBERT-based backdoor detector with cosine retrieval."""

from __future__ import annotations

import ast
import re
from typing import Any

import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer

from .config import DANGEROUS_SQL_KEYWORDS, KNOWN_MALICIOUS_SNIPPETS, SUSPICIOUS_BINARIES, SIMILARITY_THRESHOLD


class CodeBERTBackdoorGuard:
    """CodeBERT similarity detector with explicit rule triggers."""

    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",
        similarity_threshold: float = SIMILARITY_THRESHOLD,
    ) -> None:
        self.model_name = model_name
        self.similarity_threshold = similarity_threshold
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModel.from_pretrained(self.model_name, use_safetensors=False).to(self.device)
        self.model.eval()
        self._index_matrix, self._index_examples = self._build_index(KNOWN_MALICIOUS_SNIPPETS)

    def _embed(self, texts: list[str]) -> np.ndarray:
        toks = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt",
        )
        toks = {k: v.to(self.device) for k, v in toks.items()}
        with torch.no_grad():
            out = self.model(**toks, return_dict=True)
            last = out.last_hidden_state
            mask = toks["attention_mask"].unsqueeze(-1)
            pooled = (last * mask).sum(1) / mask.sum(1).clamp(min=1)
            embs = pooled.detach().cpu().numpy().astype("float32")
        norms = np.linalg.norm(embs, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return embs / norms

    def _build_index(self, snippets: list[str]) -> tuple[np.ndarray, list[str]]:
        embs = self._embed(snippets)
        return embs, snippets

    def _embedding_hits(self, code: str, topk: int = 3) -> tuple[list[dict[str, Any]], float]:
        emb = self._embed([code])
        # cosine similarity since vectors are L2-normalized.
        sims = np.matmul(self._index_matrix, emb[0])
        order = np.argsort(-sims)[:topk]
        hits: list[dict[str, Any]] = []
        max_sim = 0.0
        for idx in order:
            sim_f = float(sims[int(idx)])
            if sim_f >= self.similarity_threshold:
                hits.append(
                    {
                        "example": self._index_examples[int(idx)],
                        "sim": round(sim_f, 4),
                    }
                )
            max_sim = max(max_sim, sim_f)
        return hits, max_sim

    @staticmethod
    def _ast_findings(code: str) -> list[str]:
        findings: list[str] = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return findings

        def _str_constant(node: ast.AST) -> str | None:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            return None

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in {"eval", "exec"}:
                findings.append("dynamic execution (eval/exec)")
            if func_name in {"system", "Popen", "run", "call"}:
                findings.append("shell/subprocess execution")
            if func_name in {"execute", "executemany", "executescript"} and node.args:
                sql_literal = _str_constant(node.args[0])
                if sql_literal:
                    lowered = sql_literal.lower()
                    if any(re.search(rf"\b{kw}\b", lowered) for kw in DANGEROUS_SQL_KEYWORDS):
                        findings.append("dangerous SQL literal")
                else:
                    findings.append("dynamic SQL construction")
            if func_name == "delete":
                findings.append("ORM delete call")
        return sorted(set(findings))

    @staticmethod
    def _subprocess_hits(code: str) -> list[str]:
        hits: list[str] = []
        for binary in SUSPICIOUS_BINARIES:
            if re.search(rf"[\"'\s/\[]({re.escape(binary)})[\"'\s\],/]", code):
                hits.append(binary)
        if re.search(r"subprocess\.Popen|subprocess\.call|subprocess\.run|os\.system", code):
            for binary in SUSPICIOUS_BINARIES:
                if binary in code and binary not in hits:
                    hits.append(binary)
        return sorted(set(hits))

    @staticmethod
    def _behavioral_hits(code: str) -> list[str]:
        hits: list[str] = []
        if re.search(r"rm\s+-rf|drop\s+table|truncate\s+table", code, flags=re.IGNORECASE):
            hits.append("destructive command pattern")
        if re.search(r"/dev/tcp|reverse shell|nc\s+-e", code, flags=re.IGNORECASE):
            hits.append("network exfiltration / shell beacon")
        return hits

    def check_code_safety(self, code: str) -> dict[str, Any]:
        ast_hits = self._ast_findings(code)
        subproc_hits = self._subprocess_hits(code)
        behavioral_hits = self._behavioral_hits(code)
        embedding_hits, max_sim = self._embedding_hits(code)

        rule_triggered = bool(ast_hits or subproc_hits or behavioral_hits)
        codebert_triggered = max_sim >= self.similarity_threshold

        if rule_triggered and codebert_triggered:
            label = "MALICIOUS"
        elif rule_triggered or codebert_triggered:
            label = "SUSPICIOUS"
        else:
            label = "CLEAN"

        return {
            "label": label,
            "score": round(float(max_sim), 4),
            "details": {
                "ast_findings": ast_hits,
                "subprocess_hits": subproc_hits,
                "behavioral_findings": behavioral_hits,
                "embedding_hits": embedding_hits,
                "max_similarity": round(float(max_sim), 4),
                "similarity_threshold": self.similarity_threshold,
                "codebert_triggered": codebert_triggered,
                "rule_triggered": rule_triggered,
            },
        }
