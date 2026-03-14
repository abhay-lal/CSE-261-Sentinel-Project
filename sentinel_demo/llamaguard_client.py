"""Real Llama Guard client using Groq-hosted Llama Guard models."""

from __future__ import annotations

import os
import re
import time
from typing import Any

from groq import Groq


class LlamaGuardClient:
    """Thin wrapper around Groq Llama Guard completion API."""

    def __init__(self, model: str | None = None) -> None:
        api_key = os.getenv("GROQ_API_KEY")
        self.model = model or os.getenv("GROQ_LLAMAGUARD_MODEL", "meta-llama/llama-guard-4-12b")
        self._client = Groq(api_key=api_key) if api_key else None
        # Keep below provider RPM limits to avoid 429 storms.
        self.max_rpm = int(os.getenv("LLAMAGUARD_MAX_RPM", "25"))
        self.min_interval_s = 60.0 / max(1, self.max_rpm)
        self.max_retries = int(os.getenv("LLAMAGUARD_MAX_RETRIES", "8"))
        self._next_call_ts = 0.0
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}

    def is_configured(self) -> bool:
        return self._client is not None

    def classify(self, text: str, direction: str = "input") -> dict[str, Any]:
        if not self._client:
            raise RuntimeError("Llama Guard is not configured. Set GROQ_API_KEY.")

        cache_key = (direction, text)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        role = "assistant" if direction.lower().startswith("out") else "user"
        attempt = 0
        while True:
            attempt += 1
            self._throttle()
            try:
                completion = self._client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": role, "content": text}],
                    temperature=0,
                    max_tokens=64,
                )
                raw = completion.choices[0].message.content.strip() if completion.choices else ""
                parsed = self._parse_response(raw)
                if parsed is None:
                    raise RuntimeError(f"Failed to parse Llama Guard output: {raw!r}")
                parsed["raw_text"] = raw
                self._cache[cache_key] = parsed
                return parsed
            except Exception as exc:
                if attempt >= self.max_retries:
                    raise RuntimeError(
                        f"Llama Guard call failed after {attempt} attempts: {exc}"
                    ) from exc
                sleep_s = self._retry_delay(attempt, exc)
                time.sleep(sleep_s)

    @staticmethod
    def _parse_response(raw: str) -> dict[str, Any] | None:
        if not raw:
            return None
        low = raw.lower().strip()
        if low.startswith("safe"):
            return {
                "flagged": False,
                "categories_codes": [],
                "reason": "safe",
            }
        if low.startswith("unsafe"):
            lines = raw.splitlines()
            codes: list[str] = []
            if len(lines) >= 2:
                tail = ",".join(lines[1:])
                codes = [c.strip().upper() for c in re.split(r"[,\s]+", tail) if c.strip()]
            codes = [c for c in codes if re.match(r"^S\d+$", c)]
            return {
                "flagged": True,
                "categories_codes": codes,
                "reason": "unsafe",
            }
        return None

    def _throttle(self) -> None:
        now = time.time()
        if now < self._next_call_ts:
            time.sleep(self._next_call_ts - now)
        self._next_call_ts = time.time() + self.min_interval_s

    @staticmethod
    def _retry_delay(attempt: int, exc: Exception) -> float:
        msg = str(exc)
        # Parse provider hint: "Please try again in 2s"
        m = re.search(r"try again in\s+(\d+)s", msg, flags=re.IGNORECASE)
        if m:
            return float(m.group(1)) + 0.2
        # Conservative exponential backoff.
        return min(30.0, 1.5 ** attempt)
