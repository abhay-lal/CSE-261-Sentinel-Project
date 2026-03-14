"""Data models for pipeline traces."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


@dataclass
class LayerResult:
    layer: str
    status: str
    action: str
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PipelineResult:
    run_id: str
    prompt: str
    generated_code: str
    final_status: str
    risk_label: str
    blocked_layer: str | None
    safe_output: str
    layers: list[LayerResult] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "prompt": self.prompt,
            "generated_code": self.generated_code,
            "final_status": self.final_status,
            "risk_label": self.risk_label,
            "blocked_layer": self.blocked_layer,
            "safe_output": self.safe_output,
            "layers": [layer.to_dict() for layer in self.layers],
            "timestamp": self.timestamp,
        }
