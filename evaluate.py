#!/usr/bin/env python3
"""Benchmark Sentinel demo on local or external datasets."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from sentinel_demo import SentinelPipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate Sentinel quick demo.")
    parser.add_argument(
        "--dataset-source",
        choices=["custom", "jbb", "deepset"],
        default="jbb",
        help="Dataset source: custom JSONL, JailbreakBench, or deepset prompt-injections.",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="sentinel_eval_prompts.jsonl",
        help="Path to JSONL dataset when --dataset-source custom.",
    )
    parser.add_argument(
        "--deepset-split",
        choices=["train", "test", "all"],
        default="all",
        help="Which split to evaluate for deepset dataset.",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=0,
        help="Optional cap on total rows (0 = use all).",
    )
    parser.add_argument(
        "--save-dir",
        type=str,
        default="results/eval",
        help="Directory where per-run traces and summary are saved.",
    )
    parser.add_argument(
        "--strict-real-only",
        action="store_true",
        help="Reserved flag for compatibility; real detectors are always required.",
    )
    return parser.parse_args()


def load_local_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        rows.append(
            {
                "id": obj.get("id", f"custom-{len(rows) + 1}"),
                "prompt": obj["prompt"],
                "label": obj["label"],  # expected: attack|safe
                "attack_type": obj.get("attack_type", "unknown"),
            }
        )
    return rows


def load_external_rows(dataset_source: str, deepset_split: str) -> list[dict[str, Any]]:
    try:
        from datasets import load_dataset  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "HuggingFace datasets is required for external benchmarks. "
            "Install it in your venv and run with that Python."
        ) from exc

    rows: list[dict[str, Any]] = []
    if dataset_source == "jbb":
        ds = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors")
        for idx, row in enumerate(ds["harmful"]):
            rows.append(
                {
                    "id": f"jbb-h-{idx}",
                    "prompt": row["Goal"],
                    "label": "attack",
                    "attack_type": row.get("Category", "harmful"),
                }
            )
        for idx, row in enumerate(ds["benign"]):
            rows.append(
                {
                    "id": f"jbb-b-{idx}",
                    "prompt": row["Goal"],
                    "label": "safe",
                    "attack_type": row.get("Category", "benign"),
                }
            )
        return rows

    ds = load_dataset("deepset/prompt-injections")
    splits = ["train", "test"] if deepset_split == "all" else [deepset_split]
    for split in splits:
        for idx, row in enumerate(ds[split]):
            rows.append(
                {
                    "id": f"deepset-{split}-{idx}",
                    "prompt": row["text"],
                    "label": "attack" if int(row["label"]) == 1 else "safe",
                    "attack_type": "prompt_injection",
                }
            )
    return rows


def safe_div(num: float, den: float) -> float:
    return 0.0 if den == 0 else num / den


def evaluate(rows: list[dict[str, Any]], save_dir: Path, pipe: SentinelPipeline) -> dict[str, Any]:
    save_dir.mkdir(parents=True, exist_ok=True)

    tp = fp = tn = fn = 0
    total = 0
    by_attack_type: dict[str, Counter] = defaultdict(Counter)
    layer_trigger_counts: Counter = Counter()
    layer_block_counts: Counter = Counter()
    blocked_layer_counts: Counter = Counter()
    misclassified: list[dict[str, Any]] = []

    for row in rows:
        prompt = row["prompt"]
        label_attack = row["label"] == "attack"
        attack_type = row.get("attack_type", "unknown")

        result = pipe.run(prompt=prompt)
        SentinelPipeline.save_result(result, save_dir)
        predicted_attack = result.final_status == "BLOCKED"

        total += 1
        if label_attack and predicted_attack:
            tp += 1
        elif (not label_attack) and predicted_attack:
            fp += 1
        elif (not label_attack) and (not predicted_attack):
            tn += 1
        else:
            fn += 1

        if predicted_attack != label_attack and len(misclassified) < 50:
            misclassified.append(
                {
                    "id": row.get("id"),
                    "attack_type": attack_type,
                    "label": row["label"],
                    "predicted": "attack" if predicted_attack else "safe",
                    "blocked_layer": result.blocked_layer,
                    "prompt": prompt[:220],
                }
            )

        if result.blocked_layer:
            blocked_layer_counts[result.blocked_layer] += 1

        for layer in result.layers:
            if layer.action != "allow":
                layer_trigger_counts[layer.layer] += 1
            if layer.action == "block":
                layer_block_counts[layer.layer] += 1

        key = "tp" if (label_attack and predicted_attack) else (
            "fp" if ((not label_attack) and predicted_attack) else (
                "tn" if ((not label_attack) and (not predicted_attack)) else "fn"
            )
        )
        by_attack_type[attack_type][key] += 1
        by_attack_type[attack_type]["count"] += 1

    accuracy = safe_div(tp + tn, total)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, fn + tp)

    return {
        "dataset_size": total,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision_attack": round(precision, 4),
            "recall_attack": round(recall, 4),
            "f1_attack": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
        },
        "layer_trigger_counts": dict(layer_trigger_counts),
        "layer_block_counts": dict(layer_block_counts),
        "blocked_layer_counts": dict(blocked_layer_counts),
        "attack_type_breakdown": {k: dict(v) for k, v in by_attack_type.items()},
        "misclassified_examples": misclassified,
    }


def main() -> None:
    args = parse_args()
    save_dir = Path(args.save_dir)
    _ = args.strict_real_only
    pipe = SentinelPipeline()

    if args.dataset_source == "custom":
        dataset_path = Path(args.dataset)
        rows = load_local_jsonl(dataset_path)
        source_name = str(dataset_path)
    else:
        rows = load_external_rows(args.dataset_source, args.deepset_split)
        source_name = f"{args.dataset_source}:{args.deepset_split}"

    if args.max_samples > 0:
        rows = rows[: args.max_samples]

    summary = evaluate(rows, save_dir, pipe)

    summary_path = save_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("Evaluation complete.")
    print(f"Dataset source: {source_name}")
    print(f"Total samples: {summary['dataset_size']}")
    print(f"Confusion matrix: {summary['confusion_matrix']}")
    print(f"Metrics: {summary['metrics']}")
    print(f"Summary file: {summary_path}")


if __name__ == "__main__":
    main()
