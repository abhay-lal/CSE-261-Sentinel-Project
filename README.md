# Sentinel Project (Runnable Demo)

**CSE 261 course project.**

- `L1 CodeGuard` (regex/pattern scan with parallel workers)
- `Semantic Guard` (real Llama Guard API classification)
- `L2 Backdoor Detection` (real CodeBERT similarity + rule triggers)
- `L3 Multi-Agent Validator` (trajectory-level risk)
- `L4 Safe Output` (final redaction step)

Real detector mode is required: only API/model-based detectors are used.

## Requirements

- Python 3.13+
- Virtual environment with dependencies installed
- `GROQ_API_KEY` (required for Llama Guard)
- Optional:
  - `GROQ_LLAMAGUARD_MODEL` (default: `meta-llama/llama-guard-4-12b`)
  - `LLAMAGUARD_MAX_RPM` (default: `25`, throttles request pace)
  - `LLAMAGUARD_MAX_RETRIES` (default: `8`, retry/backoff on rate limits)

Set env var for the current shell:

```bash
export GROQ_API_KEY="your_key_here"
```

## Run Demo

From project root:

```bash
./.venv/bin/python run_demo.py
```

This runs 3 built-in prompts and saves traces to `results/`.

## Run with your own prompt

```bash
./.venv/bin/python run_demo.py --prompt "Generate a report script for monthly expenses"
```

## Run with external code

If you have code in a file:

```bash
./.venv/bin/python run_demo.py --prompt "review this code" --code-file ./my_generated_code.py
```

## Human override

To simulate reviewer override:

```bash
./.venv/bin/python run_demo.py --run-examples
./.venv/bin/python run_demo.py --run-examples --override
```

## Output

For each run, the script prints:

- final status (`COMPLETED` / `BLOCKED`)
- risk level (`Low` / `Med` / `High`)
- per-layer verdicts and reasons
- trace JSON file path

Each trace file in `results/` contains all layer details for auditability.

## How Signals Become Binary Decision

Each layer evaluates independently and returns a structured verdict:

- `L1_CodeGuard`: allow / warn / block
- `Semantic_LlamaGuard`: safe / unsafe
- `L2_BackdoorDetection`: clean / suspicious / malicious
- `L3_MultiAgentValidator`: low / medium / high trajectory risk

Binary mapping used for evaluation:

```text
if any layer returns action=block  -> final_status = BLOCKED   -> predicted label = attack
else                               -> final_status = COMPLETED -> predicted label = safe
```

For JBB:

```text
harmful -> attack
benign  -> safe
```

## Quick metrics (benchmark mode)

Run evaluation on external datasets:

```bash
./.venv/bin/python evaluate.py --dataset-source jbb
./.venv/bin/python evaluate.py --dataset-source deepset --deepset-split all
```

Notes:
- `jbb` uses `JailbreakBench/JBB-Behaviors` (`harmful` + `benign`).
- `deepset` uses `deepset/prompt-injections` (`train` + `test` by default).
- Runs can take time because Llama Guard calls are rate-limited.

Run evaluation on your own JSONL dataset:

```bash
./.venv/bin/python evaluate.py --dataset-source custom --dataset ./your_prompts.jsonl
```

Expected custom JSONL row format:

```json
{"id":"row-1","label":"attack","attack_type":"prompt_injection","prompt":"..."}
```

Outputs:

- per-sample trace files in the selected `--save-dir`
- aggregate metrics summary in `<save-dir>/summary.json`

Metrics reported:

- confusion matrix (`tp`, `fp`, `tn`, `fn`) for attack detection
- accuracy
- precision / recall / F1 (attack class)
- false positive and false negative rates
- per-layer trigger and block counts
- sample misclassified prompts for debugging

## Latest Full JBB Results (Real Detectors)

Source file: `jbb_eval_summary.json` (copy of `results/real_eval_jbb/summary.json`, committed for reference)

- Dataset: `JailbreakBench/JBB-Behaviors` (`harmful` + `benign`)
- Total samples: `200` (binary classification: `attack` vs `safe`)
- Confusion matrix: `TP=87`, `FP=19`, `TN=81`, `FN=13`
- Accuracy: `0.84`
- Precision (attack): `0.8208`
- Recall (attack): `0.87`
- F1 (attack): `0.8447`
- False positive rate: `0.19`
- False negative rate: `0.13`
