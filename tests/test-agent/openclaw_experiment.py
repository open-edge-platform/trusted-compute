#!/usr/bin/env python3
"""Run a Langfuse dataset as an experiment against the OpenClaw agent (via Gateway).

Each dataset item's `input` is sent to `openclaw agent --json ...`, the agent's
reply is captured, and a Langfuse trace/dataset-run-item is created linking the
run to the dataset. Scoring is handled by the LLM-as-judge Evaluator already
configured in the Langfuse project (it scores new dataset-run traces against
each item's `expected_output` automatically).

Usage:
    ./.venv/bin/python openclaw_experiment.py \
        --dataset-name trusted-compute-evaluation \
        --run-name openclaw-baseline \
        --agent main
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from langfuse import Langfuse

OPENCLAW_CONFIG_PATH = Path.home() / ".openclaw" / "openclaw.json"


def load_langfuse_config(config_path: Path) -> dict[str, str]:
    """Read Langfuse credentials from OpenClaw's plugin configuration."""
    with config_path.open(encoding="utf-8") as config_file:
        config = json.load(config_file)

    try:
        plugin_config = config["plugins"]["entries"]["langfuse-bridge"]["config"]
        public_key = plugin_config["publicKey"]
        secret_key = plugin_config["secretKey"]
        host = plugin_config.get("baseUrl", "http://localhost:3000")
    except (KeyError, TypeError) as exc:
        raise RuntimeError(
            "Could not find plugins.entries.langfuse-bridge.config in "
            f"{config_path}"
        ) from exc

    if not all(isinstance(value, str) and value for value in (public_key, secret_key, host)):
        raise RuntimeError(f"Langfuse credentials are incomplete in {config_path}")

    return {"public_key": public_key, "secret_key": secret_key, "host": host}


def extract_input_text(raw_input: Any) -> str:
    """Dataset item inputs may be a plain string or a dict; find the text to send."""
    if isinstance(raw_input, str):
        return raw_input
    if isinstance(raw_input, dict):
        for key in ("question", "input", "message", "text", "prompt"):
            if key in raw_input and isinstance(raw_input[key], str):
                return raw_input[key]
        return json.dumps(raw_input)
    return str(raw_input)


def run_openclaw_agent(
    *,
    message: str,
    agent: str,
    session_key: str,
    model: str | None,
) -> dict[str, Any]:
    # This CLI call uses the Gateway path used by the OpenClaw TUI.
    cmd = [
        "openclaw",
        "agent",
        "--agent",
        agent,
        "--session-key",
        session_key,
        "--message",
        message,
        "--json",
    ]
    if model:
        cmd += ["--model", model]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"openclaw agent failed (exit {proc.returncode}): {proc.stderr.strip()}")

    # OpenClaw returns the agent reply inside result.payloads.
    payload = json.loads(proc.stdout)
    payloads = payload.get("result", {}).get("payloads", [])
    text = "\n".join(p.get("text", "") for p in payloads if p.get("text"))
    return {"text": text, "raw": payload}


def build_task(*, agent: str, model: str | None, run_name: str):
    def task(*, item: Any, **_: Any) -> str:
        message = extract_input_text(item.input)
        # Isolate each dataset item so previous answers cannot affect this run.
        session_key = f"agent:{agent}:experiment-{run_name}-{uuid.uuid4().hex[:8]}"
        outcome = run_openclaw_agent(
            message=message,
            agent=agent,
            session_key=session_key,
            model=model,
        )
        return outcome["text"]

    return task


def get_persisted_scores(result: Any, langfuse: Langfuse) -> list[dict[str, Any]]:
    """Read evaluator scores persisted on each experiment trace in Langfuse."""
    persisted_scores = []
    for index, item_result in enumerate(result.item_results, start=1):
        item = item_result.item
        input_value = item.get("input") if isinstance(item, dict) else item.input
        trace_scores = langfuse.api.scores.get_many(trace_id=item_result.trace_id, limit=100)
        persisted_scores.append(
            {
                "input": input_value,
                "output": item_result.output,
                "scores": {
                    score.name: score.value if score.string_value is None else score.string_value
                    for score in trace_scores.data
                },
            }
        )
    return persisted_scores


def print_persisted_scores(persisted_scores: list[dict[str, Any]]) -> None:
    """Print each dataset item with its response and persisted evaluator scores."""
    print("\nPersisted Langfuse scores:")
    for index, item_result in enumerate(persisted_scores, start=1):
        print(f"\nItem {index}")
        print(f"Input: {item_result['input']}")
        print(f"Response: {item_result['output']}")
        if item_result["scores"]:
            for name, value in item_result["scores"].items():
                print(f"Score ({name}): {value}")
        else:
            print("Score: no persisted evaluation found")


def plot_scores(result: Any, output_dir: Path, persisted_scores: list[dict[str, Any]]) -> None:
    """Create one score graph per numeric evaluator across all dataset items."""
    try:
        import matplotlib.pyplot as plt
    except ModuleNotFoundError:
        print("Score graphs not created: matplotlib is not installed.")
        return

    scores: dict[str, list[float | None]] = {}
    evaluator_names = {
        name
        for item_result in persisted_scores
        for name, value in item_result["scores"].items()
        if isinstance(value, (int, float))
    }
    for name in evaluator_names:
        scores[name] = [
            item_result["scores"].get(name)
            if isinstance(item_result["scores"].get(name), (int, float))
            else None
            for item_result in persisted_scores
        ]

    if not scores:
        print("Score graph not created: no evaluations were recorded.")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    item_numbers = list(range(1, len(persisted_scores) + 1))
    for name, values in scores.items():
        figure, axis = plt.subplots(figsize=(12, 6))
        axis.plot(item_numbers, values, marker="o", label=name)
        axis.set_title(f"{name} scores for {result.run_name}")
        axis.set_xlabel("Dataset item")
        axis.set_ylabel("Score")
        axis.set_xticks(item_numbers)
        axis.grid(True, alpha=0.3)
        figure.tight_layout()
        output_path = output_dir / f"{name.replace(' ', '_')}.png"
        figure.savefig(output_path, dpi=150)
        plt.close(figure)
        print(f"Score graph ({name}): {output_path.resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a Langfuse dataset experiment against OpenClaw")
    parser.add_argument("--dataset-name", required=True, help="Langfuse dataset name")
    parser.add_argument("--run-name", default=f"openclaw-run-{int(time.time())}")
    parser.add_argument("--agent", default="main", help="OpenClaw agent id")
    parser.add_argument("--model", default=None, help="Model override (provider/model or model id)")
    parser.add_argument(
        "--config-path",
        type=Path,
        default=OPENCLAW_CONFIG_PATH,
        help="OpenClaw config containing the langfuse-bridge keys",
    )
    parser.add_argument(
        "--plot-dir",
        type=Path,
        default=Path("score_plots"),
        help="Directory for the generated evaluator score graphs",
    )
    parser.add_argument("--max-concurrency", type=int, default=1)
    args = parser.parse_args()

    langfuse_config = load_langfuse_config(args.config_path)
    # The SDK uses these config values to read the dataset and write run results.
    langfuse = Langfuse(
        public_key=langfuse_config["public_key"],
        secret_key=langfuse_config["secret_key"],
        host=langfuse_config["host"],
    )

    # The original dataset remains unchanged; outputs are stored in a dataset run.
    dataset = langfuse.get_dataset(args.dataset_name)
    task = build_task(agent=args.agent, model=args.model, run_name=args.run_name)

    # Langfuse calls task once per item and associates its return value with that item.
    result = dataset.run_experiment(
        name=args.run_name,
        description="OpenClaw agent responses evaluated by the configured LLM-as-judge Evaluator",
        task=task,
        max_concurrency=args.max_concurrency,
        metadata={"agent": args.agent, "model": args.model or "default"},
    )

    persisted_scores = get_persisted_scores(result, langfuse)
    print_persisted_scores(persisted_scores)
    plot_scores(result, args.plot_dir, persisted_scores)
    # print(result.format(include_item_results=True))
    print(f"Langfuse results: {result.dataset_run_url}")


if __name__ == "__main__":
    main()
