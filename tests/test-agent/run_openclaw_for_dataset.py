#!/usr/bin/env python3
"""Run a Langfuse dataset as an experiment against the OpenClaw agent (via Gateway).

Each dataset item's `input` is sent to `openclaw agent --json ...`, the agent's
reply is captured, and a Langfuse trace/dataset-run-item is created linking the
run to the dataset. Scoring is handled by the LLM-as-judge Evaluator already
configured in the Langfuse project (it scores new dataset-run traces against
each item's `expected_output` automatically).

Usage:
    python3 -m venv .venv
    ./.venv/bin/python -m pip install --upgrade pip
    ./.venv/bin/python -m pip install -r requirements.txt

    ./.venv/bin/python run_openclaw_for_dataset.py \
        --dataset-name your-dataset-name \
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
        trace_scores = langfuse.api.score_v_2.get(trace_id=item_result.trace_id, limit=100)
        persisted_scores.append(
            {
                "input": input_value,
                "output": item_result.output,
                "scores": {
                    score.name: (
                        score.value
                        if getattr(score, "string_value", None) is None
                        else score.string_value
                    )
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


def wait_for_persisted_scores(
    result: Any,
    langfuse: Langfuse,
    *,
    wait_seconds: float,
    poll_seconds: float,
) -> list[dict[str, Any]]:
    """Poll Langfuse until evaluator scores are persisted for every item."""
    wait_seconds = max(wait_seconds, 0.0)
    poll_seconds = max(poll_seconds, 0.1)
    deadline = time.monotonic() + wait_seconds
    persisted_scores = get_persisted_scores(result, langfuse)
    missing_count = sum(1 for item_result in persisted_scores if not item_result["scores"])

    while missing_count and time.monotonic() < deadline:
        remaining_seconds = deadline - time.monotonic()
        time.sleep(min(poll_seconds, remaining_seconds))
        persisted_scores = get_persisted_scores(result, langfuse)
        missing_count = sum(1 for item_result in persisted_scores if not item_result["scores"])

    if missing_count:
        print(
            "Timed out waiting for persisted evaluator scores "
            f"({missing_count} item(s) still missing)."
        )

    return persisted_scores


def plot_scores(
    result: Any,
    output_dir: Path,
    persisted_scores: list[dict[str, Any]],
    model: str,
) -> None:
    """Add this run to the persisted model comparison graph."""
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
    comparison_data_path = output_dir / "all_metrics_data.json"
    comparison_runs: list[dict[str, Any]] = []
    if comparison_data_path.exists():
        try:
            stored_data = json.loads(comparison_data_path.read_text(encoding="utf-8"))
            if isinstance(stored_data, list):
                comparison_runs = stored_data
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Could not read existing comparison data: {exc}")

    current_run = {"run_name": result.run_name, "model": model, "scores": scores}
    comparison_runs = [
        run for run in comparison_runs if run.get("run_name") != result.run_name
    ]
    comparison_runs.append(current_run)
    comparison_data_path.write_text(
        json.dumps(comparison_runs, indent=2),
        encoding="utf-8",
    )

    item_count = max(
        len(values)
        for run in comparison_runs
        for values in run.get("scores", {}).values()
    )
    item_numbers = list(range(1, item_count + 1))
    figure, axis = plt.subplots(figsize=(12, 6))
    for run in comparison_runs:
        for name, values in run.get("scores", {}).items():
            run_items = list(range(1, len(values) + 1))
            label = f"{run['model']} - {name}"
            axis.plot(run_items, values, marker="o", label=label)
    axis.set_title("Evaluator score comparison by model")
    axis.set_xlabel("Dataset item")
    axis.set_ylabel("Score")
    axis.set_xticks(item_numbers)
    axis.grid(True, alpha=0.3)
    axis.legend()
    figure.tight_layout()
    output_path = output_dir / "all_metrics.png"
    figure.savefig(output_path, dpi=150)
    plt.close(figure)
    print(f"Score graph (all metrics): {output_path.resolve()}")
    print(f"Score comparison data: {comparison_data_path.resolve()}")


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
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Only run the first N items of the dataset (default: run all items)",
    )
    parser.add_argument(
        "--score-wait-seconds",
        type=float,
        default=180.0,
        help="Seconds to wait for asynchronous Langfuse evaluator scores before plotting",
    )
    parser.add_argument(
        "--score-poll-seconds",
        type=float,
        default=2.0,
        help="Seconds between evaluator score polling attempts",
    )
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
    if args.limit is not None:
        dataset.items = dataset.items[: args.limit]
    task = build_task(agent=args.agent, model=args.model, run_name=args.run_name)

    # Langfuse calls task once per item and associates its return value with that item.
    result = dataset.run_experiment(
        name=args.run_name,
        description="OpenClaw agent responses evaluated by the configured LLM-as-judge Evaluator",
        task=task,
        max_concurrency=args.max_concurrency,
        metadata={"agent": args.agent, "model": args.model or "default"},
    )

    persisted_scores = wait_for_persisted_scores(
        result,
        langfuse,
        wait_seconds=args.score_wait_seconds,
        poll_seconds=args.score_poll_seconds,
    )
    print_persisted_scores(persisted_scores)
    plot_scores(result, args.plot_dir, persisted_scores, args.model or "default")
    # print(result.format(include_item_results=True))
    print(f"Langfuse results: {result.dataset_run_url}")


if __name__ == "__main__":
    main()
