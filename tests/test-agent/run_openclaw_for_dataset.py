#!/usr/bin/env python3
"""Run a Langfuse dataset as an experiment against the OpenClaw agent (via Gateway).

Each dataset item's `input` is sent to the Gateway's OpenAI-compatible
`/v1/chat/completions` endpoint, the agent's reply is captured, and a Langfuse
trace/dataset-run-item is created linking the run to the dataset. Scoring is
handled by the LLM-as-judge Evaluator already configured in the Langfuse
project (it scores new dataset-run traces against each item's
`expected_output` automatically).

The Gateway's chatCompletions endpoint must be enabled first:
    openclaw config set gateway.http.endpoints.chatCompletions.enabled true --strict-json
    openclaw gateway restart

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
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from langfuse import Langfuse

OPENCLAW_CONFIG_PATH = Path.home() / ".openclaw" / "openclaw.json"
DEFAULT_GATEWAY_PORT = 18790


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


def load_gateway_config(config_path: Path) -> dict[str, Any]:
    """Read the Gateway's local URL and auth credential from the OpenClaw config."""
    with config_path.open(encoding="utf-8") as config_file:
        config = json.load(config_file)

    gateway_config = config.get("gateway", {})
    port = gateway_config.get("port", DEFAULT_GATEWAY_PORT)
    auth = gateway_config.get("auth", {})
    auth_mode = auth.get("mode", "none")
    # token/password auth both send the credential as a bearer token.
    credential = auth.get("token") if auth_mode == "token" else auth.get("password")

    return {"url": f"http://127.0.0.1:{port}", "credential": credential}


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
    gateway_url: str,
    credential: str | None,
) -> dict[str, Any]:
    # Calls the Gateway's OpenAI-compatible endpoint (same codepath as `openclaw agent`).
    request_body = {
        "model": f"openclaw/{agent}",
        "messages": [{"role": "user", "content": message}],
        "user": session_key,
    }
    headers = {"Content-Type": "application/json"}
    if credential:
        headers["Authorization"] = f"Bearer {credential}"
    if model:
        headers["x-openclaw-model"] = model

    request = urllib.request.Request(
        f"{gateway_url}/v1/chat/completions",
        data=json.dumps(request_body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    # The gateway is always loopback traffic; corporate HTTP(S)_PROXY env vars must not apply.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=600) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"openclaw gateway request failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"openclaw gateway request failed: {exc.reason}") from exc

    text = payload["choices"][0]["message"]["content"]
    return {"text": text, "raw": payload}


def build_task(*, agent: str, model: str | None, run_name: str, gateway_url: str, credential: str | None):
    def task(*, item: Any, **_: Any) -> str:
        message = extract_input_text(item.input)
        # Isolate each dataset item so previous answers cannot affect this run.
        session_key = f"agent:{agent}:experiment-{run_name}-{uuid.uuid4().hex[:8]}"
        outcome = run_openclaw_agent(
            message=message,
            agent=agent,
            session_key=session_key,
            model=model,
            gateway_url=gateway_url,
            credential=credential,
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

    metric_names = sorted(
        {
            name
            for run in comparison_runs
            for name in run.get("scores", {})
        }
    )
    item_count = max(
        len(values)
        for run in comparison_runs
        for values in run.get("scores", {}).values()
    )
    item_numbers = list(range(1, item_count + 1))
    figure, axes = plt.subplots(
        len(metric_names),
        1,
        figsize=(14, max(4 * len(metric_names), 6)),
        sharex=True,
        squeeze=False,
    )
    for axis, name in zip(axes.flat, metric_names):
        for run in comparison_runs:
            values = run.get("scores", {}).get(name)
            if values is None:
                continue
            run_items = list(range(1, len(values) + 1))
            label = f"{run['model']} - {run['run_name']}"
            axis.plot(run_items, values, marker="o", linewidth=2, label=label)
        axis.set_title(name, loc="left", fontweight="bold")
        axis.set_ylabel("Score")
        axis.set_ylim(-0.05, 1.05)
        axis.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
        axis.set_xticks(item_numbers)
        axis.grid(True, alpha=0.3)
        axis.legend(loc="upper left", bbox_to_anchor=(1.01, 1), fontsize=9)
    axes.flat[-1].set_xlabel("Dataset item")
    figure.suptitle("Evaluator score comparison by model", fontsize=16)
    figure.subplots_adjust(hspace=0.45, right=0.72, top=0.95)
    output_path = output_dir / "all_metrics.png"
    figure.savefig(output_path, dpi=180, bbox_inches="tight")
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
        help="OpenClaw config containing the langfuse-bridge keys and gateway settings",
    )
    parser.add_argument(
        "--gateway-url",
        default=None,
        help="Gateway base URL (default: derived from gateway.port in the OpenClaw config)",
    )
    parser.add_argument(
        "--gateway-token",
        default=None,
        help="Gateway auth token/password override (default: read from the OpenClaw config)",
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
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of times to repeat the dataset run (default: 1)",
    )
    parser.add_argument(
        "--iteration-delay-seconds",
        type=float,
        default=0.0,
        help="Seconds to wait between iterations",
    )
    args = parser.parse_args()

    if args.iterations < 1:
        parser.error("--iterations must be at least 1")

    langfuse_config = load_langfuse_config(args.config_path)
    # The SDK uses these config values to read the dataset and write run results.
    langfuse = Langfuse(
        public_key=langfuse_config["public_key"],
        secret_key=langfuse_config["secret_key"],
        host=langfuse_config["host"],
    )

    gateway_config = load_gateway_config(args.config_path)
    gateway_url = args.gateway_url or gateway_config["url"]
    gateway_credential = args.gateway_token or gateway_config["credential"]

    # The original dataset remains unchanged; outputs are stored in a dataset run.
    dataset = langfuse.get_dataset(args.dataset_name)
    if args.limit is not None:
        dataset.items = dataset.items[: args.limit]

    for iteration in range(1, args.iterations + 1):
        # Each iteration gets its own run name so Langfuse keeps them as separate dataset runs.
        run_name = args.run_name if args.iterations == 1 else f"{args.run_name}-{iteration}"
        if args.iterations > 1:
            print(f"\n=== Iteration {iteration}/{args.iterations}: {run_name} ===")

        task = build_task(
            agent=args.agent,
            model=args.model,
            run_name=run_name,
            gateway_url=gateway_url,
            credential=gateway_credential,
        )

        # Langfuse calls task once per item and associates its return value with that item.
        result = dataset.run_experiment(
            name=run_name,
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
        print(f"Langfuse results: {result.dataset_run_url}")

        if iteration < args.iterations and args.iteration_delay_seconds > 0:
            time.sleep(args.iteration_delay_seconds)


if __name__ == "__main__":
    main()
