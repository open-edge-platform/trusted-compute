# Test Agent

This directory contains utilities for evaluating an OpenClaw agent against a Langfuse dataset and uploading dataset records to Langfuse for benchmarking.

## Contents

- `setup_langfuse_openclaw_integration.sh` — sets up a local Langfuse stack, installs the Langfuse/OpenClaw plugin, and configures the OpenClaw CLI to talk to Langfuse.
- `upload_dataset_to_langfuse.py` — validates a dataset JSON file and uploads it to the configured Langfuse project.
- `run_openclaw_for_dataset.py` — runs each dataset item through the OpenClaw agent and records the result as a Langfuse dataset run.
- `requirements.txt` — Python dependencies for the dataset runner and uploader.

## Prerequisites

Before using these tools, make sure the following are available on the host:

- Python 3.10+
- `pip`
- OpenClaw CLI (`openclaw`)
- Docker and Docker Compose v2
- Node.js and `npm`
- Git
- `curl`
- `openssl`

The scripts read configuration from `~/.openclaw/openclaw.json`.

## Quick Start

1. Create and activate a Python virtual environment:

   ```bash
   cd tests/test-agent
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

2. Set up the local Langfuse + OpenClaw integration:

   ```bash
   ./setup_langfuse_openclaw_integration.sh
   ```

   This script will:
   - download the Langfuse Docker Compose configuration,
   - create a local Langfuse environment file,
   - deploy Langfuse,
   - install the OpenClaw Langfuse bridge plugin,
   - configure OpenClaw with the generated keys.

3. Prepare a dataset JSON file.

   Example dataset format:

   ```json
   {
     "name": "example-dataset",
     "description": "Simple evaluation set",
     "items": [
       {
         "input": "What is the capital of France?",
         "expectedOutput": "Paris"
       },
       {
         "input": "Summarize the benefits of containerization.",
         "expectedOutput": "Containerization improves portability, reproducibility, and isolation."
       }
     ]
   }
   ```

4. Upload the dataset to Langfuse:

   ```bash
   python upload_dataset_to_langfuse.py path/to/dataset.json
   ```

   Optional dry run support is available:

   ```bash
   python upload_dataset_to_langfuse.py path/to/dataset.json --dry-run
   ```

5. Run the agent against the dataset and save the results as a Langfuse run:

   ```bash
   python run_openclaw_for_dataset.py \
     --dataset-name example-dataset \
     --run-name openclaw-baseline \
     --agent main
   ```

   Optional model override:

   ```bash
   python run_openclaw_for_dataset.py \
     --dataset-name example-dataset \
     --run-name openclaw-baseline \
     --agent main \
     --model gpt-4o-mini
   ```

## Dataset upload behavior

`upload_dataset_to_langfuse.py` validates that:

- the dataset JSON contains a non-empty `name`,
- `items` is a non-empty list,
- each item has a non-empty `input`,
- each item has a non-empty `expectedOutput`,
- duplicate `input` values are rejected.

The script creates or reuses the Langfuse dataset entry and inserts each item with a stable generated identifier.

## Evaluation and score plotting

`run_openclaw_for_dataset.py` does the following:

- reads Langfuse credentials from the OpenClaw config,
- loads the dataset from Langfuse,
- sends each item input to the configured OpenClaw agent via the CLI,
- captures the model output,
- creates a dataset run in Langfuse,
- lets the configured Langfuse evaluator score the run automatically.

When `matplotlib` is installed, the runner also writes score comparison output under `score_plots/` by default:

- `all_metrics.png` contains the score graph,
- `all_metrics_data.json` stores the comparison data used to redraw the graph across runs.

Langfuse evaluator scores are persisted asynchronously after the dataset run item is created. This means the OpenClaw response may finish before the evaluator score is available through the Langfuse API. To avoid missing delayed scores in the printed output or graph, the runner polls Langfuse before plotting.

By default, the runner waits up to 180 seconds and checks every 2 seconds:

```bash
python run_openclaw_for_dataset.py \
  --dataset-name example-dataset \
  --run-name openclaw-baseline \
  --agent main
```

For slower evaluators or larger models, increase the wait time:

```bash
python run_openclaw_for_dataset.py \
  --dataset-name example-dataset \
  --run-name openclaw-baseline \
  --agent main \
  --score-wait-seconds 300 \
  --score-poll-seconds 5
```

If the timeout is reached, the runner still prints and plots the scores that were available. Items without a persisted score are printed as `Score: no persisted evaluation found` and appear as missing points in the graph data.

Useful run options:

- `--plot-dir`: change where score plots and comparison data are written,
- `--limit`: run only the first N dataset items,
- `--score-wait-seconds`: maximum time to wait for evaluator scores before plotting,
- `--score-poll-seconds`: delay between score polling attempts.

## Troubleshooting

- If `openclaw` commands fail, confirm the CLI is installed and the current user can access the OpenClaw config directory.
- If Langfuse setup fails, check Docker is running and that the required container services can start.
- If dataset upload fails, ensure the JSON file matches the expected structure and contains valid strings for `input` and `expectedOutput`.
- If the last dataset item prints `Score: no persisted evaluation found`, rerun with a larger `--score-wait-seconds` value. The evaluator may still be running when the plot is generated.
- If scoring does not appear in Langfuse after increasing the wait time, verify the bridge plugin is enabled and the project keys in `~/.openclaw/openclaw.json` match the deployed Langfuse project.

## Related references

- OpenClaw CLI and plugin configuration
- Local Langfuse deployment generated by `setup_langfuse_openclaw_integration.sh`
- Langfuse dataset-run evaluation workflow
