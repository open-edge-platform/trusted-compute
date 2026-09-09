#!/usr/bin/env python3
"""Upload a JSON dataset file to the configured Langfuse instance."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


CONFIG_PATH = Path.home() / ".openclaw" / "openclaw.json"


def request_json(base_url: str, auth: str, path: str, payload: dict[str, Any]) -> Any:
	request = urllib.request.Request(
		base_url.rstrip("/") + path,
		data=json.dumps(payload).encode(),
		headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
		method="POST",
	)
	with urllib.request.urlopen(request, timeout=30) as response:
		return json.load(response)


def load_dataset(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
	dataset = json.loads(path.read_text())
	name = dataset["name"]
	source_items = dataset["items"]
	if not isinstance(name, str) or not name.strip():
		raise ValueError("dataset name must be a non-empty string")
	if not isinstance(source_items, list) or not source_items:
		raise ValueError("dataset items must be a non-empty list")

	items = []
	seen_inputs = set()
	for index, source_item in enumerate(source_items, start=1):
		if not isinstance(source_item, dict):
			raise ValueError(f"item {index} must be an object")
		question = source_item.get("input")
		expected_output = source_item.get("expectedOutput")
		if not isinstance(question, str) or not question.strip():
			raise ValueError(f"item {index} input must be a non-empty string")
		if not isinstance(expected_output, str) or not expected_output.strip():
			raise ValueError(f"item {index} expectedOutput must be a non-empty string")
		if question in seen_inputs:
			raise ValueError(f"duplicate item input: {question}")
		seen_inputs.add(question)
		items.append(
			{
				**source_item,
				"id": source_item.get("id")
				or str(uuid.uuid5(uuid.NAMESPACE_URL, f"{name}:{question}")),
				"datasetName": name,
			}
		)
	return dataset, items


def main() -> int:
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"dataset_file",
		type=Path,
		help="dataset JSON file to upload",
	)
	parser.add_argument("--dry-run", action="store_true", help="validate and print the payload summary")
	args = parser.parse_args()
	dataset, items = load_dataset(args.dataset_file)
	dataset_name = dataset["name"]

	if args.dry_run:
		print(f"Dataset: {dataset_name}")
		print(f"Source file: {args.dataset_file}")
		print(f"Items: {len(items)}")
		print(f"Unique IDs: {len({item['id'] for item in items})}")
		return 0

	config = json.loads(CONFIG_PATH.read_text())
	langfuse = config["plugins"]["entries"]["langfuse-bridge"]["config"]
	auth = base64.b64encode(
		f"{langfuse['publicKey']}:{langfuse['secretKey']}".encode()
	).decode()

	try:
		request_json(
			langfuse["baseUrl"],
			auth,
			"/api/public/v2/datasets",
			{
				"name": dataset_name,
				"description": dataset.get("description"),
				"metadata": dataset.get("metadata"),
			},
		)
	except urllib.error.HTTPError as error:
		if error.code != 409:
			raise

	for item in items:
		request_json(langfuse["baseUrl"], auth, "/api/public/dataset-items", item)

	print(
		f"Uploaded {len(items)} items from '{args.dataset_file}' "
		f"to Langfuse dataset '{dataset_name}'."
	)
	return 0


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except (KeyError, OSError, TypeError, ValueError, urllib.error.URLError) as error:
		print(f"Dataset upload failed: {error}", file=sys.stderr)
		raise SystemExit(1)
