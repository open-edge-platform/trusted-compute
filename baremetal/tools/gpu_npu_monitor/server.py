#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Minimal HTTP server for the GPU/NPU usage display sample.
#
# Accepts InfluxDB line-protocol metrics from both agents at a single common
# path, POST /metrics, and serves a self-contained dashboard at GET / that
# polls GET /api/npu and GET /api/gpu. The measurement name in each line
# decides where it's stored, so both agents can point push_path at the same
# /metrics endpoint.
#

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent / "static"
INDEX_HTML = STATIC_DIR / "index.html"

# Reject bodies larger than this to avoid a client exhausting server memory.
MAX_BODY_BYTES = 8 * 1024
# Hosts that haven't reported in this long are dropped from the dashboard.
STALE_AFTER_S = 300
# Bounds untrusted "host" tag values so a client can't inflate dict-key memory.
MAX_HOST_LEN = 128
# Same bound for "engine"/"type" tag values used as keys in per-GPU dicts.
MAX_TAG_LEN = 64
# Caps distinct engine/power keys per GPU so a client can't grow them unbounded.
MAX_KEYS_PER_GPU = 32

_lock = threading.Lock()
_npu_metrics: dict[str, dict] = {}  # host -> {field: value, "received_at": epoch_s}
# host -> gpu_id -> {"engines": {name: pct}, "power": {type: watts}, "frequency": mhz, "received_at": epoch_s}
_gpu_metrics: dict[str, dict] = {}

# Fields emitted by npu_reader.py; values ending in "i" are integers.
_INT_FIELDS = {"temperature", "tile_config", "utilization"}
_NPU_FIELDS = _INT_FIELDS | {"power", "frequency", "bandwidth", "memory_mb"}


def parse_line_protocol(line: str) -> tuple[str, dict, dict] | None:
    """Parse a single InfluxDB line-protocol point into (measurement, tags, fields).

    Expected shape (no spaces within tags/fields):
        measurement,tag1=a,tag2=b field1=1.0,field2=2i,... <ts_ns>
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split()
    if len(parts) < 2:
        return None
    measurement_and_tags, field_set = parts[0], parts[1]

    segments = measurement_and_tags.split(",")
    measurement = segments[0]
    if not measurement:
        return None
    tags = {}
    for seg in segments[1:]:
        if "=" not in seg:
            continue
        key, _, value = seg.partition("=")
        tags[key] = value

    fields = {}
    for kv in field_set.split(","):
        if "=" not in kv:
            continue
        key, _, value = kv.partition("=")
        if value.endswith("i"):
            value = value[:-1]
        try:
            v = float(value)
        except ValueError:
            continue
        if v != v or v in (float("inf"), float("-inf")):  # reject NaN/Infinity: not valid JSON
            continue
        fields[key] = v

    if not fields:
        return None
    return measurement, tags, fields


def _ingest_line(line: str, now: float) -> bool:
    """Parse and store one line-protocol point. Returns True if accepted."""
    parsed = parse_line_protocol(line)
    if parsed is None:
        return False
    measurement, tags, fields = parsed
    host = tags.get("host")
    if not host or len(host) > MAX_HOST_LEN:
        return False

    if measurement == "npu":
        fields = {k: v for k, v in fields.items() if k in _NPU_FIELDS}
        if not fields:
            return False
        entry = _npu_metrics.setdefault(host, {})
        entry.update(fields)
        entry["received_at"] = now
        return True

    if measurement in ("gpu_engine_usage", "gpu_frequency", "gpu_power"):
        gpu_id = tags.get("gpu_id", "0")
        if len(gpu_id) > MAX_HOST_LEN:
            return False
        gpu_entry = _gpu_metrics.setdefault(host, {}).setdefault(gpu_id, {"engines": {}, "power": {}})
        if measurement == "gpu_engine_usage" and "usage" in fields:
            engine = tags.get("engine", "unknown")
            if len(engine) > MAX_TAG_LEN:
                return False
            if engine not in gpu_entry["engines"] and len(gpu_entry["engines"]) >= MAX_KEYS_PER_GPU:
                return False
            gpu_entry["engines"][engine] = fields["usage"]
        elif measurement == "gpu_frequency" and "value" in fields:
            gpu_entry["frequency"] = fields["value"]
        elif measurement == "gpu_power" and "value" in fields:
            ptype = tags.get("type", "unknown")
            if len(ptype) > MAX_TAG_LEN:
                return False
            if ptype not in gpu_entry["power"] and len(gpu_entry["power"]) >= MAX_KEYS_PER_GPU:
                return False
            gpu_entry["power"][ptype] = fields["value"]
        else:
            return False
        gpu_entry["received_at"] = now
        return True

    return False


class Handler(BaseHTTPRequestHandler):
    server_version = "npu-usage-display/1.0"

    def log_message(self, fmt, *args):  # quieter default logging
        pass

    def _send_json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            try:
                body = INDEX_HTML.read_bytes()
            except OSError:
                self._send_json(500, {"error": "dashboard asset missing"})
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/npu":
            now = time.time()
            with _lock:
                stale_hosts = [h for h, m in _npu_metrics.items() if now - m["received_at"] > STALE_AFTER_S]
                for h in stale_hosts:
                    del _npu_metrics[h]
                snapshot = {
                    host: {**{k: v for k, v in m.items() if k != "received_at"},
                           "age_s": round(now - m["received_at"], 1)}
                    for host, m in _npu_metrics.items()
                }
            self._send_json(200, snapshot)
        elif self.path == "/api/gpu":
            now = time.time()
            with _lock:
                for host, gpus in list(_gpu_metrics.items()):
                    stale_ids = [g for g, m in gpus.items() if now - m["received_at"] > STALE_AFTER_S]
                    for g in stale_ids:
                        del gpus[g]
                    if not gpus:
                        del _gpu_metrics[host]
                snapshot = {
                    host: {
                        gpu_id: {**{k: v for k, v in m.items() if k != "received_at"},
                                 "age_s": round(now - m["received_at"], 1)}
                        for gpu_id, m in gpus.items()
                    }
                    for host, gpus in _gpu_metrics.items()
                }
            self._send_json(200, snapshot)
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        # A single common ingest path for both GPU and NPU agents: the
        # measurement name in each line (npu / gpu_engine_usage / gpu_frequency /
        # gpu_power) determines where it's stored, so both telemetry agents
        # point push_path at this same endpoint.
        if self.path != "/metrics":
            self._send_json(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            self._send_json(400, {"error": "invalid Content-Length"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(400, {"error": "invalid or oversized body"})
            return
        body = self.rfile.read(length).decode("utf-8", errors="replace")

        accepted = 0
        now = time.time()
        with _lock:
            for line in body.splitlines():
                if _ingest_line(line, now):
                    accepted += 1

        if accepted == 0:
            self._send_json(400, {"error": "no valid metric lines found"})
        else:
            self._send_json(200, {"accepted": accepted})


def main():
    parser = argparse.ArgumentParser(description="GPU/NPU usage display sample server")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="bind port (default: 8080)")
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"GPU/NPU usage display listening on http://{args.host}:{args.port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
