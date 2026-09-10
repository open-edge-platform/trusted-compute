# GPU/NPU Monitor

A lightweight, dependency-free sample dashboard that visualizes GPU and NPU
telemetry (utilization, frequency, power, temperature, memory bandwidth)
pushed by the guest telemetry agents.

The dashboard runs a small HTTP server that receives telemetry pushed by the
guest agents, exposes the latest values per host as JSON APIs, and serves a
self-contained web page that polls those APIs and renders live NPU and GPU
usage views for every reporting host.

## Usage

```bash
python3 server.py --host 0.0.0.0 --port 8080
```

Then open `http://<server>:8080/` in a browser.

### Configuring guest agents to push to this server

Point your guest telemetry agents at this server via the pod's Kata
hypervisor annotation:

```yaml
io.katacontainers.config.hypervisor.kernel_params: "push_host=<host_ip> push_port=8080 push_path=/metrics"
```

Hosts (or GPUs) that stop reporting for a short period are marked stale
(dimmed) in the dashboard, and are dropped entirely after a longer period of
inactivity.
