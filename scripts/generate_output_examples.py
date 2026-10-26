"""Regenerate the documented outputs from the mixed-protocol PCAP fixture."""

import argparse
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary", type=Path, default=ROOT / "target/debug/ot-pcap-processor"
    )
    parser.add_argument("--output-dir", type=Path, default=ROOT / "docs/examples")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"collector binary does not exist: {binary}")
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    capture = output_dir / "mixed-traffic.pcap"
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/generate_validation_capture.py"), str(capture)],
        check=True,
    )

    result = subprocess.run(
        [
            str(binary),
            "file",
            str(capture),
            "--graph",
            str(output_dir / "network.dot"),
            "--corona",
            str(output_dir / "network.ttl"),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    (output_dir / "summary.txt").write_text(result.stdout)

    received: dict[str, dict] = {}

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers["Content-Length"])
            received[self.path] = json.loads(self.rfile.read(length))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    with HTTPServer(("127.0.0.1", 0), Receiver) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            subprocess.run(
                [
                    str(binary),
                    "file",
                    str(capture),
                    "--otlp-endpoint",
                    f"http://127.0.0.1:{server.server_port}",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
        finally:
            server.shutdown()
            thread.join()

    if set(received) != {"/v1/logs", "/v1/metrics"}:
        raise RuntimeError(f"expected OTLP metrics and logs, got {sorted(received)}")

    logs = received["/v1/logs"]
    for resource in logs["resourceLogs"]:
        for scope in resource["scopeLogs"]:
            for record in scope["logRecords"]:
                record["observedTimeUnixNano"] = "1700000002000000000"

    metrics = received["/v1/metrics"]
    for resource in metrics["resourceMetrics"]:
        for scope in resource["scopeMetrics"]:
            for metric in scope["metrics"]:
                points = metric.get("sum", metric.get("gauge"))["dataPoints"]
                for point in points:
                    point["timeUnixNano"] = "1700000001000000000"
                    if "startTimeUnixNano" in point:
                        point["startTimeUnixNano"] = "1700000000000000000"

    (output_dir / "otlp-logs.json").write_text(json.dumps(logs, indent=2) + "\n")
    (output_dir / "otlp-metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print(f"Wrote output examples to {output_dir}")


if __name__ == "__main__":
    main()
