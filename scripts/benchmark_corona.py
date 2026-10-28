"""Compare end-to-end BACnet PCAP to Turtle processing with the Python collector."""

import argparse
import json
import platform
import statistics
import struct
import subprocess
import tempfile
import time
from pathlib import Path


PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}


def repeat_capture(source: Path, destination: Path, copies: int) -> int:
    content = source.read_bytes()
    if len(content) < 24 or content[:4] not in PCAP_MAGIC:
        raise ValueError("benchmark input must be a classic PCAP file")
    endian = PCAP_MAGIC[content[:4]]
    records = []
    offset = 24
    while offset < len(content):
        if len(content) - offset < 16:
            raise ValueError("truncated PCAP record header")
        seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", content, offset)
        offset += 16
        if len(content) - offset < captured:
            raise ValueError("truncated PCAP record data")
        records.append((seconds, fraction, captured, original, content[offset : offset + captured]))
        offset += captured
    if not records:
        raise ValueError("benchmark input has no packets")
    span = max(record[0] for record in records) - min(record[0] for record in records) + 1
    with destination.open("wb") as output:
        output.write(content[:24])
        for copy_index in range(copies):
            for seconds, fraction, captured, original, packet in records:
                shifted = seconds + copy_index * span
                if shifted > 0xFFFFFFFF:
                    raise ValueError("repeated PCAP timestamp exceeds 32 bits")
                output.write(struct.pack(endian + "IIII", shifted, fraction, captured, original))
                output.write(packet)
    return len(records) * copies


def run_once(command: list[str], working_directory: Path, output: Path) -> tuple[float, str]:
    start = time.perf_counter()
    result = subprocess.run(
        command,
        cwd=working_directory,
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed = time.perf_counter() - start
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed:\n{result.stdout}\n{result.stderr}")
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError(f"{command[0]} produced no Turtle output")
    return elapsed, result.stdout


def count_python_decoder_frames(python: Path, repo: Path, source: Path) -> int:
    result = subprocess.run(
        [
            str(python),
            "-c",
            "from bacpypes3.analysis import decode_file; import sys; print(sum(1 for _ in decode_file(sys.argv[1])))",
            str(source),
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return int(result.stdout.strip())


def compare_rdf(python: Path, repo: Path, rust_output: Path, python_output: Path) -> int:
    """Compare RDF triples, ignoring Turtle ordering and generated comments."""
    script = (
        "from rdflib import Graph; import sys; "
        "rust = Graph().parse(sys.argv[1]); old = Graph().parse(sys.argv[2]); "
        "missing = old - rust; extra = rust - old; "
        "print(f'Python triples: {len(old)}, Rust triples: {len(rust)}, missing: {len(missing)}, extra: {len(extra)}'); "
        "sys.exit(1 if missing or extra else 0)"
    )
    result = subprocess.run(
        [str(python), "-c", script, str(rust_output), str(python_output)],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"Corona compatibility RDF differs: {result.stdout}\n{result.stderr}")
    print(result.stdout.strip())
    return int(result.stdout.split("Python triples: ", 1)[1].split(",", 1)[0])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="BACnet-only classic PCAP")
    parser.add_argument("--python-repo", required=True, type=Path)
    parser.add_argument("--python-executable", type=Path)
    parser.add_argument("--rust-binary", type=Path, default=Path("target/release/ot-pcap-processor"))
    parser.add_argument("--capture-device", help="Include the same legacy capture-device RDF in both outputs")
    parser.add_argument("--repeat", type=int, default=10)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    if min(args.repeat, args.runs) < 1 or args.warmups < 0:
        parser.error("--repeat and --runs must be positive; --warmups cannot be negative")
    source = args.pcap.resolve()
    python_repo = args.python_repo.resolve()
    python = args.python_executable or python_repo / ".venv/bin/python"
    if not python.is_absolute():
        python = Path.cwd() / python
    rust = args.rust_binary.resolve()
    if not (source.is_file() and python.is_file() and rust.is_file()):
        parser.error("the input PCAP, Python executable, and Rust binary must exist")

    with tempfile.TemporaryDirectory(prefix="corona-benchmark-") as temporary:
        temporary = Path(temporary)
        capture = temporary / "repeated.pcap"
        frames = repeat_capture(source, capture, args.repeat)
        python_decoder_frames = count_python_decoder_frames(python, python_repo, source) * args.repeat
        outputs = {name: temporary / f"{name}.ttl" for name in ("rust", "python")}
        commands = {
            "rust": [str(rust), "file", str(capture), "--corona-compat", str(outputs["rust"])],
            "python": [
                str(python),
                "src/cli.py",
                str(capture),
                str(outputs["python"]),
                "--format",
                "ttl",
            ],
        }
        if args.capture_device:
            commands["rust"].extend(["--capture-device", args.capture_device])
            commands["python"].extend(["--capture-device", args.capture_device])
        directories = {"rust": Path.cwd(), "python": python_repo}
        times: dict[str, list[float]] = {"rust": [], "python": []}
        for _ in range(args.warmups):
            for name in ("rust", "python"):
                run_once(commands[name], directories[name], outputs[name])
        # Validate equivalent work before collecting timing samples. This
        # comparison happens outside the timed sections.
        for name in ("rust", "python"):
            run_once(commands[name], directories[name], outputs[name])
        matched_triples = compare_rdf(python, python_repo, outputs["rust"], outputs["python"])
        for round_number in range(args.runs):
            order = ("rust", "python") if round_number % 2 == 0 else ("python", "rust")
            for name in order:
                elapsed, output = run_once(commands[name], directories[name], outputs[name])
                if name == "rust" and f"Captured frames: {frames}" not in output:
                    raise RuntimeError("Rust collector did not report the expected frame count")
                times[name].append(elapsed)
        medians = {name: statistics.median(values) for name, values in times.items()}
        compare_rdf(python, python_repo, outputs["rust"], outputs["python"])
        result = {
            "platform": platform.platform(),
            "source_pcap": str(source),
            "frames": frames,
            "python_decoder_frames": python_decoder_frames,
            "input_bytes": capture.stat().st_size,
            "repeat": args.repeat,
            "runs": args.runs,
            "warmups": args.warmups,
            "seconds": times,
            "median_seconds": medians,
            "speedup": medians["python"] / medians["rust"],
            "matched_rdf_triples": matched_triples,
            "output_bytes": {name: output.stat().st_size for name, output in outputs.items()},
        }
        if args.json_out:
            args.json_out.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
