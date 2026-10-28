"""Require a GitHub release tag that matches the Cargo package version."""

import argparse
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="GitHub release tag, such as v0.1.0")
    args = parser.parse_args()

    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    version = cargo["package"]["version"]
    if project["project"]["name"] != "ot-pcap-processor":
        parser.error("PyPI project name is not ot-pcap-processor")
    if args.tag != f"v{version}":
        parser.error(f"release tag {args.tag!r} does not match package version v{version}")
    print(f"Release tag {args.tag} matches ot-pcap-processor {version}")


if __name__ == "__main__":
    main()
