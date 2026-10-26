"""Verify the combined CI build and write SHA256SUMS for its distributions."""

import argparse
import hashlib
import tarfile
import tomllib
from email.parser import BytesParser
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]


def metadata_field(content: bytes, field: str) -> str:
    return BytesParser().parsebytes(content).get(field, "")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path)
    args = parser.parse_args()
    dist = args.dist
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 2 or len(sdists) != 1:
        parser.error(f"expected two wheels and one sdist, got {len(wheels)} and {len(sdists)}")
    if not any("manylinux" in path.name and "x86_64" in path.name for path in wheels):
        parser.error("Linux x86_64 manylinux wheel is missing")
    if not any("macosx" in path.name and "arm64" in path.name for path in wheels):
        parser.error("macOS arm64 wheel is missing")

    for wheel in wheels:
        with ZipFile(wheel) as archive:
            names = archive.namelist()
            scripts = [name for name in names if name.endswith(".data/scripts/ot-pcap-processor")]
            metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
            if len(scripts) != 1 or len(metadata) != 1:
                parser.error(f"wheel lacks CLI or metadata: {wheel.name}")
            if metadata_field(archive.read(metadata[0]), "Version") != version:
                parser.error(f"wheel version differs from Cargo.toml: {wheel.name}")

    with tarfile.open(sdists[0], "r:gz") as archive:
        names = archive.getnames()
        required = [
            "PKG-INFO",
            "Cargo.lock",
            "src/main.rs",
            "docs/outputs.md",
            "docs/examples/mixed-traffic.pcap",
        ]
        for suffix in required:
            if not any(name.endswith("/" + suffix) for name in names):
                parser.error(f"sdist lacks {suffix}")
        pkg_info = next(name for name in names if name.endswith("/PKG-INFO"))
        extracted = archive.extractfile(pkg_info)
        if extracted is None or metadata_field(extracted.read(), "Version") != version:
            parser.error("sdist version differs from Cargo.toml")

    distributions = sorted([*wheels, *sdists], key=lambda path: path.name)
    (dist / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in distributions
        )
    )
    print(f"Verified {len(distributions)} distributions for version {version}")


if __name__ == "__main__":
    main()
