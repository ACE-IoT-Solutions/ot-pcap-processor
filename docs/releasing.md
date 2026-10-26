# Release checklist

The PyPI package is a platform wheel containing the Rust CLI plus a source distribution. The Rust library can also be published as the `ot-pcap-processor` crate. Versions in `Cargo.toml` and `pyproject.toml` stay synchronized because the Python version is read from Cargo metadata.

1. Update the version in `Cargo.toml`, update `Cargo.lock`, regenerate the checked-in output examples with `python3 scripts/generate_output_examples.py`, and review the README and release notes.
2. Run `cargo fmt --check`, `cargo test --locked`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo package --allow-dirty`. Confirm the CI job validates generated BACnet broadcast and Modbus gateway RDF with the upstream `corona-network-tool` and the undefined-term check. The final package command should be run without `--allow-dirty` from a clean release commit.
3. Build and inspect artifacts with `uv build`. Install the wheel in a clean environment with `uv tool install ./dist/<wheel>` and run `ot-pcap-processor --help`. Install the sdist in a clean virtual environment with `python -m pip install ./dist/<sdist>` and run the same smoke test.
4. Build platform wheels for the intended targets. Linux wheels must be built with a suitable manylinux target, such as the checked-in `PyO3/maturin-action` workflow. The checked-in CI builds Linux and macOS wheels and uploads them as artifacts for inspection. Add architectures and operating systems that the release promises to support.
5. Configure a PyPI Trusted Publisher for the GitHub repository and release workflow, or provide a PyPI token to the release operator. Once the artifacts and release tag are approved, publish with `uv publish dist/*`. Uploading to PyPI is a separate, irreversible release step.
6. If the Rust crate is released, run `cargo publish --dry-run` and publish after reviewing the crate archive. The BACnet crates are registry dependencies, so the source distribution and Cargo package do not require a neighboring checkout.

No upload is performed by the build and CI workflow. The project name should be checked on PyPI again immediately before the first upload because name availability can change.
