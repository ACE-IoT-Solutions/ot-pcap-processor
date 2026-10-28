# Release checklist

The PyPI package is a platform wheel containing the Rust CLI plus a source distribution. The Rust library can also be published as the `ot-pcap-processor` crate. Versions in `Cargo.toml` and `pyproject.toml` stay synchronized because the Python version is read from Cargo metadata.

## Build from CI

The [Build and test workflow](../.github/workflows/build.yml) runs on pushes, pull requests, and manual dispatch. It tests Rust and Corona RDF output, builds Linux x86_64 and macOS arm64 wheels plus an sdist, installs each distribution into a clean environment, and compares its CLI, graph, Turtle, and OTLP output with the checked-in examples. A final job verifies the wheel metadata and sdist contents, then uploads a single `ot-pcap-processor-build` artifact containing all three distributions and `SHA256SUMS`.

To trigger and retrieve a build of `main`:

```sh
gh workflow run build.yml --repo ACE-IoT-Solutions/ot-pcap-processor --ref main
gh run list --repo ACE-IoT-Solutions/ot-pcap-processor --workflow build.yml --limit 3
# Substitute the successful run ID from the preceding command.
gh run download RUN_ID --repo ACE-IoT-Solutions/ot-pcap-processor \
  -n ot-pcap-processor-build -D ci-dist
(cd ci-dist && shasum -a 256 -c SHA256SUMS)
```

On Linux, `sha256sum -c SHA256SUMS` is an alternative to `shasum`. Install the wheel matching your platform with `uv tool install ./ci-dist/<wheel>` or `python -m pip install ./ci-dist/<wheel>` in a virtual environment. Install the sdist if no matching wheel is available; building the sdist requires Rust. CI artifacts are build outputs, not a PyPI release.

## Publish to PyPI

The [PyPI workflow](../.github/workflows/pypi-publish.yml) uses GitHub Actions OpenID Connect and PyPI Trusted Publishing. It rebuilds and tests the distributions through the reusable build workflow, verifies the checksums and release tag, then publishes the same verified wheels and sdist in a separate job. The publishing job uses the `pypi` GitHub environment and is triggered only by a **published GitHub Release**. A manual run builds and verifies the packages but skips the upload:

```sh
gh workflow run pypi-publish.yml --repo ACE-IoT-Solutions/ot-pcap-processor --ref main
```

For the first publication, add the pending Trusted Publisher on PyPI with these exact values:

| PyPI field | Value |
| --- | --- |
| Project name | `ot-pcap-processor` |
| Owner | `ACE-IoT-Solutions` |
| Repository | `ot-pcap-processor` |
| Workflow filename | `pypi-publish.yml` |
| Environment | `pypi` |

The GitHub `pypi` environment is configured to allow `v*` tags. PyPI requires the workflow filename and environment to match its publisher registration exactly. After the publisher is registered and the release artifacts are reviewed, create a `vX.Y.Z` tag matching `Cargo.toml` on the intended commit, push it, and publish a GitHub Release for that tag. The release event triggers the upload. The release workflow checks the tag against `Cargo.toml` and refuses a mismatch. A tag push by itself does not publish to PyPI.

## Release checklist

1. Update the version in `Cargo.toml`, update `Cargo.lock`, regenerate the checked-in output examples with `python3 scripts/generate_output_examples.py`, and review the README and release notes.
2. Run `cargo fmt --check`, `cargo test --locked`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo package --allow-dirty`. Confirm the CI job validates generated BACnet broadcast and Modbus gateway RDF with the upstream `corona-network-tool` and the undefined-term check. The final package command should be run without `--allow-dirty` from a clean release commit.
3. Build and inspect artifacts with `uv build`. Install the wheel in a clean environment with `uv tool install ./dist/<wheel>` and run `ot-pcap-processor --help`. Install the sdist in a clean virtual environment with `python -m pip install ./dist/<sdist>` and run the same smoke test.
4. Build platform wheels for the intended targets. Linux wheels must be built with a suitable manylinux target, such as the checked-in `PyO3/maturin-action` workflow. The checked-in CI builds Linux x86_64 and macOS arm64 wheels and uploads the combined artifact for inspection. Add architectures and operating systems that the release promises to support.
5. Register the PyPI Trusted Publisher above and run the manual staging workflow. Review its distributions and checksums, then publish the intended GitHub Release to authorize the PyPI upload. No PyPI API token is needed.
6. If the Rust crate is released, run `cargo publish --dry-run` and publish after reviewing the crate archive. The BACnet crates are registry dependencies, so the source distribution and Cargo package do not require a neighboring checkout.

No upload is performed by the build workflow or a manual run of the PyPI workflow. Check the project name on PyPI again immediately before registering the pending publisher because name availability can change.
