# rscan

Rust workspace for packet capture and packet parsing experiments.

## Workspace crates

- `rscan-core`: packet parsing primitives (Ethernet, IPv4/IPv6, TCP/UDP)
- `rscan-runtime`: capture loop and runtime wiring
- `rscan-cli`: command-line entry point

## Usage

```bash
cargo run -p rscan-cli -- sniff
