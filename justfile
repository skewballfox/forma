# Top-level recipes for the forma workspace. `just` lists them.
#
# The forma-user crate keeps its own recipes in crates/user/justfile, run as
# `just user::<recipe>`. The ones that matter most are forwarded below.

set shell := ["bash", "-euo", "pipefail", "-c"]

mod user 'crates/user'

[private]
default:
    @just --list --unsorted

# Unit tests for every crate. These need no root; the VM tests are `vm-test`.
test *args:
    cargo test --workspace {{ args }}

# Clippy, pedantic, on everything including tests
lint:
    cargo clippy --workspace --all-targets -- -W clippy::pedantic

# Build the guest image for the forma-user VM tests (once, and when crates/user/vm changes)
vm-image: user::vm-image

# Run the forma-user tests that need root in the VM; arguments filter by test name, --debug streams the guest's journal
[arg('debug', long="debug", value="true")]
vm-test debug="false" *filter:
    just user::vm-test {{ if debug == "true" { "--debug" } else { "" } }} {{ filter }}

# Record where mkosi is, for vm-image
vm-env: user::vm-env

# Spike 0(a): Podman accepts and enforces a signature forma wrote. No root; uses its own Podman storage
spike-0a:
    scripts/spike-0a.sh

# Everything: lint, unit tests, then the VM tests
check: lint test vm-test
