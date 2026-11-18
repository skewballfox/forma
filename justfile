# Top-level recipes for the forma workspace. `just` lists them.
#
# A crate with tests that need root keeps its own justfile, loaded here as a
# module and run as `just <module>::<recipe>`. Its VM recipes come from
# crates/common.just; see that file for what a crate provides. The VM recipes below
# run the same recipe in every module listed in `vm_modules`.

set shell := ["bash", "-euo", "pipefail", "-c"]

mod user 'crates/user'
mod ledger 'crates/ledger'
mod privilege 'crates/privilege'
mod secureblue 'vm/secureblue'

# The modules with VM tests, in the order they run.
vm_modules := "user privilege ledger secureblue"

[private]
default:
    @just --list --unsorted

# Unit tests for every crate. These need no root; arguments go to cargo test
unit *args:
    cargo test --workspace {{ args }}

# The unit tests, then every module's VM tests if they pass. The VMs ask for run0 authentication
test: unit vm-test

# Clippy, pedantic, on everything including tests
lint:
    cargo clippy --workspace --all-targets -- -W clippy::pedantic

# Build every module's guest image under one run0 prompt (once, and when a crate's vm/ or vm/base changes)
vm-images:
    #!/usr/bin/env bash
    set -euo pipefail
    # Each module prints the root part of its vm-image without running it
    # (crates/common.just, vm-image-script); a module with no image prints nothing.
    # Every check that can fail as the user (MKOSI set) runs here, before the
    # prompt. Inside run0 the builds run in order and the first failure stops
    # the rest.
    scripts=()
    for module in {{ vm_modules }}; do
        script=$(just --justfile {{ quote(justfile()) }} "$module::vm-image-script")
        [[ -n "$script" ]] && scripts+=("$script")
    done
    (( ${#scripts[@]} )) || { echo "no module has an image to build" >&2; exit 0; }
    joined=${scripts[0]}
    for script in "${scripts[@]:1}"; do joined+=" && $script"; done
    run0 --via-shell "$joined"

# Run every module's VM tests, each in its own guest, under one run0 prompt; arguments filter by test name, --debug streams the guest's journal on its own unfiltered console
[arg('debug', long="debug", value="true")]
vm-test debug="false" *filter:
    #!/usr/bin/env bash
    set -euo pipefail
    # As the user: build each module's test binary, then stage its guest and
    # collect the root part of its run (crates/common.just, vm-test-binary and
    # vm-test-script). A module whose binary or staging fails is marked failed
    # and skipped; the others still run.
    failed=()
    staged=()
    scripts=()
    for module in {{ vm_modules }}; do
        echo "== $module: building" >&2
        if binary=$(just --justfile {{ quote(justfile()) }} "$module::vm-test-binary") \
            && script=$(just --justfile {{ quote(justfile()) }} "$module::vm-test-script" \
                "$binary" {{ debug }} {{ filter }}); then
            staged+=("$module")
            scripts+=("echo '== $module' >&2; $script")
        else
            failed+=("$module")
        fi
    done

    # One run0 for every guest. Joined with `;`, not `&&`, so every guest runs
    # even when one fails; each module's result is checked below.
    if (( ${#scripts[@]} )); then
        joined=${scripts[0]}
        for script in "${scripts[@]:1}"; do joined+=" ; $script"; done
        if ! run0 --via-shell "$joined"; then
            echo "run0 failed; no results are trusted" >&2
            failed+=("${staged[@]}")
            staged=()
        fi
    fi

    for module in "${staged[@]}"; do
        echo "== $module: result" >&2
        just --justfile {{ quote(justfile()) }} "$module::vm-test-result" || failed+=("$module")
    done
    if (( ${#failed[@]} )); then
        echo "VM tests failed in: ${failed[*]}" >&2
        exit 1
    fi

# Record where mkosi is, for every module's vm-image
vm-env:
    for module in {{ vm_modules }}; do just --justfile {{ quote(justfile()) }} "$module::vm-env"; done

# Spike 0(a): Podman accepts and enforces a signature forma wrote. No root; uses its own Podman storage
spike-0a:
    scripts/spike-0a.sh

# Everything: lint, unit tests, then the VM tests
check: lint test
