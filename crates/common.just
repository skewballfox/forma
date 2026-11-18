# Recipes shared by every crate that has tests needing root. Those tests run
# in a VM, never on the host. A crate imports this file from its own
# justfile, and the workspace justfile loads that as a module:
#
#   # crates/<crate>/justfile
#   set shell := ["bash", "-euo", "pipefail", "-c"]
#   set dotenv-load                  # vm-env writes .env; vm-image reads MKOSI from it
#   set allow-duplicate-variables    # so the crate can override a default below
#   set allow-duplicate-recipes      # so the crate can replace a recipe below
#   import '../common.just'
#   vm_image_id := "forma-<crate>-test"
#
# and in the workspace justfile, `mod <crate> 'crates/<crate>'`, with the
# module's name added to `vm_modules`.
#
# What the crate provides:
#
# | Path or variable | What it is |
# |---|---|
# | `vm_image_id` (required) | The mkosi `ImageId` and `Output` of its guest. |
# | `vm/mkosi.conf` | Its guest: `Include=../../../vm/base`, then its own Output, packages and files. |
# | `vm/mkosi.extra/etc/<marker>` | A file the tests check for before they change anything. |
# | `tests/<vm_test_target>.rs` or `tests/<vm_test_target>/main.rs` | The tests, each `#[ignore]`d so `cargo test` skips them. Default target: `vm`. |
# | `vm_prepare` (optional) | Run as root after the build, before the image is handed to the user. |
# | `vm_binary` (instead of the above) | An executable to run in the guest, for a guest with no crate behind it (vm/secureblue). |
# | `vm-test-extra` recipe (optional) | Prints paths, one per line, to stage beside the binary: the guest sees each at `/mnt/forma-test/extra/<name>`. |
#
# The crate's definitions win over the defaults here (allow-duplicate-*), for
# example `timeout := "1800"` for slow tests.
#
# Host packages (Fedora names): mkosi builds the image, distribution-gpg-keys
# lets it verify Fedora's packages, and python3-pefile is what it uses to
# install systemd-boot. mtools (mcopy) and dosfstools fill and format the FAT
# EFI System Partition without mounting it. Also needed: systemd-vmspawn
# (systemd-container), jq.
# On an image-based host: rpm-ostree install mkosi distribution-gpg-keys python3-pefile mtools dosfstools

# The crate: the directory of the justfile that imports this one.
crate := module_directory()
vm := crate / "vm"
image := env("FORMA_VM_IMAGE", vm / "mkosi.output" / (vm_image_id + ".raw"))
run := vm / "run"

# The test target cargo builds for the guest.
vm_test_target := "vm"

# An executable vm-image runs as root right after the build, with the image,
# the timeout and vmspawn as arguments, for an image that must boot once
# before it is used (vm/secureblue/label-image). Empty: none.
vm_prepare := ""

# An executable the guest runs in place of a cargo test binary, for a guest
# with no crate behind it. Empty: build `vm_test_target` with cargo.
vm_binary := ""

# The part of a run that needs root, shared by every crate.
launch := parent_directory(source_directory()) / "vm" / "launch"

# Where mkosi is, from the crate's `.env`: run0 does not see the user's PATH.
# Empty until `vm-env` has run; `vm-image` checks.
mkosi := env("MKOSI", "")

# What starts the guest. Tests of this file replace it, and the image.
vmspawn := env("FORMA_VMSPAWN", "systemd-vmspawn")

# How long the guest may run before it is killed, in seconds.
timeout := env("FORMA_VM_TIMEOUT", "900")

# mkosi needs root to build the image: it works in a user namespace, and
# secureblue's SELinux policy refuses those to unconfined users. The image is
# root-owned and readable by wheel; `vm-test` copies it and runs only the VM as root.

# Record where mkosi is, so run0 can find it
vm-env:
    #!/usr/bin/env bash
    set -euo pipefail
    mkosi=$(command -v mkosi) || { echo "mkosi is not on PATH" >&2; exit 1; }
    printf 'MKOSI=%s\n' "$mkosi" > {{ quote(crate / ".env") }}

# Build this crate's guest image (once, and when its vm/ or the shared vm/base changes)
vm-image:
    #!/usr/bin/env bash
    set -euo pipefail
    script=$(just --justfile {{ quote(crate / "justfile") }} --working-directory {{ quote(crate) }} vm-image-script)
    [[ -n "$script" ]] || exit 0
    run0 --via-shell "$script"

# Prints the part of vm-image that runs as root, as one string for `run0
# --via-shell`, and runs nothing itself. Prints nothing for a crate with no
# image of its own. The workspace's vm-images joins these with && so every
# image builds under one run0.
#
# mkosi makes the output directory 750 and the image 640, both root's; vm-test
# reads the image as the user, so hand the group to wheel. Not world-readable.
# --via-shell joins its arguments unquoted, so each command is quoted with
# printf %q and the lot goes in as one string.
[private]
vm-image-script:
    #!/usr/bin/env bash
    set -euo pipefail
    mkosi={{ quote(mkosi) }}
    [[ -n "$mkosi" ]] || { echo "MKOSI is not set for {{ crate }}; run: just vm-env" >&2; exit 1; }
    dir={{ quote(parent_directory(image)) }}
    script=$(printf '%q ' "$mkosi" --directory {{ quote(vm) }} --force build; printf '&& ')
    prepare={{ quote(vm_prepare) }}
    [[ -n "$prepare" ]] && script+=$(printf '%q ' "$prepare" {{ quote(image) }} {{ timeout }} {{ vmspawn }}; printf '&& ')
    script+=$(printf '%q ' chgrp wheel "$dir" {{ quote(image) }}; printf '&& ')
    script+=$(printf '%q ' chmod 750 "$dir"; printf '&& ')
    script+=$(printf '%q ' chmod 640 {{ quote(image) }}; printf '&& ')
    script+=$(printf '%q ' echo built {{ quote(image) }})
    printf '%s\n' "$script"

# Files and directories the guest needs besides the test binary, such as
# another program or test fixtures: their paths, one per line, on standard
# output (build output on standard error). vm-test-script copies each into
# the share's `extra/` directory. A module replaces this recipe; by default
# there are none.
[private]
vm-test-extra:
    @true

# The module's vm-test is split in three so the workspace's vm-test can build
# every module's binary, stage every guest, and then run all the guests under
# one run0 prompt before checking each result: vm-test-binary and
# vm-test-script run as the user, and only the command vm-test-script prints
# needs root. A module's own vm-test runs the same three steps for itself.
#
# Everything after the recipe name is passed to the test binary as a filter.

# Run this crate's VM tests in a fresh copy of its guest image; --debug also streams the guest's journal on its own unfiltered console
[arg('debug', long="debug", value="true")]
vm-test debug="false" *filter:
    #!/usr/bin/env bash
    set -euo pipefail
    just_=(just --justfile {{ quote(crate / "justfile") }} --working-directory {{ quote(crate) }})
    binary=$("${just_[@]}" vm-test-binary)
    script=$("${just_[@]}" vm-test-script "$binary" {{ debug }} {{ filter }})
    run0 --via-shell "$script"
    "${just_[@]}" vm-test-result

# Build this crate's test binary for the guest and print its path (or vm_binary, when set)
vm-test-binary:
    #!/usr/bin/env bash
    set -euo pipefail
    # Found by asking cargo rather than guessing a path. cargo's progress goes
    # to stderr; stdout is the path alone.
    binary={{ quote(vm_binary) }}
    if [[ -z "$binary" ]]; then
        binary=$(cargo test --manifest-path {{ quote(crate / "Cargo.toml") }} --test {{ quote(vm_test_target) }} --no-run \
            --message-format=json-render-diagnostics \
            | jq -r --arg target {{ quote(vm_test_target) }} \
                'select(.reason == "compiler-artifact" and .profile.test == true and .target.name == $target) | .executable' \
            | tail -n 1)
    fi
    [[ -x "$binary" ]] || { echo "no test binary to run: $binary" >&2; exit 1; }
    printf '%s\n' "$binary"

# Stages BINARY, the filter and the debug flag for this crate's guest, as the
# user, so cargo's output never needs root. Then prints the part of vm-test
# that runs as root, as one string for `run0 --via-shell`, and runs nothing as
# root itself. The workspace's vm-test joins these so every guest runs under
# one run0.
#
# The printed command (vm/launch) runs the guest on a fresh copy of the image;
# the guest runs the binary, writes `exit-status` and `output` into `out`, and
# powers off. vm-test-result reads them. run0 --via-shell joins its arguments
# with spaces and hands them to the login shell unquoted, so the command is ONE
# string with the quoting already done (as corectl's common.just does).
[private]
vm-test-script binary debug="false" *filter:
    #!/usr/bin/env bash
    set -euo pipefail
    [[ -f {{ quote(image) }} ]] || { echo "no image at {{ image }}; run: just vm-images" >&2; exit 1; }
    binary={{ quote(binary) }}
    [[ -x "$binary" ]] || { echo "no test binary to run: $binary" >&2; exit 1; }

    stage={{ quote(run + ".new") }}
    rm -rf "$stage"
    mkdir -p "$stage"
    cp --reflink=auto "$binary" "$stage/vm-tests"
    extra=$(just --justfile {{ quote(crate / "justfile") }} --working-directory {{ quote(crate) }} vm-test-extra)
    if [[ -n "$extra" ]]; then
        mkdir "$stage/extra"
        while IFS= read -r path; do
            [[ -e "$path" ]] || { echo "no file to stage at $path" >&2; exit 1; }
            cp -r --reflink=auto -- "$path" "$stage/extra/"
        done <<<"$extra"
    fi
    printf '%s\n' {{ filter }} > "$stage/args"
    # The guest streams its journal to the console when this file is there.
    [[ {{ debug }} == true ]] && touch "$stage/debug"

    printf '%q ' {{ quote(launch) }} \
        {{ quote(run) }} "$stage" {{ quote(image) }} "$(id -u):$(id -g)" {{ timeout }} {{ vmspawn }}
    printf '\n'

# Fails unless this crate's last guest reported that its tests passed
[private]
vm-test-result:
    #!/usr/bin/env bash
    set -euo pipefail
    [[ -f {{ quote(run / "out" / "exit-status") }} ]] || { echo "the guest never reported a result" >&2; exit 1; }
    status=$(<{{ quote(run / "out" / "exit-status") }})
    [[ "$status" == 0 ]] || { echo "tests failed in the VM (exit status $status)" >&2; exit 1; }
