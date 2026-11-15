#!/usr/bin/env bash
# Spike 0(a) of docs/architecture.md, as far as it goes without root and
# without a TPM: does Podman accept, and enforce, a sigstore-format signature
# that forma-signing-payload wrote into a dir: layout?
#
# Runs as a normal user. Uses its own Podman storage under a temporary
# directory, so it touches neither your images nor your policy.json.
# Needs podman and cargo. Run it with `just spike-0a`.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
# Unix sockets and overlay paths need a short directory.
work=$(mktemp -d /tmp/forma-spike-0a.XXXXXX)
trap 'podman --root "$work/build" --runroot "$work/run-build" rmi -af >/dev/null 2>&1 || true
      for store in "$work"/pull-*; do [ -d "$store" ] && podman unshare rm -rf "$store" 2>/dev/null || true; done
      podman unshare rm -rf "$work" 2>/dev/null || rm -rf "$work"' EXIT

reference=localhost/spike/hello:latest
failures=0

cargo build --quiet --manifest-path "$repo/Cargo.toml" -p forma-signing-payload --example sign_dir
sign=$(cargo metadata --quiet --manifest-path "$repo/Cargo.toml" --format-version 1 --no-deps |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')/debug/examples/sign_dir

mkdir "$work/context"
echo hello >"$work/context/hello"
printf 'FROM scratch\nCOPY hello /hello\n' >"$work/context/Containerfile"
echo '{"default":[{"type":"insecureAcceptAnything"}]}' >"$work/accept.json"
build=(podman --root "$work/build" --runroot "$work/run-build")
"${build[@]}" build --quiet --signature-policy "$work/accept.json" -t "$reference" "$work/context" >/dev/null
"${build[@]}" push --quiet --signature-policy "$work/accept.json" --format oci "$reference" "dir:$work/image"

cat >"$work/policy.json" <<POLICY
{"default": [{"type": "reject"}],
 "transports": {"dir": {"$work/image": [{
   "type": "sigstoreSigned",
   "keyPath": "$work/public.pem",
   "signedIdentity": {"type": "exactReference", "dockerReference": "$reference"}}]}}}
POLICY

# pull <name> <expected exit: 0 or 125> <what the case shows>
pull() {
    local status=0 output
    output=$(podman --root "$work/pull-$1" --runroot "$work/run-$1" pull --signature-policy "$work/policy.json" \
        "dir:$work/image" 2>&1) || status=$?
    if [ "$status" -eq "$2" ]; then
        echo "ok    $3"
    else
        echo "FAIL  $3 (exit $status, expected $2): $output"
        failures=$((failures + 1))
    fi
}

before=$(sha256sum "$work/image/manifest.json" | cut -d' ' -f1)

pull unsigned 125 "an unsigned image is rejected"

"$sign" "$work/image" "$reference" "$work/public.pem" >/dev/null
pull signed 0 "an image signed by forma-signing-payload is accepted"

stored=$(podman --root "$work/pull-signed" --runroot "$work/run-signed" image inspect --format '{{.Digest}}' "$reference" 2>/dev/null ||
    podman --root "$work/pull-signed" --runroot "$work/run-signed" image inspect --format '{{.Digest}}' \
        "$(podman --root "$work/pull-signed" --runroot "$work/run-signed" images -q | head -n1)")
if [ "$stored" = "sha256:$before" ]; then
    echo "ok    the manifest in containers-storage has the digest that was signed"
else
    echo "FAIL  the manifest digest changed: signed sha256:$before, stored $stored"
    failures=$((failures + 1))
fi

"$sign" "$work/image" localhost/spike/other:latest "$work/public.pem" >/dev/null
pull other-reference 125 "a signature for another reference is rejected"

"$sign" "$work/image" "$reference" "$work/public.pem" >/dev/null
python3 - "$work/image/signature-1" <<'PYTHON'
import base64, json, sys
from pathlib import Path

path = Path(sys.argv[1])
magic = b"\x00sigstore-json\n"
document = json.loads(path.read_bytes()[len(magic):])
payload = base64.b64decode(document["payload"]).replace(b"hello:latest", b"hello:latesu")
document["payload"] = base64.b64encode(payload).decode()
path.write_bytes(magic + json.dumps(document).encode())
PYTHON
pull changed-payload 125 "a payload changed after signing is rejected"

"$sign" "$work/image" "$reference" "$work/public.pem" >/dev/null
openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl ec -pubout 2>/dev/null >"$work/public.pem"
pull other-key 125 "a signature by a key the policy does not trust is rejected"

podman --version
if [ "$failures" -eq 0 ]; then
    echo "spike 0(a): all checks passed (software key; the TPM key is spike 0(b))"
else
    echo "spike 0(a): $failures check(s) failed"
    exit 1
fi
