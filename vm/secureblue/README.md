# A test guest with secureblue's SELinux policy

Forma's notes depend on some properties of secureblue that a plain Fedora
guest does not have. This guest is Fedora 44 with those properties added, in
the way secureblue's own image build adds them. It boots under
`systemd-vmspawn` like the other test guests (`vm/base`).

```
just secureblue::vm-image   # build it: needs run0 and the network
just secureblue::vm-test    # boot it and run ./check
just secureblue::compare    # diff its user-namespace rules with this host's
```

## What it has

| Property | Where forma relies on it | How the guest gets it |
|---|---|---|
| Only some domains may create a user namespace; `unconfined_t` may not | Architecture 5.6 (the builder), spikes 0(c) and 0(g), `service-account-limits.md` | secureblue's `harden_userns.cil`, enabled |
| Container domains may create one (rootless Podman and buildah work) | Every container check | `harden_container_userns.cil` installed and disabled, as `ujust set-container-userns on` leaves it |
| Role transitions out of `unconfined_r` are constrained | A candidate cause of the failed build from `run0` (spike 0(c)); not yet shown | The `constrain` rules in `harden_userns.cil` |
| `deny_ptrace` on, `container_allow_ptrace` off | `service-account-limits.md` 3 | `setsebool -P`, as secureblue's `set-selinux-booleans.sh` |
| The other secureblue modules (sockets, ptrace, flatpak, stdmalloc) | Nothing directly; installed so the policy is the same | `semodule -X 300 -i`, as secureblue's `installselinuxpolicies.sh` |
| SELinux enforcing, every file labelled | All of the above | Labelled by the image itself on one permissive boot after the build (below); enforcing on every boot after that |
| secureblue's patched `bubblewrap` and `bubblewrap-selinux` | `flatpakfull.te` calls their `bubblewrap_role` | secureblue's COPR (`mkosi.sandbox/`), with the key secureblue ships |

`mkosi.postinst.chroot` follows secureblue's two scripts step by step and says
where it differs.

## Why the image labels itself

The first build failed at mkosi's relabel, on this host:

```
/usr/bin/setfiles: Could not set context for /buildroot/usr/bin/podman:  Permission denied
```

for `crun`, `bwrap`, `podman`, `buildah` and `passt` (and `passt.avx2`) as well: exactly
the files whose types are in the module's `userns_privileged_file_type`.
`pasta` (`pasta_exec_t`, not in that set) was labelled without complaint. The cause is
secureblue's `userns_deny_unconfined_relabels.cil`, one of the
modules this guest installs: it lets only `init_t` and `kernel_t` (and
`install_t`) give a file a type that may create user namespaces
(`container_runtime_exec_t`, `bubblewrap_exec_t`, `passt_exec_t`, ...). mkosi
runs `setfiles` as root in `unconfined_t`, so the host refuses it. That is
the property working, seen from the build side.

So mkosi does not label (`SELinuxRelabel=no`). `mkosi.postinst.chroot` sets
the guest permissive and leaves `/.forma-relabel`. `vm-image` then boots the
image once, in place and with nothing shared from the host (`label-image`).
`forma-relabel.service` labels the root file system with the guest's own
policy under the guest's kernel, sets `SELINUX=enforcing`, and powers off.
A failure powers it off at once. `label-image` then reads
`/etc/selinux/config` back out of the image (`systemd-dissect`) and fails the
build unless it says enforcing, which forma-relabel writes only after
`restorecon` has succeeded. `./check`
confirms the labels and the enforcing mode on each test boot.

## What it lacks

- **The secureblue kernel and its kernel arguments, sysctls and module
  blacklists.** None of forma's checks depends on them so far. Add them
  here if one does.
- **rpm-ostree and a read-only `/usr`.** The guest is a normal, writable
  Fedora system.
- **`hardened_malloc`, `run0edit`, secureblue's `ujust` commands and
  services.**
- **Local modules a host adds.** The development host also has moonshine's
  modules and the NVIDIA image's `nvidia_container_t`, so
  `just secureblue::compare` shows those types on the host side only.

## How it was checked

Before any image was built, `mkosi.postinst.chroot` was run in a rootless
`registry.fedoraproject.org/fedora:44` container (2026-11-18,
`selinux-policy-targeted-44.11`, `container-selinux-2.251.0`,
`bubblewrap-selinux-1.0.10`), with `SELINUX_SOURCES` pointing at
`selinux/`. Every module compiled and installed. The source types that may
create a user namespace were then the same as on the development host
(secureblue 45.20261030.2.1, securecore), less the host's local modules
listed above. On that host, `./check` passed every line that does not need
root; the module lines read `semodule -lfull`, which does. Booleans in the
container: `deny_ptrace` on, `container_allow_ptrace` off, and
`user_t_run_containers` off, which is Fedora's default (secureblue does not
set it; the host has it off too).

To replay it, with the packages from `mkosi.conf` installed and the COPR from
`mkosi.sandbox/` enabled in the container:

```
SELINUX_SOURCES=/src/selinux /src/mkosi.postinst.chroot
```

The image has not been booted yet: `just secureblue::vm-test` is the first
run of `./check` in it.

## Why not secureblue's own image

secureblue's server image (`ghcr.io/secureblue/securecore-main-hardened`) is
a Fedora CoreOS image: an OCI container for rpm-ostree, several gigabytes.
mkosi cannot build from it. Turning it into a disk would need `bootc install
to-disk` run in privileged, rootful Podman, then a way to put the test runner
on an ostree system. That is possible, but heavy, and every secureblue
update would change the guest under the tests. This guest pins what forma
depends on, from sources that can be read.

## The sources

`selinux/` is a copy of secureblue's `files/scripts/selinux/` at commit
`e49163b96cda11ea9a50b3fda25d56978d91dd47` (2026-11-17), from
<https://github.com/secureblue/secureblue>. Each file keeps its SPDX header
(`Apache-2.0 OR MIT`, one `MIT`); `selinux/LICENSES/` holds both licences.
`nvidia-container/` is copied too, though secureblue's script does not
install it on this kind of image, and neither does this guest.

To update, copy that directory from a newer commit, change the commit here,
and compare `cil_policy_modules` and `policy_modules` in their
`installselinuxpolicies.sh` with `mkosi.postinst.chroot`.
