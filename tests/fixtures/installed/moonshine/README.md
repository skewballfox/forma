# Installed state fixture

This tree looks like a host after a root materia has installed the
`valid/moonshine` repository on host `forge`. Both components set
`User = "moonshine"`, so materia delegated them
(`docs/architecture.md` 2.4).

Tests point forma at three directories:

| Directory | Stands for | Default on a host |
|---|---|---|
| `data/` | `<materia_dir>/components` | `/var/lib/materia/components` |
| `quadlets/` | `quadlet_dir` | `/etc/containers/systemd` |
| `delegate/` | `executor.delegate_dir` | `/var/lib/materia/delegate` |

The files for `moonshine` and `nvidia-driver` were written by materia's own
code (`pkg/loader`, `pkg/repository`, `pkg/delegate` on the
`feat-delegated-components` branch), not by hand. Regenerate them when
`valid/moonshine` changes. The one exception: when the shared account moved to
the repository manifest, the `[Forma.Account]` and `[[Forma.Groups]]` tables
were removed by hand from `data/<component>/MANIFEST.toml`, which materia
copies unchanged from the component.

| Path | What it is |
|---|---|
| `data/<component>/` | The root-side record: `.component_version` (with `User`), the component's own `MANIFEST.toml` with its `[Forma]` tables, and the lifecycle scripts. |
| `quadlets/<component>/` | Only `.materia_managed`. Root materia installs no Quadlets for a delegated component. |
| `delegate/accounts/moonshine/` | The repository staged for the account's materia: every other file of both components, templates not rendered, and manifests without `[Forma]`, `User` or the lifecycle scripts. Forma reads Quadlets from here. |

On a real host `delegate/accounts/moonshine/` has mode `0750` and also holds
an `attributes/` directory. `delegate/state/` exists too; it is materia's own
and forma never reads it. The account's installed copy, under its home, is not
modelled: forma never reads it.

| Component | What it tests |
|---|---|
| `nvidia-driver`, `moonshine` | Fully installed and delegated to one shared account. |
| `half-installed` | Materia stopped part way: no `.component_version`. Forma skips and reports it. |
| `hand-made` | No `.materia_managed`: not a materia component. Forma ignores it. |
