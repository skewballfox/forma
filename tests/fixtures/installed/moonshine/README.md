# Installed state fixture

This tree looks like a host after materia has installed the `valid/moonshine`
repository. Tests point forma's `quadlet_dir` at `quadlets/`,
`materia_dir/components` at `data/`, and the user-unit directory at
`services/`. Under materia option S, `services/` stands for
`/etc/systemd/user/` (`docs/proposed_materia_changes.md`, F12). Its
`ConditionUser=` drop-ins are not modelled here.

| Directory | What it tests |
|---|---|
| `nvidia-driver`, `moonshine` | Fully installed: `.materia_managed` and `.component_version` both exist. |
| `half-installed` | Materia stopped part way: no `.component_version`. Forma skips and reports it. |
| `hand-made` | No `.materia_managed`: not a materia component. Forma ignores it. |
