# Test fixtures

These files are test input for `forma-config` and `forma-plan`. They are
shaped like a materia repository, with `[Forma]` extension tables added.

- `valid/` holds repositories that forma must accept.
- `invalid/` holds repositories that forma must reject. Each directory has an
  `EXPECTED_ERROR` file that names the error the test expects.
- `host/` holds host-only configuration (`/etc/forma/config.toml`).
- `installed/` holds a host's state after materia has installed `valid/moonshine`.
  See its own README.

The build contexts and SELinux files here are placeholders. Tests only check
that forma finds them and copies them. Tests never build or install them.
