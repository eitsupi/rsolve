# rsolve

`rsolve` is experimental, pre-release, resolver-first infrastructure for R
package resolution. Its primary surface is a set of reusable libraries for
building a deterministic logical resolution from validated package metadata.

The top-level `rsolve` crate is a reference integration consumer. It composes
requests, projects lock and wire formats, orchestrates CRAN resolution, and
integrates with `pak`. Its binary is only a future CLI entry point: `main.rs`
currently performs no work, so it is a no-op and provides no user-facing CLI or
usable command interface yet.

## Crates

- `rsolve-core` — domain types and transport-neutral traits.
- `rsolve-resolver` — PubGrub-based logical dependency solving with injected
  candidate loading, preference, and lock-update policies.
- `rsolve-provider` — CRAN metadata and acquisition adapters.
- `rsolve-repository` — verified artifact caching and project-local CRAN-like
  repository materialization.
- `rsolve` — reference integration for composition, lock/wire handling, CRAN
  orchestration, and `pak` integration.

The resolver does not know about CRAN or HTTP, `pak`, cache or filesystem
materialization, manifest or lock schemas, or CLI implementation. It depends
only on injected boundaries such as `CandidateLoader`, `CandidatePreference`,
and `LockUpdatePolicy`.

The local CRAN-like repository is not a new distribution format. It is a
standard `PACKAGES`/file-repository boundary that passes the selected logical
resolution to standard R tooling.

## Non-goals

`rsolve` is not an R runtime manager. It does not discover, install, or switch
R runtimes, and it is not intended to become a generic multi-language tool
manager.

## Current status

The first vertical slice exists end to end in the libraries and their tests.
The public API, CLI, and product surface are experimental and are not yet
stable or complete.

## Quick validation

Run the synthetic, in-memory Matrix resolver example (the example itself does
not perform network access):

```sh
cargo run -p rsolve-resolver --example matrix
```

Run the repository validation suite:

```sh
sh scripts/check.sh
```

## Live CRAN example

The opt-in `cran_matrix` example performs network access when it runs. It
uses `https://cloud.r-project.org` by default and resolves Matrix for target R
versions `4.3.3` and `4.4.0` when no positional versions are supplied:

```sh
cargo run -p rsolve --example cran_matrix
```

Pass one or more target R versions after `--`:

```sh
cargo run -p rsolve --example cran_matrix -- 4.3.3 4.4.0
```

Override the mirror with `RSOLVE_CRAN_MIRROR`:

```sh
RSOLVE_CRAN_MIRROR=https://cran.rstudio.com \
  cargo run -p rsolve --example cran_matrix -- 4.4.0
```

The example is separate from the top-level binary, which is currently a
no-op. Results can change as the live CRAN catalog changes.

## License

rsolve is licensed under the [MIT License](LICENSE).
