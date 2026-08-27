# tidyverse benchmark harness

`benchmark-tidyverse.py` is a thin consumer of the `rsolve` metrics boundary.
It runs a prebuilt release binary directly under the external `hyperfine`
binary. Build the release binary first, for example:

```sh
cargo build --release -p rsolve
```

The benchmark requires a release `rsolve` binary and `hyperfine` on `PATH`.
The default target is R 3.6.0 and the default mirror is public CRAN; use a
mirror without URL userinfo. Give
`--output-root` an absolute, empty directory (or omit it to receive a newly
created temporary directory):

```sh
python3 scripts/benchmark-tidyverse.py \
  --binary target/release/rsolve \
  --output-root /tmp/rsolve-tidyverse-benchmark
```

Cold trials use three runs with no warmup; each warm mode uses ten runs with
two warmups. Override these independently with `--r-version`, `--cold-runs`,
`--cold-warmup`, `--warm-runs`, and `--warm-warmup` when a different baseline
is required.

The four modes are isolated cold (an empty cache for every trial), fresh
online warm (the completed cold cache), offline warm (the same completed cold
cache), and projection-warm (a copy with only `current`,
`current-validation`, and `generations` removed while raw projections remain).
Cache preparation is outside the timed command; `hyperfine` invokes the
harness's capability-protected private prepare operation before every warmup
and timed trial. Every mode leaves a
`lock.toml`, `metrics.json`, and `hyperfine.json` under its output directory,
and the root contains a versioned `manifest.json`.

The manifest records schema version 1, binary and hyperfine versions, binary
SHA-256, safe uname system/release/version/machine/processor fields, CPU count, validated mirror URL, safe arguments,
relative artifact paths, timing statistics, lock SHA-256, provider counters,
fallback package count/package-local bytes, phase values, and cache decisions.
It does not record absolute cache paths or credentials. Reports must have
`metrics_overflow=false`; provider aggregate requests and bytes must agree
with their source counters, and all mode lock hashes must match. These are
consumer validation gates, while live timing values and fallback package
counts/bytes are recorded for comparison rather than used as regression
thresholds.

Historical baseline references include an earlier cold/fresh/offline run at
13.30s, 0.636s, and 0.338s, respectively, and a later
projection-inclusive run at 15.334s cold, 306.4ms fresh, 286.9ms offline, and
9.155s projection-warm. Their common old lock hash is historical only and is
not a live gate. Record live results in the project task tracker; benchmark
artifacts should not be committed to the repository. Peak RSS requires a
separate measurement and is not supplied by this harness.
