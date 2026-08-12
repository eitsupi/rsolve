# Closure fixture provenance

These three source archives are fictional packages authored for the repository
tests. They are generated only by `generate_fixture.R --update`, and test runs
use the checked-in bytes without rebuilding them. `--check` verifies every
archive against `SHA256SUMS` and never writes an archive.

The dependency closure is `root (LinkingTo: middle) -> middle (Imports: leaf)`;
all packages are version `0.1.0`. `middle` installs and calls `leaf`, and its
native source includes `inst/include/middle_marker.h`. `root` must include that
header while compiling.
