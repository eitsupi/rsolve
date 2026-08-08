# Generate deterministic synthetic DCF fixtures.
# Provenance: R 4.6.1; generated from hand-constructed fictional records
# without network access, CRAN input, or tools::write_PACKAGES.

script_path <- sub("^--file=", "", commandArgs(trailingOnly = FALSE)[
    grep("^--file=", commandArgs(trailingOnly = FALSE))
])
setwd(dirname(normalizePath(script_path)))

stopifnot(getRversion() == "4.6.1")

write_fixture <- function(name, records) {
    bytes <- charToRaw(enc2utf8(paste0(records, collapse = "")))
    writeBin(bytes, name)
}

folded_suggests <- paste0(
    "Suggests: nrrfixture.suggest-00,\n ",
    paste(sprintf("nrrfixture.suggest-%02d", 1:24), collapse = ",\n ")
)

packages <- c(
    paste0(
        "Package: nrrfixture.core\n",
        "Version: 0.1.0\n",
        "Depends: R (>= 4.6.0), nrrfixture.base\n",
        "Imports: nrrfixture.import\n nrrfixture.import-helper\n",
        "LinkingTo: nrrfixture.link\n",
        "Suggests: nrrfixture.suggest\n",
        "Enhances: nrrfixture.enhance\n",
        "Priority: fixture-primary\n",
        "Path: synthetic/core\n",
        "OS_type: fixture-unix\n",
        "Archs: fixture-x86, fixture-arm\n",
        "License: NRR Fictional Terms Core\n",
        "License_is_FOSS: yes\n",
        "License_restricts_use: no\n",
        "MD5sum: 00000000000000000000000000000001\n",
        "NeedsCompilation: yes\n",
        "Published: 2026-06-24 19:14:59 UTC\n\n"
    ),
    paste0(
        "Package: nrrfixture.folded\n",
        "Version: 0.2.0\n",
        folded_suggests, "\n",
        "Description: UTF-8 fixture value: 日本語の説明 – café\n",
        "License: NRR Fictional Terms Folded\n",
        "MD5sum: 00000000000000000000000000000002\n",
        "NeedsCompilation: no\n",
        "Published: 2026-06-25 19:14:59 UTC\n\n"
    ),
    paste0(
        "Package: nrrfixture.rare\n",
        "Version: 1.0.0\n",
        "Priority: fixture-secondary\n",
        "Path: synthetic/rare\n",
        "OS_type: fixture-windows\n",
        "Archs: fixture-riscv, fixture-wasm\n",
        "License: NRR Fictional Terms Restricted\n",
        "License_is_FOSS: no\n",
        "License_restricts_use: yes\n",
        "MD5sum: 00000000000000000000000000000003\n",
        "NeedsCompilation: maybe\n",
        "Published: 2026-06-26 19:14:59 UTC\n\n"
    ),
    paste0(
        "Package: nrrfixture.plain\n",
        "Version: 3.0.0\n",
        "License: NRR Fictional Terms Plain\n",
        "MD5sum: 00000000000000000000000000000004\n",
        "NeedsCompilation: no\n",
        "Published: 2026-06-27 19:14:59 UTC\n\n"
    )
)

write_fixture("synthetic-PACKAGES", packages)

description <- paste0(
    "Package: nrrfixture.description\n",
    "Version: 0.4.0\n",
    "Title: A fictional single-record fixture\n",
    "Description: UTF-8 single record: 日本語とcafé\n",
    "Maintainer: Fixture Author <fixture@example.invalid>\n",
    "License: NRR Fictional Terms Description\n",
    "Encoding: UTF-8\n",
    "Published: 2026-06-28 19:14:59 UTC\n\n"
)
write_fixture("synthetic-DESCRIPTION", description)
