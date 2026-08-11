# Check or update deterministic synthetic DCF and archive-index fixtures.
# Provenance: R 4.6.1; generated from hand-constructed fictional records
# without network access, CRAN input, or tools::write_PACKAGES.

args <- commandArgs(trailingOnly = TRUE)
mode <- if (length(args) == 0L) "--check" else args[[1L]]
if (length(args) > 1L || !mode %in% c("--check", "--update")) {
    stop("use --check or --update")
}

script_path <- sub("^--file=", "", commandArgs(trailingOnly = FALSE)[
    grep("^--file=", commandArgs(trailingOnly = FALSE))
])
root <- dirname(normalizePath(script_path, mustWork = TRUE))

stopifnot(getRversion() == "4.6.1")

write_fixture <- function(name, records) {
    bytes <- charToRaw(enc2utf8(paste0(records, collapse = "")))
    target <- file.path(root, name)
    if (mode == "--update") {
        writeBin(bytes, target)
        return(invisible(NULL))
    }
    if (!file.exists(target)) {
        stop("fixture is missing: ", name, "; run --update")
    }
    expected <- readBin(target, what = "raw", n = file.info(target)$size)
    if (!identical(expected, bytes)) {
        stop("fixture differs: ", name, "; run --update")
    }
}

folded_suggests <- paste0(
    "Suggests: nrrfixture.suggest.00,\n ",
    paste(sprintf("nrrfixture.suggest.%02d", 1:24), collapse = ",\n ")
)

packages <- c(
    paste0(
        "Package: nrrfixture.core\n",
        "Version: 0.1.0\n",
        "Depends: R (>= 4.6.0), nrrfixture.base\n",
        "Imports: nrrfixture.import,\n nrrfixture.import.helper\n",
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

archive_columns <- c(
    "Version", "Package", "Priority", "MD5sum", "Depends", "Imports",
    "LinkingTo", "Suggests", "Enhances", "License", "License_is_FOSS",
    "License_restricts_use", "OS_type", "Archs", "NeedsCompilation"
)
archive <- matrix(
    NA_character_,
    nrow = 4L,
    ncol = length(archive_columns),
    dimnames = list(NULL, archive_columns)
)
set_archive_row <- function(row, values) {
    archive[row, names(values)] <<- unname(values)
}

set_archive_row(1L, c(
    Package = "nrrfixture.history",
    Version = "1.10.0",
    Depends = "R (>= 4.6.0), nrrfixture.base",
    Imports = paste0(
        "nrrfixture.import,\n  nrrfixture.import.helper,\n  ",
        "nrrfixture.import.extra"
    ),
    LinkingTo = "nrrfixture.link",
    Suggests = "nrrfixture.suggest",
    Enhances = "nrrfixture.enhance",
    License = "NRR Fictional Terms – Archive",
    License_is_FOSS = "yes",
    License_restricts_use = "no",
    MD5sum = "00000000000000000000000000000011",
    NeedsCompilation = "yes"
))
set_archive_row(2L, c(
    Package = "nrrfixture.history",
    Version = "0.3.0",
    License = "NRR Fictional Terms Older",
    License_is_FOSS = "yes",
    License_restricts_use = "no",
    MD5sum = "00000000000000000000000000000012",
    NeedsCompilation = "no"
))
set_archive_row(3L, c(
    Package = "nrrfixture.utf8",
    Version = "2.0.0",
    License = "NRR Fictional Terms 日本語",
    License_is_FOSS = "no",
    License_restricts_use = "yes",
    MD5sum = "00000000000000000000000000000013",
    NeedsCompilation = "no"
))
set_archive_row(4L, c(
    Package = "nrrfixture.broken",
    Version = "not-a-version",
    License = "NRR Fictional Terms Broken",
    MD5sum = "00000000000000000000000000000014"
))

archive_bytes <- function(value) {
    path <- tempfile("nrrfixture-archive-")
    saveRDS(value, path, compress = "gzip", version = 3L)
    bytes <- readBin(path, what = "raw", n = file.info(path)$size)
    unlink(path)
    # R's gzip writer records the current time in bytes 5:8 of the header.
    # The serialized payload and all other header fields are deterministic.
    bytes[5:8] <- as.raw(rep(0L, 4L))
    bytes
}

write_binary_fixture <- function(name, value) {
    bytes <- archive_bytes(value)
    decompressed <- memDecompress(bytes, type = "gzip")
    stopifnot(
        identical(bytes[seq_len(2L)], as.raw(c(0x1f, 0x8b))),
        identical(decompressed[seq_len(2L)], charToRaw("X\n")),
        identical(decompressed[3:6], as.raw(c(0, 0, 0, 3)))
    )
    target <- file.path(root, name)
    if (mode == "--update") {
        writeBin(bytes, target)
        return(invisible(NULL))
    }
    if (!file.exists(target)) {
        stop("fixture is missing: ", name, "; run --update")
    }
    expected <- readBin(target, what = "raw", n = file.info(target)$size)
    if (!identical(expected, bytes)) {
        stop("fixture differs: ", name, "; run --update")
    }
}

write_raw_fixture <- function(name, bytes) {
    target <- file.path(root, name)
    if (mode == "--update") {
        writeBin(bytes, target)
        return(invisible(NULL))
    }
    if (!file.exists(target)) {
        stop("fixture is missing: ", name, "; run --update")
    }
    expected <- readBin(target, what = "raw", n = file.info(target)$size)
    if (!identical(expected, bytes)) {
        stop("fixture differs: ", name, "; run --update")
    }
}

write_binary_fixture("synthetic-archive-PACKAGES.rds", archive)

matrix_archive <- matrix(
    NA_character_,
    nrow = 2L,
    ncol = length(archive_columns),
    dimnames = list(NULL, archive_columns)
)
set_matrix_archive_row <- function(row, values) {
    matrix_archive[row, names(values)] <<- unname(values)
}
set_matrix_archive_row(1L, c(
    Package = "Matrix",
    Version = "1.6-5",
    Depends = "R (>= 3.5.0)",
    Imports = "methods",
    License = "NRR Fictional Terms Matrix",
    MD5sum = "00000000000000000000000000000021",
    NeedsCompilation = "yes"
))
set_matrix_archive_row(2L, c(
    Package = "Matrix",
    Version = "1.7-0",
    Depends = "R (>= 4.4.0)",
    Imports = "methods",
    License = "NRR Fictional Terms Matrix",
    MD5sum = "00000000000000000000000000000022",
    NeedsCompilation = "yes"
))
write_binary_fixture("synthetic-matrix-archive-PACKAGES.rds", matrix_archive)
write_binary_fixture("synthetic-matrix-archive-wrong-root.rds", "wrong root")
write_binary_fixture(
    "synthetic-matrix-archive-missing-version.rds",
    matrix_archive[, setdiff(colnames(matrix_archive), "Version"), drop = FALSE]
)

tar_field <- function(value, width) {
    bytes <- charToRaw(enc2utf8(value))
    if (length(bytes) >= width) {
        stop("tar field is too long")
    }
    c(bytes, as.raw(rep(0L, width - length(bytes))))
}

octal_field <- function(value, width) {
    text <- sprintf("%0*o", width - 1L, as.integer(value))
    c(charToRaw(text), as.raw(0L))
}

tar_entry <- function(path, contents) {
    header <- as.raw(rep(0L, 512L))
    header[seq_along(tar_field(path, 100L))] <- tar_field(path, 100L)
    header[101:108] <- tar_field("0000644", 8L)
    header[109:116] <- tar_field("0000000", 8L)
    header[117:124] <- tar_field("0000000", 8L)
    header[125:136] <- octal_field(length(contents), 12L)
    header[137:148] <- octal_field(0L, 12L)
    header[149:156] <- as.raw(rep(32L, 8L))
    header[157] <- as.raw(charToRaw("0"))
    header[258:265] <- tar_field("ustar  ", 8L)
    checksum <- sum(as.integer(header))
    header[149:156] <- tar_field(sprintf("%06o ", checksum), 8L)
    padding <- (512L - (length(contents) %% 512L)) %% 512L
    c(header, contents, as.raw(rep(0L, padding)), as.raw(rep(0L, 1024L)))
}

matrix_tarball <- function(version, r_constraint) {
    description <- charToRaw(enc2utf8(paste0(
        "Package: Matrix\n",
        "Version: ", version, "\n",
        "Depends: R (", r_constraint, ")\n",
        "Imports: methods\n",
        "License: NRR Fictional Terms Matrix\n",
        "NeedsCompilation: yes\n\n"
    )))
    tar <- tar_entry("Matrix/DESCRIPTION", description)
    path <- tempfile("nrrfixture-tar-")
    connection <- gzfile(path, open = "wb")
    writeBin(tar, connection)
    close(connection)
    bytes <- readBin(path, what = "raw", n = file.info(path)$size)
    unlink(path)
    bytes[5:8] <- as.raw(rep(0L, 4L))
    bytes
}

matrix_old_tar <- matrix_tarball("1.6-5", ">= 3.5.0")
matrix_new_tar <- matrix_tarball("1.7-0", ">= 4.4.0")
write_raw_fixture("synthetic-Matrix_1.6-5.tar.gz", matrix_old_tar)
write_raw_fixture("synthetic-Matrix_1.7-0.tar.gz", matrix_new_tar)

archive_history <- list(
    Matrix = data.frame(
        size = c(length(matrix_old_tar), length(matrix_new_tar)),
        isdir = c(FALSE, FALSE),
        mode = c(420L, 420L),
        mtime = c(1790000000, 1790000001),
        ctime = c(1790000000, 1790000001),
        atime = c(1790000000, 1790000001),
        uid = c(1000L, 1000L),
        gid = c(1000L, 1000L),
        uname = c("fixture", "fixture"),
        grname = c("fixture", "fixture"),
        row.names = c(
            "src/contrib/Archive/Matrix/Matrix_1.6-5.tar.gz",
            "Matrix/Matrix_1.7-0.tar.gz"
        )
    )
)
write_binary_fixture("synthetic-meta-archive.rds", archive_history)

invalid_history <- function(path) {
    list(Matrix = data.frame(
        size = 1,
        isdir = FALSE,
        mode = 420L,
        mtime = 1790000000,
        ctime = 1790000000,
        atime = 1790000000,
        uid = 1000L,
        gid = 1000L,
        uname = "fixture",
        grname = "fixture",
        row.names = path
    ))
}

invalid_history_paths <- c(
    "synthetic-meta-invalid-traversal.rds" = "Matrix/../Matrix_1.6-5.tar.gz",
    "synthetic-meta-invalid-query.rds" = "Matrix/Matrix_1.6-5.tar.gz?download=1",
    "synthetic-meta-invalid-fragment.rds" = "Matrix/Matrix_1.6-5.tar.gz#fragment",
    "synthetic-meta-invalid-percent-traversal.rds" =
        "Matrix/%2e%2e%2fMatrix_1.6-5.tar.gz",
    "synthetic-meta-invalid-backslash.rds" = "Matrix\\Matrix_1.6-5.tar.gz",
    "synthetic-meta-invalid-package-mismatch.rds" = "Other/Matrix_1.6-5.tar.gz",
    "synthetic-meta-invalid-version.rds" = "Matrix/Matrix_latest.tar.gz"
)
for (name in names(invalid_history_paths)) {
    write_binary_fixture(name, invalid_history(invalid_history_paths[[name]]))
}

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

cat("Fixture", mode, "passed for CRAN DCF, archive RDS, history RDS, and source tarball fixtures.\n")
