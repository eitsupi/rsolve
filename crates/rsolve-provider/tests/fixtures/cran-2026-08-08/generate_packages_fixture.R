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
    "Suggests: rsolvefixture.suggest.00,\n ",
    paste(sprintf("rsolvefixture.suggest.%02d", 1:24), collapse = ",\n ")
)

packages <- c(
    paste0(
        "Package: rsolvefixture.core\n",
        "Version: 0.1.0\n",
        "Depends: R (>= 4.6.0), rsolvefixture.base\n",
        "Imports: rsolvefixture.import,\n rsolvefixture.import.helper\n",
        "LinkingTo: rsolvefixture.link\n",
        "Suggests: rsolvefixture.suggest\n",
        "Enhances: rsolvefixture.enhance\n",
        "Priority: fixture-primary\n",
        "Repository: synthetic/core\n",
        "OS_type: fixture-unix\n",
        "Archs: fixture-x86, fixture-arm\n",
        "License: RSOLVE Fictional Terms Core\n",
        "License_is_FOSS: yes\n",
        "License_restricts_use: no\n",
        "MD5sum: 00000000000000000000000000000001\n",
        "NeedsCompilation: yes\n",
        "Published: 2026-06-24 19:14:59 UTC\n\n"
    ),
    paste0(
        "Package: rsolvefixture.folded\n",
        "Version: 0.2.0\n",
        folded_suggests, "\n",
        "Description: UTF-8 fixture value: 日本語の説明 – café\n",
        "License: RSOLVE Fictional Terms Folded\n",
        "MD5sum: 00000000000000000000000000000002\n",
        "NeedsCompilation: no\n",
        "Published: 2026-06-25 19:14:59 UTC\n\n"
    ),
    paste0(
        "Package: rsolvefixture.rare\n",
        "Version: 1.0.0\n",
        "Priority: fixture-secondary\n",
        "Repository: synthetic/rare\n",
        "OS_type: fixture-windows\n",
        "Archs: fixture-riscv, fixture-wasm\n",
        "License: RSOLVE Fictional Terms Restricted\n",
        "License_is_FOSS: no\n",
        "License_restricts_use: yes\n",
        "MD5sum: 00000000000000000000000000000003\n",
        "NeedsCompilation: maybe\n",
        "Published: 2026-06-26 19:14:59 UTC\n\n"
    ),
    paste0(
        "Package: rsolvefixture.plain\n",
        "Version: 3.0.0\n",
        "License: RSOLVE Fictional Terms Plain\n",
        "MD5sum: 00000000000000000000000000000004\n",
        "NeedsCompilation: no\n",
        "Published: 2026-06-27 19:14:59 UTC\n"
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
    Package = "rsolvefixture.history",
    Version = "1.10.0",
    Depends = "R (>= 4.6.0), rsolvefixture.base",
    Imports = paste0(
        "rsolvefixture.import,\n  rsolvefixture.import.helper,\n  ",
        "rsolvefixture.import.extra"
    ),
    LinkingTo = "rsolvefixture.link",
    Suggests = "rsolvefixture.suggest",
    Enhances = "rsolvefixture.enhance",
    License = "RSOLVE Fictional Terms – Archive",
    License_is_FOSS = "yes",
    License_restricts_use = "no",
    MD5sum = "00000000000000000000000000000011",
    NeedsCompilation = "yes"
))
set_archive_row(2L, c(
    Package = "rsolvefixture.history",
    Version = "0.3.0",
    License = "RSOLVE Fictional Terms Older",
    License_is_FOSS = "yes",
    License_restricts_use = "no",
    MD5sum = "00000000000000000000000000000012",
    NeedsCompilation = "no"
))
set_archive_row(3L, c(
    Package = "rsolvefixture.utf8",
    Version = "2.0.0",
    License = "RSOLVE Fictional Terms 日本語",
    License_is_FOSS = "no",
    License_restricts_use = "yes",
    MD5sum = "00000000000000000000000000000013",
    NeedsCompilation = "no"
))
set_archive_row(4L, c(
    Package = "rsolvefixture.broken",
    Version = "not-a-version",
    License = "RSOLVE Fictional Terms Broken",
    MD5sum = "00000000000000000000000000000014"
))

archive_bytes <- function(value, compression = "gzip", version = 3L) {
    path <- tempfile("rsolvefixture-archive-")
    saveRDS(value, path, compress = compression, version = version)
    bytes <- readBin(path, what = "raw", n = file.info(path)$size)
    unlink(path)
    # R's gzip writer records the current time in bytes 5:8 of the header.
    # The serialized payload and all other header fields are deterministic.
    if (identical(compression, "gzip")) {
        bytes[5:8] <- as.raw(rep(0L, 4L))
    }
    bytes
}

write_binary_fixture <- function(name, value, compression = "gzip", version = 3L) {
    bytes <- archive_bytes(value, compression, version)
    if (identical(compression, FALSE)) {
        stopifnot(
            identical(bytes[seq_len(2L)], charToRaw("X\n")),
            identical(bytes[3:6], as.raw(c(0, 0, 0, version)))
        )
    } else {
        decompressed <- memDecompress(bytes, type = compression)
        magic <- switch(
            compression,
            gzip = as.raw(c(0x1f, 0x8b)),
            xz = as.raw(c(0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)),
            bzip2 = charToRaw("BZh"),
            stop("unsupported fixture compression: ", compression)
        )
        stopifnot(
            identical(bytes[seq_len(length(magic))], magic),
            identical(decompressed[seq_len(2L)], charToRaw("X\n")),
            identical(decompressed[3:6], as.raw(c(0, 0, 0, version)))
        )
    }
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
write_binary_fixture(
    "synthetic-valid-archive-PACKAGES.rds",
    archive[c(1L, 2L, 3L), , drop = FALSE]
)

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
    License = "RSOLVE Fictional Terms Matrix",
    MD5sum = "00000000000000000000000000000021",
    NeedsCompilation = "yes"
))
set_matrix_archive_row(2L, c(
    Package = "Matrix",
    Version = "1.7-0",
    Depends = "R (>= 4.4.0)",
    Imports = "methods",
    License = "RSOLVE Fictional Terms Matrix",
    MD5sum = "00000000000000000000000000000022",
    NeedsCompilation = "yes"
))
write_binary_fixture("synthetic-matrix-archive-PACKAGES.rds", matrix_archive)

empty_matrix_archive <- matrix(
    character(),
    nrow = 0L,
    ncol = length(archive_columns),
    dimnames = list(NULL, archive_columns)
)
write_binary_fixture(
    "synthetic-empty-matrix-archive-PACKAGES.rds",
    empty_matrix_archive
)
write_binary_fixture(
    "synthetic-matrix-archive-xz-PACKAGES.rds",
    matrix_archive,
    "xz"
)
write_binary_fixture(
    "synthetic-matrix-archive-bzip2-PACKAGES.rds",
    matrix_archive,
    "bzip2"
)

# Format 2 has no native-encoding field in its header. These repository
# records retain valid UTF-8 bytes while their character flags remain
# Native/unknown, so the provider's explicit UTF-8 contract is required.
native_license <- "RSOLVE UTF-8 fixture ™"
Encoding(native_license) <- "unknown"
native_archive <- matrix(
    c("Matrix", "1.7-6", native_license),
    nrow = 1L,
    dimnames = list(NULL, c("Package", "Version", "License"))
)
write_binary_fixture(
    "synthetic-native-utf8-archive-PACKAGES.rds",
    native_archive,
    compression = FALSE,
    version = 2L
)

# Invalid native bytes must remain a hard decode failure even when the
# provider opts into UTF-8 for CRAN-compatible repository data.
invalid_license <- rawToChar(as.raw(c(0xc3, 0x28)), multiple = FALSE)
Encoding(invalid_license) <- "unknown"
invalid_archive <- matrix(
    c("Matrix", "1.7-6", invalid_license),
    nrow = 1L,
    dimnames = list(NULL, c("Package", "Version", "License"))
)
write_binary_fixture(
    "synthetic-invalid-utf8-archive-PACKAGES.rds",
    invalid_archive,
    compression = FALSE,
    version = 2L
)

# A current-index-shaped pair: the root row precedes a Recommended path
# overlay for the same release identity. The catalog reader must keep the
# root metadata while retaining the overlay only as scoped evidence.
matrix_overlay_columns <- c(archive_columns, "Path")
matrix_overlay_archive <- matrix(
    NA_character_,
    nrow = 2L,
    ncol = length(matrix_overlay_columns),
    dimnames = list(NULL, matrix_overlay_columns)
)
set_matrix_overlay_row <- function(row, values) {
    matrix_overlay_archive[row, names(values)] <<- unname(values)
}
set_matrix_overlay_row(1L, c(
    Package = "Matrix",
    Version = "1.7-6",
    Depends = "R (>= 4.4), methods",
    License = "RSOLVE Fictional Terms Matrix",
    MD5sum = "00000000000000000000000000000031",
    NeedsCompilation = "yes"
))
set_matrix_overlay_row(2L, c(
    Package = "Matrix",
    Version = "1.7-6",
    Depends = "R (>= 4.7), methods",
    License = "RSOLVE Fictional Terms Matrix",
    MD5sum = "00000000000000000000000000000031",
    NeedsCompilation = "yes",
    Path = "4.7.0/Recommended"
))
write_binary_fixture(
    "synthetic-matrix-archive-overlay-PACKAGES.rds",
    matrix_overlay_archive
)
matrix_overlay_mismatch <- matrix_overlay_archive
matrix_overlay_mismatch[2L, "MD5sum"] <- "00000000000000000000000000000032"
write_binary_fixture(
    "synthetic-matrix-archive-overlay-mismatch-PACKAGES.rds",
    matrix_overlay_mismatch
)

# A true pathless root duplicate must remain fail closed. Unlike the
# Recommended row above, both rows claim the same CRAN root release scope.
matrix_root_duplicate <- matrix_overlay_archive[c(1L, 1L), , drop = FALSE]
matrix_root_duplicate[2L, "Depends"] <- "R (>= 4.7), methods"
matrix_root_duplicate[2L, "MD5sum"] <- "00000000000000000000000000000032"
write_binary_fixture(
    "synthetic-matrix-archive-root-duplicate-PACKAGES.rds",
    matrix_root_duplicate
)

# P3M-shaped current-index duplicate: the Recommended overlay comes first and
# neither row carries MD5sum. Catalog selection must still retain the root row.
matrix_p3m_overlay <- matrix_overlay_archive[c(2L, 1L), , drop = FALSE]
matrix_p3m_overlay[, "MD5sum"] <- NA_character_
write_binary_fixture(
    "synthetic-matrix-archive-overlay-p3m-PACKAGES.rds",
    matrix_p3m_overlay
)
write_binary_fixture("synthetic-matrix-archive-wrong-root.rds", "wrong root")
write_binary_fixture(
    "synthetic-matrix-archive-missing-version.rds",
    matrix_archive[, setdiff(colnames(matrix_archive), "Version"), drop = FALSE]
)

nlme_archive_columns <- archive_columns
nlme_archive <- matrix(
    NA_character_,
    nrow = 3L,
    ncol = length(nlme_archive_columns),
    dimnames = list(NULL, nlme_archive_columns)
)
set_nlme_archive_row <- function(row, values) {
    nlme_archive[row, names(values)] <<- unname(values)
}
set_nlme_archive_row(1L, c(
    Package = "nlme",
    Version = "3.1-168",
    Depends = "R (>= 3.6.0)",
    Imports = "graphics, stats, utils, lattice",
    License = "RSOLVE Fictional Terms nlme",
    MD5sum = "00000000000000000000000000000041",
    NeedsCompilation = "yes"
))
set_nlme_archive_row(2L, c(
    Package = "nlme",
    Version = "3.1-167",
    Depends = "R (>= 3.5.0)",
    Imports = "graphics, stats, utils, lattice",
    License = "RSOLVE Fictional Terms nlme",
    MD5sum = "00000000000000000000000000000042",
    NeedsCompilation = "yes"
))
set_nlme_archive_row(3L, c(
    Package = "nlme",
    Version = "3.1-166",
    Depends = "R (>= 3.6.x)",
    Imports = "graphics, stats, utils, lattice",
    License = "RSOLVE Fictional Terms nlme",
    MD5sum = "00000000000000000000000000000043",
    NeedsCompilation = "yes"
))
write_binary_fixture("synthetic-nlme-archive-PACKAGES.rds", nlme_archive)
write_binary_fixture(
    "synthetic-nlme-invalid-archive-PACKAGES.rds",
    nlme_archive[3L, , drop = FALSE]
)
nlme_invalid_identity <- nlme_archive[1L, , drop = FALSE]
nlme_invalid_identity[1L, "Package"] <- "nlme!"
write_binary_fixture(
    "synthetic-nlme-invalid-identity-archive-PACKAGES.rds",
    nlme_invalid_identity
)
nlme_invalid_version <- nlme_archive[c(1L, 2L, 1L), , drop = FALSE]
nlme_invalid_version[3L, "Version"] <- "3.1-2 (1999/12/23)"
nlme_invalid_version[3L, "MD5sum"] <- "00000000000000000000000000000044"
write_binary_fixture(
    "synthetic-nlme-invalid-version-archive-PACKAGES.rds",
    nlme_invalid_version
)
write_binary_fixture(
    "synthetic-nlme-all-invalid-version-archive-PACKAGES.rds",
    nlme_invalid_version[3L, , drop = FALSE]
)

matrix_invalid_path <- matrix_overlay_archive
matrix_invalid_path[2L, "Path"] <- "4.7.0/NotRecommended"
write_binary_fixture(
    "synthetic-matrix-archive-invalid-path-PACKAGES.rds",
    matrix_invalid_path
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
        "License: RSOLVE Fictional Terms Matrix\n",
        "NeedsCompilation: yes\n\n"
    )))
    tar <- tar_entry("Matrix/DESCRIPTION", description)
    path <- tempfile("rsolvefixture-tar-")
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

nested_archive_history <- list(
    Matrix = data.frame(
        size = 1234,
        isdir = FALSE,
        mode = 420L,
        mtime = 1790000000,
        ctime = 1790000000,
        atime = 1790000000,
        uid = 1000L,
        gid = 1000L,
        uname = "fixture",
        grname = "fixture",
        row.names = "Matrix/legacy/Matrix_1.6-5.tar.gz"
    )
)
write_binary_fixture("synthetic-meta-nested-archive.rds", nested_archive_history)

foreign_nested_archive_history <- list(
    calibFit = data.frame(
        size = 1234,
        isdir = FALSE,
        mode = 420L,
        mtime = 1790000000,
        ctime = 1790000000,
        atime = 1790000000,
        uid = 1000L,
        gid = 1000L,
        uname = "fixture",
        grname = "fixture",
        row.names = "calibFit/Ancestry/calib_0.1.02.tar.gz"
    )
)
write_binary_fixture(
    "synthetic-meta-foreign-nested-archive.rds",
    foreign_nested_archive_history
)

root_history_frame <- function(paths) {
    count <- length(paths)
    data.frame(
        size = rep(1234, count),
        isdir = rep(FALSE, count),
        mode = rep(420L, count),
        mtime = rep(1790000000, count),
        ctime = rep(1790000000, count),
        atime = rep(1790000000, count),
        uid = rep(1000L, count),
        gid = rep(1000L, count),
        uname = rep("fixture", count),
        grname = rep("fixture", count),
        row.names = paths
    )
}

write_binary_fixture(
    "synthetic-meta-root-nested-mixed.rds",
    root_history_frame(c(
        "Matrix/legacy/Matrix_1.6-5.tar.gz",
        "calibFit/Ancestry/calib_0.1.02.tar.gz",
        "dse/dse_R2000.4-1.tar.gz"
    ))
)
write_binary_fixture(
    "synthetic-meta-root-unsafe-percent.rds",
    root_history_frame("Matrix/%2e/Matrix_1.6-5.tar.gz")
)

invalid_history <- function(path, package = "Matrix") {
    setNames(list(data.frame(
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
    )), package)
}

invalid_history_paths <- c(
    "synthetic-meta-invalid-traversal.rds" = "Matrix/../Matrix_1.6-5.tar.gz",
    "synthetic-meta-invalid-query.rds" = "Matrix/Matrix_1.6-5.tar.gz?download=1",
    "synthetic-meta-invalid-fragment.rds" = "Matrix/Matrix_1.6-5.tar.gz#fragment",
    "synthetic-meta-invalid-percent-traversal.rds" =
        "Matrix/%2e%2e%2fMatrix_1.6-5.tar.gz",
    "synthetic-meta-invalid-percent-slash.rds" =
        "Matrix/Matrix_1.6-5.tar.gz%2fdownload",
    "synthetic-meta-invalid-percent-backslash.rds" =
        "Matrix/Matrix_1.6-5.tar.gz%5cdownload",
    "synthetic-meta-invalid-percent-dot.rds" =
        "Matrix/%2e/Matrix_1.6-5.tar.gz",
    "synthetic-meta-invalid-percent-query.rds" =
        "Matrix/Matrix_1.6-5.tar.gz%3fdownload",
    "synthetic-meta-invalid-percent-fragment.rds" =
        "Matrix/Matrix_1.6-5.tar.gz%23fragment",
    "synthetic-meta-invalid-backslash.rds" = "Matrix\\Matrix_1.6-5.tar.gz",
    "synthetic-meta-invalid-package-mismatch.rds" = "Other/Matrix_1.6-5.tar.gz",
    "synthetic-meta-invalid-version.rds" = "Matrix/Matrix_latest.tar.gz"
)
for (name in names(invalid_history_paths)) {
    write_binary_fixture(name, invalid_history(invalid_history_paths[[name]]))
}
write_binary_fixture(
    "synthetic-meta-invalid-legacy-version.rds",
    invalid_history("dse/dse_R2000.4-1.tar.gz", "dse")
)

description <- paste0(
    "Package: rsolvefixture.description\n",
    "Version: 0.4.0\n",
    "Title: A fictional single-record fixture\n",
    "Description: UTF-8 single record: 日本語とcafé\n",
    "Maintainer: Fixture Author <fixture@example.invalid>\n",
    "License: RSOLVE Fictional Terms Description\n",
    "Encoding: UTF-8\n",
    "Published: 2026-06-28 19:14:59 UTC\n\n"
)
write_fixture("synthetic-DESCRIPTION", description)

cat("Fixture", mode, "passed for CRAN DCF, archive RDS, history RDS, and source tarball fixtures.\n")
