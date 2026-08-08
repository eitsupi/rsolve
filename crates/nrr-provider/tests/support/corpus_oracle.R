#!/usr/bin/env Rscript

# Emit a small, dependency-free canonical form of read.dcf() output.
# The Rust differential test compares record order and field/value pairs.

args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 2L) stop("usage: corpus_oracle.R PACKAGES OUTPUT")
if (getRversion() != "4.6.1")
    stop("corpus oracle requires R 4.6.1; found ", getRversion())

packages_path <- normalizePath(args[[1L]], mustWork = TRUE)
output_path <- args[[2L]]
size <- unname(file.info(packages_path)$size)
if (is.na(size) || size <= 0) stop("corpus PACKAGES file is absent or empty")

table <- read.dcf(packages_path, all = TRUE, keep.white = TRUE)

hex <- function(value) {
    paste(sprintf("%02x", as.integer(charToRaw(enc2utf8(value)))), collapse = "")
}

lines <- sprintf("records\t%d", nrow(table))
for (row in seq_len(nrow(table))) {
    for (field_name in names(table)) {
        value <- table[[field_name]][[row]]
        if (length(value) != 1L)
            stop("corpus field is not scalar: ", field_name, " row ", row)
        if (is.na(value)) next
        lines <- c(lines, paste(
            "field", row, hex(field_name), hex(value), sep = "\t"
        ))
    }
}

writeLines(lines, output_path, useBytes = TRUE)
