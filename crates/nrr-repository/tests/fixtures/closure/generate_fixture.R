#!/usr/bin/env Rscript
args <- commandArgs(trailingOnly = TRUE)
mode <- if (length(args) == 1L) args[[1L]] else "--check"
if (!mode %in% c("--check", "--update")) stop("usage: generate_fixture.R --check|--update")

all_args <- commandArgs()
file_arg <- all_args[grepl("^--file=", all_args)][1L]
if (is.na(file_arg)) stop("script path is unavailable")
root <- normalizePath(dirname(sub("^--file=", "", file_arg)), mustWork = TRUE)
out <- file.path(root, "artifacts")
manifest <- file.path(root, "SHA256SUMS")
names <- c("leaf", "middle", "root")
versions <- rep("0.1.0", 3L)
tarballs <- file.path(out, paste0(names, "_", versions, ".tar.gz"))

if (mode == "--check") {
  missing <- tarballs[!file.exists(tarballs)]
  if (length(missing)) stop("fixture archive missing: ", paste(missing, collapse = ", "))
  if (!file.exists(manifest)) stop("fixture manifest missing: ", manifest)
} else {
  dir.create(out, recursive = TRUE, showWarnings = FALSE)
  work <- file.path(root, "work")
  unlink(work, recursive = TRUE, force = TRUE)
  dir.create(work, recursive = TRUE)

  write_text <- function(path, lines) {
    dir.create(dirname(path), recursive = TRUE, showWarnings = FALSE)
    writeLines(lines, path, useBytes = TRUE)
  }
  make_leaf <- function() {
    p <- file.path(work, "leaf")
    write_text(file.path(p, "DESCRIPTION"), c(
      "Package: leaf", "Version: 0.1.0", "Title: Fictional Leaf",
      "Description: UTF-8 leaf package – café.", "Authors@R: person('Fixture', 'Author', email='fixture@example.com', role=c('aut','cre','cph'))",
      "License: MIT", "Encoding: UTF-8", "NeedsCompilation: no"))
    write_text(file.path(p, "NAMESPACE"), "export(leaf_value)")
    write_text(file.path(p, "R/leaf.R"), c("leaf_value <- function() {", "  'leaf-ok'", "}"))
    p
  }
  make_middle <- function() {
    p <- file.path(work, "middle")
    write_text(file.path(p, "DESCRIPTION"), c(
      "Package: middle", "Version: 0.1.0", "Title: Fictional Middle",
      "Description: UTF-8 middle package – café.", " folded metadata line.",
      "Authors@R: person('Fixture', 'Author', email='fixture@example.com', role=c('aut','cre','cph'))",
      "License: MIT", "Encoding: UTF-8", "Imports: leaf", "NeedsCompilation: yes"))
    write_text(file.path(p, "NAMESPACE"), c("importFrom(leaf,leaf_value)", "export(middle_value)", "useDynLib(middle)"))
    write_text(file.path(p, "R/middle.R"), c("middle_value <- function() {", "  paste0('middle-', leaf_value())", "}"))
    write_text(file.path(p, "src/middle.c"), c(
      "#include <R.h>", "#include <Rinternals.h>", "#include \"../inst/include/middle_marker.h\"",
      "SEXP middle_marker(void) { return ScalarInteger(MIDDLE_MARKER_VALUE); }"))
    write_text(file.path(p, "inst/include/middle_marker.h"), c("#ifndef MIDDLE_MARKER_H", "#define MIDDLE_MARKER_H", "#define MIDDLE_MARKER_VALUE 17", "#endif"))
    p
  }
  make_root <- function() {
    p <- file.path(work, "root")
    write_text(file.path(p, "DESCRIPTION"), c(
      "Package: root", "Version: 0.1.0", "Title: Fictional Root",
      "Description: UTF-8 root package – café.", "Authors@R: person('Fixture', 'Author', email='fixture@example.com', role=c('aut','cre','cph'))",
      "License: MIT", "Encoding: UTF-8", "LinkingTo: middle", "NeedsCompilation: yes"))
    write_text(file.path(p, "NAMESPACE"), "useDynLib(root)")
    write_text(file.path(p, "src/root.c"), c(
      "#include <R.h>", "#include <Rinternals.h>", "#include <middle_marker.h>",
      "void root_init(DllInfo *dll) { if (MIDDLE_MARKER_VALUE != 17) error(\"marker mismatch\"); }"))
    p
  }
  archive <- function(package_dir, name) {
    target <- file.path(out, paste0(name, "_0.1.0.tar.gz"))
    if (!dir.exists(package_dir)) stop("package source directory is missing: ", package_dir)
    status <- system2("tar", c("--sort=name", "--mtime=2020-01-01", "--owner=0", "--group=0", "--numeric-owner", "-C", work, "-czf", target, name))
    if (status != 0) stop("tar failed for ", name)
  }
  archive(make_leaf(), "leaf")
  archive(make_middle(), "middle")
  archive(make_root(), "root")
  unlink(work, recursive = TRUE, force = TRUE)
}

hash <- function(path) {
  line <- system2("sha256sum", path, stdout = TRUE)
  if (length(line) != 1L) stop("sha256sum failed for ", path)
  sub("[[:space:]].*", "", line)
}
dir.create(out, recursive = TRUE, showWarnings = FALSE)
actual <- setNames(vapply(tarballs, hash, character(1)), basename(tarballs))
if (mode == "--update") {
  writeLines(paste(actual, names(actual)), manifest, useBytes = TRUE)
} else {
  expected <- readLines(manifest, warn = FALSE)
  expected <- expected[nzchar(expected)]
  expected_values <- setNames(sub("[[:space:]].*", "", expected), sub("^[^[:space:]]+[[:space:]]+", "", expected))
  if (!identical(expected_values[names(actual)], actual)) stop("fixture SHA256SUMS mismatch")
}
cat(mode, ": fixture archives and SHA256SUMS verified\n")
