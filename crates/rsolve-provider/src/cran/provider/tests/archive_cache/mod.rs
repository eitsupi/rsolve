use super::*;

mod allpackages;
mod archive_history;
mod package_archive;
mod package_archive_revalidation;
mod support;

pub(super) use support::{
    ROOT_DUPLICATE_ARCHIVE, all_semantic_invalid_archive_index, allpackages_duplicate_fixture_body,
    allpackages_fixture_body, allpackages_transport, custom_mirror_transport, empty_transport,
    history_response, history_response_with_body, matrix_history_entries,
    mixed_semantic_archive_index, partial_fast_path_detail, release_signature, store,
};

const ALLPACKAGES_FIXTURE_URL: &str = "https://feed.invalid/ALLPACKAGES.zst";
