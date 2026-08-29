use super::*;

#[test]
fn build_reopens_and_is_deterministic() {
    let dir = tempdir().unwrap();
    let one = dir.path().join("one.redb");
    let two = dir.path().join("two.redb");
    let a = SnapshotGenerationBuilder::new(input(), &one)
        .build()
        .unwrap();
    let b = SnapshotGenerationBuilder::new(input(), &two)
        .build()
        .unwrap();
    assert_eq!(
        a.generation(),
        "46782d0d0b28075b68402556aa8449f656d4423cda0a89ff2c42e1b0babd900c"
    );
    assert_eq!(a.generation(), b.generation());
    assert_eq!(a.header_bytes(), b.header_bytes());
}

#[test]
fn source_reordering_remaps_observations_without_mutating_input() {
    let dir = tempdir().unwrap();
    let (canonical_input, input_source_ids) = two_source_input();
    let mut reversed_input = canonical_input.clone();
    reversed_input.sources.reverse();
    reversed_input.histories[0].observations[0].source_index = 1;
    reversed_input.histories[0].observations[1].source_index = 0;

    let first =
        SnapshotGenerationBuilder::new(canonical_input.clone(), dir.path().join("canonical.redb"))
            .build()
            .unwrap();
    let second =
        SnapshotGenerationBuilder::new(reversed_input.clone(), dir.path().join("reversed.redb"))
            .build()
            .unwrap();

    assert_eq!(first.generation(), second.generation());
    assert_eq!(first.header_bytes(), second.header_bytes());
    assert_eq!(canonical_input.histories[0].observations[0].source_index, 0);
    assert_eq!(canonical_input.histories[0].observations[1].source_index, 1);
    let history = stored_history(second.path());
    for (observation, input_source_id) in history.observations.iter().zip(input_source_ids) {
        assert_eq!(
            second.header().sources[observation.source_index as usize].id,
            input_source_id
        );
    }
}

#[test]
fn bare_destination_uses_current_directory_without_changing_it() {
    assert_eq!(
        destination_parent(Path::new("generation.redb")),
        Path::new(".")
    );
    assert_eq!(
        destination_parent(Path::new("nested/generation.redb")),
        Path::new("nested")
    );
}
