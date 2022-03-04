// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

#[macro_use]
extern crate criterion;
use criterion::Criterion;
use jf_cap::{
    bench_utils::{
        compute_sizes, compute_title_simple, get_builder_mint, save_result_to_file_simple, GEN,
        TREE_DEPTH, VERIFY,
    },
    keys::{UserKeyPair, ViewerKeyPair},
    mint::MintNote,
    proof::{
        mint,
        mint::{MintProvingKey, MintVerifyingKey},
        universal_setup,
    },
    structs::NoteType,
    utils::{compute_universal_param_size, params_builder::MintParamsBuilder},
    NodeValue,
};
use rand::rngs::StdRng;
use std::time::Duration;

fn run_mint_creation(
    prng: &mut StdRng,
    mint_note_builder: &MintParamsBuilder,
    proving_key: &MintProvingKey,
) -> MintNote {
    let (mint_note, ..) = mint_note_builder
        .build_mint_note(prng, &proving_key)
        .unwrap();

    mint_note
}

fn run_mint_verification(verifier_key: &MintVerifyingKey, note: &MintNote, root: NodeValue) {
    assert!(note.verify(&verifier_key, root).is_ok());
}

const TRANSACTION_NAME: &str = "mint_note";

fn run_benchmark_mint(c: &mut Criterion, filename_list: &mut Vec<String>) {
    let mut benchmark_group = c.benchmark_group(TRANSACTION_NAME);
    benchmark_group.sample_size(10);
    benchmark_group.measurement_time(Duration::new(10, 0));

    let mut prng = ark_std::test_rng();

    // Public parameters
    let domain_size = compute_universal_param_size(NoteType::Mint, 0, 0, TREE_DEPTH).unwrap();
    let srs = universal_setup(domain_size, &mut prng).unwrap();
    let (proving_key, verifying_key, n_constraints) = mint::preprocess(&srs, TREE_DEPTH).unwrap();

    let creator_keypair = UserKeyPair::generate(&mut prng);
    let receiver_keypair = UserKeyPair::generate(&mut prng);
    let viewer_keypair = ViewerKeyPair::generate(&mut prng);
    let builder = get_builder_mint(
        &mut prng,
        &creator_keypair,
        &receiver_keypair,
        &viewer_keypair,
        TREE_DEPTH,
    );

    // The mint note is computed outside the "benching section" in order to
    // obtain the size of the note
    let (mint_note, ..) = builder.build_mint_note(&mut prng, &proving_key).unwrap();

    let (mint_note_size, proving_key_size, verifying_key_size) =
        compute_sizes(&mint_note, &proving_key, &verifying_key);

    let num_inputs = 0;

    // Generation
    let title = compute_title_simple(
        GEN,
        0,
        0,
        TREE_DEPTH,
        domain_size,
        n_constraints,
        mint_note_size,
        proving_key_size,
        verifying_key_size,
    );

    filename_list.push(title.clone());

    benchmark_group.bench_with_input(&title, &num_inputs, move |b, &_num_inputs| {
        b.iter(|| run_mint_creation(&mut prng, &builder, &proving_key))
    });

    // Verification
    let title = compute_title_simple(
        VERIFY,
        0,
        0,
        TREE_DEPTH,
        domain_size,
        n_constraints,
        mint_note_size,
        proving_key_size,
        verifying_key_size,
    );

    filename_list.push(title.clone());

    let root = mint_note.aux_info.merkle_root;
    benchmark_group.bench_with_input(&title, &&num_inputs, move |b, &_num_input| {
        b.iter(|| run_mint_verification(&verifying_key, &mint_note, root))
    });

    benchmark_group.finish();
}

fn bench(c: &mut Criterion) {
    let mut filename_list = vec![];
    run_benchmark_mint(c, &mut filename_list);
    let _ = save_result_to_file_simple(filename_list, TRANSACTION_NAME);
}

criterion_group!(benches, bench);

criterion_main!(benches);
