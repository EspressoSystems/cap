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
        compute_sizes, compute_title_simple, get_builder_freeze, save_result_to_file_simple, GEN,
        NUM_INPUTS_RANGE, TREE_DEPTH, VERIFY,
    },
    prelude::*,
    proof::freeze::{self, FreezeProvingKey, FreezeVerifyingKey},
    utils::{compute_universal_param_size, params_builder::FreezeParamsBuilder},
};
use jf_primitives::merkle_tree::NodeValue;
use rand::rngs::StdRng;
use std::time::Duration;

fn run_freeze_creation(
    prng: &mut StdRng,
    builder: &FreezeParamsBuilder<Config>,
    proving_key: &FreezeProvingKey<Config>,
) -> FreezeNote<Config> {
    let (note, ..) = builder.build_freeze_note(prng, proving_key).unwrap();
    note
}

fn run_freeze_verification(
    verifier_key: &FreezeVerifyingKey<Config>,
    note: &FreezeNote<Config>,
    root: NodeValue<<Config as CapConfig>::ScalarField>,
) {
    assert!(note.verify(verifier_key, root).is_ok());
}

const TRANSACTION_NAME: &str = "freeze_note";

fn run_benchmark_freeze(c: &mut Criterion, filename_list: &mut Vec<String>) {
    let mut benchmark_group = c.benchmark_group(TRANSACTION_NAME);
    benchmark_group.sample_size(10);
    benchmark_group.measurement_time(Duration::new(10, 0));

    for num_inputs in &NUM_INPUTS_RANGE {
        let mut prng = ark_std::test_rng();

        // Public parameters
        let domain_size =
            compute_universal_param_size::<Config>(NoteType::Freeze, *num_inputs, 0, TREE_DEPTH)
                .unwrap();
        let srs = jf_cap::proof::universal_setup::<_, Config>(domain_size, &mut prng).unwrap();
        let (proving_key, verifying_key, n_constraints) =
            freeze::preprocess(&srs, *num_inputs, TREE_DEPTH).unwrap();

        let fee_keypair = UserKeyPair::generate(&mut prng);
        let freezer_keypair = FreezerKeyPair::generate(&mut prng);
        let builder = get_builder_freeze(
            &fee_keypair,
            vec![&freezer_keypair; *num_inputs - 1],
            *num_inputs,
            TREE_DEPTH,
        );

        // The freeze note is computed outside the "benching section" in order to
        // obtain the size of the note
        let (freeze_note, ..) = builder.build_freeze_note(&mut prng, &proving_key).unwrap();

        let (freeze_note_size, proving_key_size, verifying_key_size) =
            compute_sizes(&freeze_note, &proving_key, &verifying_key);

        // Generation

        let title = compute_title_simple(
            GEN,
            *num_inputs,
            0,
            TREE_DEPTH,
            domain_size,
            n_constraints,
            freeze_note_size,
            proving_key_size,
            verifying_key_size,
        );

        filename_list.push(title.clone());

        benchmark_group.bench_with_input(&title, &num_inputs, move |b, &_num_inputs| {
            b.iter(|| run_freeze_creation(&mut prng, &builder, &proving_key))
        });

        // Verification
        let title = compute_title_simple(
            VERIFY,
            *num_inputs,
            0,
            TREE_DEPTH,
            domain_size,
            n_constraints,
            freeze_note_size,
            proving_key_size,
            verifying_key_size,
        );

        filename_list.push(title.clone());

        let root = freeze_note.aux_info.merkle_root;

        benchmark_group.bench_with_input(&title, &num_inputs, move |b, &_num_input| {
            b.iter(|| run_freeze_verification(&verifying_key, &freeze_note, root))
        });
    }

    benchmark_group.finish();
}

fn bench(c: &mut Criterion) {
    let mut filename_list = vec![];
    run_benchmark_freeze(c, &mut filename_list);
    let _ = save_result_to_file_simple(filename_list, TRANSACTION_NAME);
}

criterion_group!(benches, bench);

criterion_main!(benches);
