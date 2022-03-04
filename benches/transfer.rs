// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use jf_cap::{
    bench_utils::{
        compute_sizes, compute_title_simple, get_builder_transfer, get_key_pairs,
        save_result_to_file_simple, GEN, NUM_INPUTS_RANGE, NUM_OUTPUTS_RANGE, TREE_DEPTH, VERIFY,
    },
    proof::{
        transfer::{preprocess, TransferProvingKey, TransferVerifyingKey},
        universal_setup,
    },
    structs::NoteType,
    transfer::TransferNote,
    utils::{compute_universal_param_size, params_builder::TransferParamsBuilder},
    NodeValue,
};
use rand::rngs::StdRng;
use std::time::Duration;

fn run_transfer_creation(
    prng: &mut StdRng,
    transfer_note_builder: &TransferParamsBuilder,
    proving_key: &TransferProvingKey,
    valid_until: u64,
) -> TransferNote {
    let (transfer_note, ..) = transfer_note_builder
        .build_transfer_note(prng, &proving_key, valid_until, vec![])
        .unwrap();
    transfer_note
}

fn run_transfer_verification(
    verifier_key: &TransferVerifyingKey,
    note: &TransferNote,
    root: NodeValue,
    timestamp: u64,
) {
    assert!(note.verify(&verifier_key, root, timestamp).is_ok());
}

const TRANSACTION_NAME: &str = "transfer_note";

fn run_benchmark_transfer(c: &mut Criterion, filename_list: &mut Vec<String>) {
    let mut benchmark_group = c.benchmark_group(TRANSACTION_NAME);
    benchmark_group.sample_size(10);
    benchmark_group.measurement_time(Duration::new(10, 0));

    for num_inputs in &NUM_INPUTS_RANGE {
        for num_outputs in &NUM_OUTPUTS_RANGE {
            let mut prng = ark_std::test_rng();

            let valid_until = 1234;

            // Public parameters
            let domain_size = compute_universal_param_size(
                NoteType::Transfer,
                *num_inputs,
                *num_outputs,
                TREE_DEPTH,
            )
            .unwrap();
            let srs = universal_setup(domain_size, &mut prng).unwrap();
            let (proving_key, verifying_key, n_constraints) =
                preprocess(&srs, *num_inputs, *num_outputs, TREE_DEPTH).unwrap();

            let user_keypairs = get_key_pairs(*num_inputs);
            let builder =
                get_builder_transfer(&user_keypairs, *num_inputs, *num_outputs, TREE_DEPTH);

            // The transfer note is computed outside the "benching section" in order to
            // obtain the size of the note
            let (transfer_note, ..) = builder
                .build_transfer_note(&mut prng, &proving_key, valid_until, vec![])
                .unwrap();

            let (transfer_note_size, proving_key_size, verifying_key_size) =
                compute_sizes(&transfer_note, &proving_key, &verifying_key);

            // Generation
            let title = compute_title_simple(
                GEN,
                *num_inputs,
                *num_outputs,
                TREE_DEPTH,
                domain_size,
                n_constraints,
                transfer_note_size,
                proving_key_size,
                verifying_key_size,
            );

            filename_list.push(title.clone());

            benchmark_group.bench_with_input(&title, &num_inputs, move |b, &_num_inputs| {
                b.iter(|| run_transfer_creation(&mut prng, &builder, &proving_key, valid_until))
            });

            // Verification
            let title = compute_title_simple(
                VERIFY,
                *num_inputs,
                *num_outputs,
                TREE_DEPTH,
                domain_size,
                n_constraints,
                transfer_note_size,
                proving_key_size,
                verifying_key_size,
            );

            filename_list.push(title.clone());

            let root = transfer_note.aux_info.merkle_root;
            benchmark_group.bench_with_input(&title, &num_inputs, move |b, &_num_input| {
                b.iter(|| {
                    run_transfer_verification(
                        &verifying_key,
                        &transfer_note.clone(),
                        root,
                        valid_until - 1,
                    )
                })
            });
        }
    }

    benchmark_group.finish();
}

fn bench(c: &mut Criterion) {
    let mut filename_list = vec![];
    run_benchmark_transfer(c, &mut filename_list);
    let _ = save_result_to_file_simple(filename_list, TRANSACTION_NAME);
}

criterion_group!(benches, bench);

criterion_main!(benches);
