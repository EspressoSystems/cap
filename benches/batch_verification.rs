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
        compute_title_batch, get_builder_freeze, get_builder_mint, get_builder_transfer,
        get_key_pairs, save_result_to_file_batch, BATCH_VERIF, NUM_INPUTS_RANGE, NUM_OUTPUTS_RANGE,
        TREE_DEPTH,
    },
    keys::{FreezerKeyPair, UserKeyPair, ViewerKeyPair},
    proof::{freeze, mint, transfer, universal_setup},
    structs::NoteType,
    txn_batch_verify,
    utils::compute_universal_param_size,
    NodeValue, TransactionNote, TransactionVerifyingKey,
};
use std::{cmp::max, time::Duration};

fn run_batch_verification(
    verify_keys: &[TransactionVerifyingKey],
    notes: &[TransactionNote],
    roots: &[NodeValue],
    timestamp: u64,
) {
    let verify_keys: Vec<_> = verify_keys.iter().map(|x| x).collect();
    assert!(txn_batch_verify(notes, roots, timestamp, &verify_keys).is_ok());
}

const TRANSACTION_NAME: &str = "batch_verification";
const NUM_NOTES_PER_TX_TYPE: [u8; 3] = [1, 2, 4];

fn run_benchmark_batch_verification(c: &mut Criterion, filename_list: &mut Vec<String>) {
    let mut benchmark_group = c.benchmark_group(TRANSACTION_NAME);
    benchmark_group.sample_size(10);
    benchmark_group.measurement_time(Duration::new(10, 0));

    let mut prng = ark_std::test_rng();

    let timestamp = 1234;

    for num_notes in &NUM_NOTES_PER_TX_TYPE {
        for num_inputs in &NUM_INPUTS_RANGE {
            for num_outputs in &NUM_OUTPUTS_RANGE {
                ///////////////////////////////////////////////////////////////////////////////
                // Public parameters
                ///////////////////////////////////////////////////////////////////////////////

                let domain_size_transfer = compute_universal_param_size(
                    NoteType::Transfer,
                    *num_inputs,
                    *num_outputs,
                    TREE_DEPTH,
                )
                .unwrap();
                let domain_size_mint = compute_universal_param_size(
                    NoteType::Mint,
                    *num_inputs,
                    *num_outputs,
                    TREE_DEPTH,
                )
                .unwrap();

                let domain_size_freeze = compute_universal_param_size(
                    NoteType::Freeze,
                    *num_inputs,
                    *num_outputs,
                    TREE_DEPTH,
                )
                .unwrap();

                let domain_size = vec![domain_size_transfer, domain_size_mint, domain_size_freeze]
                    .iter()
                    .fold(domain_size_transfer, |acc, &x| max(acc, x));

                let srs = universal_setup(domain_size, &mut prng).unwrap();

                let (proving_key_transfer, verifying_key_transfer, _) =
                    transfer::preprocess(&srs, *num_inputs, *num_outputs, TREE_DEPTH).unwrap();

                let (proving_key_mint, verifying_key_mint, _) =
                    mint::preprocess(&srs, TREE_DEPTH).unwrap();

                let (proving_key_freeze, verifying_key_freeze, _) =
                    freeze::preprocess(&srs, *num_inputs, TREE_DEPTH).unwrap();

                //////////////////////////////////////////////////////////////////////////
                // Build the transactions
                //////////////////////////////////////////////////////////////////////////

                // Transfer notes
                let user_keypairs = get_key_pairs(*num_inputs);
                let builder_transfer =
                    get_builder_transfer(&user_keypairs, *num_inputs, *num_outputs, TREE_DEPTH);

                let mut transfer_notes = vec![];

                let (transfer_note, ..) = builder_transfer
                    .build_transfer_note(&mut prng, &proving_key_transfer, timestamp, vec![])
                    .unwrap();
                for _ in 0..*num_notes {
                    transfer_notes.push(transfer_note.clone());
                }

                // Mint notes
                let minter_keypair = UserKeyPair::generate(&mut prng);
                let receiver_keypair = UserKeyPair::generate(&mut prng);
                let viewer_keypair = ViewerKeyPair::generate(&mut prng);
                let builder_mint = get_builder_mint(
                    &mut prng,
                    &minter_keypair,
                    &receiver_keypair,
                    &viewer_keypair,
                    TREE_DEPTH,
                );

                let mut mint_notes = vec![];
                let (mint_note, ..) = builder_mint
                    .build_mint_note(&mut prng, &proving_key_mint)
                    .unwrap();
                for _ in 0..*num_notes {
                    mint_notes.push(mint_note.clone());
                }

                // Freeze notes
                let fee_keypair = UserKeyPair::generate(&mut prng);
                let freezer_keypair = FreezerKeyPair::generate(&mut prng);
                let builder = get_builder_freeze(
                    &fee_keypair,
                    vec![&freezer_keypair; *num_inputs - 1],
                    *num_inputs,
                    TREE_DEPTH,
                );

                let mut freeze_notes = vec![];
                let mut verif_keys = vec![];
                let mut roots = vec![];

                let (freeze_note, ..) = builder
                    .build_freeze_note(&mut prng, &proving_key_freeze)
                    .unwrap();
                for _ in 0..*num_notes {
                    freeze_notes.push(freeze_note.clone());
                }

                // Build the heterogeneous list of notes
                let mut notes = vec![];

                for transfer_note in transfer_notes {
                    notes.push(TransactionNote::from(transfer_note.clone()));
                    verif_keys.push(TransactionVerifyingKey::Transfer(
                        verifying_key_transfer.clone(),
                    ));
                    roots.push(transfer_note.aux_info.merkle_root.clone());
                }

                for mint_note in mint_notes {
                    notes.push(TransactionNote::from(mint_note.clone()));
                    verif_keys.push(TransactionVerifyingKey::Mint(verifying_key_mint.clone()));
                    roots.push(mint_note.aux_info.merkle_root.clone());
                }

                for freeze_note in freeze_notes {
                    notes.push(TransactionNote::from(freeze_note.clone()));
                    verif_keys.push(TransactionVerifyingKey::Freeze(
                        verifying_key_freeze.clone(),
                    ));
                    roots.push(freeze_note.aux_info.merkle_root.clone());
                }

                let total_num_notes = notes.len();

                // Verification
                let title = compute_title_batch(
                    BATCH_VERIF,
                    *num_inputs,
                    *num_outputs,
                    TREE_DEPTH,
                    total_num_notes,
                );

                filename_list.push(title.clone());

                benchmark_group.bench_with_input(&title, &num_inputs, move |b, &_num_input| {
                    b.iter(|| run_batch_verification(&verif_keys, &notes, &roots, timestamp))
                });
            }
        }
    }

    benchmark_group.finish();
}

fn bench(c: &mut Criterion) {
    let mut filename_list = vec![];
    run_benchmark_batch_verification(c, &mut filename_list);
    let _ = save_result_to_file_batch(filename_list, TRANSACTION_NAME);
}

criterion_group!(benches, bench);

criterion_main!(benches);
