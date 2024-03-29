// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

#![allow(missing_docs)]
use crate::{
    keys::{FreezerKeyPair, UserKeyPair, ViewerKeyPair},
    prelude::CapConfig,
    structs::Amount,
    utils::params_builder::{FreezeParamsBuilder, MintParamsBuilder, TransferParamsBuilder},
};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    boxed::Box,
    env,
    error::Error,
    format,
    fs::File,
    io::{BufWriter, Read},
    path::PathBuf,
    println,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use percentage::Percentage;
use rand::{CryptoRng, RngCore};

pub const GEN: &str = "Gen";
pub const BATCH_VERIF: &str = "BatchVerify";
pub const VERIFY: &str = "Verify";

pub const NUM_INPUTS_RANGE: [usize; 3] = [2, 3, 4];
pub const NUM_OUTPUTS_RANGE: [usize; 2] = [2, 5];
pub const TREE_DEPTH: u8 = 26; // Corresponds to 2.5 trillions leaves

pub fn full_path(dirname: &str, transaction_name: &str) -> String {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("..");
    d.push("target");
    d.push("criterion");
    d.push(transaction_name);
    d.push(dirname);
    d.push("new");
    d.push("estimates");
    d.set_extension("json");
    d.into_os_string().into_string().unwrap()
}

/// The number of threads is given by the environment variable RAYON_NUM_THREADS
/// or is equal to the number of cores
fn number_threads() -> String {
    match env::var("RAYON_NUM_THREADS") {
        Ok(s) => s,
        _ => num_cpus::get().to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn compute_title_batch(
    fun_desc: &str,
    num_inputs: usize,
    num_outputs: usize,
    tree_depth: u8,
    num_notes: usize,
) -> String {
    format!(
        "{}-{}-{}-{}-{}-{}",
        number_threads(),
        fun_desc,
        num_inputs,
        num_outputs,
        tree_depth,
        num_notes,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compute_title_simple(
    fun_desc: &str,
    num_inputs: usize,
    num_outputs: usize,
    tree_depth: u8,
    domain_size: usize,
    n_constraints: usize,
    note_size: usize,
    proving_key_size: usize,
    verifying_key_size: usize,
) -> String {
    let utility_ratio =
        Percentage::from_decimal((n_constraints as f64) / (domain_size as f64)).value() * (100_f64);

    format!(
        "{}-{}-{}-{}-{}-{}-{}-{:.0}-{}-{}-{}",
        number_threads(),
        fun_desc,
        num_inputs,
        num_outputs,
        tree_depth,
        domain_size,
        n_constraints,
        utility_ratio,
        note_size,
        proving_key_size,
        verifying_key_size
    )
}

pub fn compute_sizes<N, P, V>(
    transfer_note: &N,
    proving_key: &P,
    verifying_key: &V,
) -> (usize, usize, usize)
where
    N: CanonicalSerialize,
    P: CanonicalSerialize,
    V: CanonicalSerialize,
{
    (
        transfer_note.serialized_size(),
        proving_key.serialized_size(),
        verifying_key.serialized_size(),
    )
}

pub fn get_key_pairs<C: CapConfig>(num_inputs: usize) -> Vec<UserKeyPair<C>> {
    let mut prng = ark_std::test_rng();
    let mut user_keypairs = vec![];
    for _ in 0..num_inputs {
        user_keypairs.push(UserKeyPair::generate(&mut prng));
    }
    user_keypairs
}

fn read_json(full_path_name: &str) -> String {
    let mut file = File::open(full_path_name).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let json = serde_json::from_str::<serde_json::Value>(&data).unwrap();
    let json_str = &json["mean"]["point_estimate"];
    json_str.to_string()
}

fn convert_nano_sec_to_millisec(time: &str) -> String {
    let nano_sec: f64 = time.parse().unwrap();
    let millisec = nano_sec / (1_000_000_f64);
    millisec.to_string()
}

fn convert_bytes_to_kilobytes(size: &str) -> String {
    let bytes: f64 = size.parse().unwrap();
    let kilo_bytes = bytes / (1_000_f64);
    kilo_bytes.to_string()
}

fn build_csv_records_simple(
    note_description: &str,
    values: Vec<&str>,
    time_str: &str,
) -> Vec<String> {
    vec![
        note_description.to_string(),
        values[0].to_string(),
        values[1].to_string(),
        values[2].to_string(),
        values[3].to_string(),
        values[4].to_string(),
        values[5].to_string(),
        values[6].to_string(),
        values[7].to_string(),
        convert_bytes_to_kilobytes(values[8]),
        convert_bytes_to_kilobytes(values[9]),
        convert_bytes_to_kilobytes(values[10]),
        time_str.to_string(),
    ]
}

fn build_csv_records_batch(
    note_description: &str,
    values: Vec<&str>,
    time_str: &str,
) -> Vec<String> {
    vec![
        note_description.to_string(),
        values[0].to_string(),
        values[1].to_string(),
        values[2].to_string(),
        values[3].to_string(),
        values[4].to_string(),
        values[5].to_string(),
        time_str.to_string(),
    ]
}

#[allow(clippy::type_complexity)]
pub fn save_results_to_file(
    headers: &[&str],
    list: Vec<String>,
    note_description: &str,
    build_csv_record_fun: &dyn Fn(&str, Vec<&str>, &str) -> Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let output_filename = format!("/tmp/{}_cap_benchmark.csv", note_description);
    let f = File::create(&output_filename).expect("Unable to create file");
    let wtr = BufWriter::new(f);
    let mut csv_wtr = csv::Writer::from_writer(wtr);
    csv_wtr.write_record(headers)?;

    for dirname in list {
        let full_filename = full_path(&dirname, note_description);
        let split_values = dirname.split('-');
        let values = split_values.collect::<Vec<&str>>();

        let time_nano_sec_str = read_json(&full_filename);
        let time_str = convert_nano_sec_to_millisec(&time_nano_sec_str);

        let csv_record = build_csv_record_fun(note_description, values, &time_str);

        csv_wtr.write_record(csv_record)?;
    }
    csv_wtr.flush()?;
    println!("//////////////////////////////////////////////////////////////////////////////////");
    println!("// Benchmark results can be found in {} ", output_filename);
    println!("//////////////////////////////////////////////////////////////////////////////////");
    Ok(())
}

pub fn save_result_to_file_simple(
    list: Vec<String>,
    note_description: &str,
) -> Result<(), Box<dyn Error>> {
    let headers = vec![
        "TRANSACTION",
        "N_THREADS",
        "FUNCTION",
        "N_INPUTS",
        "N_OUTPUTS",
        "TREE_HEIGHT",
        "DOMAIN_SIZE",
        "N_CONSTRAINTS",
        "UTILITY_RATIO(%)",
        "TRANSFER_NOTE_SIZE (KB)",
        "PROVING_KEY_SIZE (KB)",
        "VERIFYING_KEY_SIZE (KB)",
        "TIME (ms)",
    ];
    save_results_to_file(&headers, list, note_description, &build_csv_records_simple)
}

pub fn save_result_to_file_batch(
    list: Vec<String>,
    note_description: &str,
) -> Result<(), Box<dyn Error>> {
    let headers = vec![
        "TRANSACTION",
        "N_THREADS",
        "FUNCTION",
        "N_INPUTS",
        "N_OUTPUTS",
        "TREE_HEIGHT",
        "N_NOTES",
        "TIME (ms)",
    ];
    save_results_to_file(&headers, list, note_description, &build_csv_records_batch)
}

pub fn get_builder_freeze<'a, C: CapConfig>(
    fee_keypair: &'a UserKeyPair<C>,
    freeze_keypairs: Vec<&'a FreezerKeyPair<C>>,
    num_inputs: usize,
    tree_depth: u8,
) -> FreezeParamsBuilder<'a, C> {
    let input_amounts = vec![Amount::from(15_u128); num_inputs - 1];
    let fee_input_amount = Amount::from(10u64);
    let fee = Amount::from(5u64);

    FreezeParamsBuilder::new(
        tree_depth,
        &input_amounts,
        fee_input_amount,
        fee,
        fee_keypair,
        freeze_keypairs,
    )
}

pub fn get_builder_mint<'a, R: RngCore + CryptoRng, C: CapConfig>(
    rng: &mut R,
    minter_keypair: &'a UserKeyPair<C>,
    receiver_keypair: &'a UserKeyPair<C>,
    viewer_keypair: &'a ViewerKeyPair<C>,
    tree_depth: u8,
) -> MintParamsBuilder<'a, C> {
    let input_amount = Amount::from(10u64);
    let fee = Amount::from(4u64);
    let mint_amount = Amount::from(35u64);

    MintParamsBuilder::new(
        rng,
        tree_depth,
        input_amount,
        fee,
        mint_amount,
        minter_keypair,
        receiver_keypair,
        viewer_keypair,
    )
}

pub fn get_builder_transfer<C: CapConfig>(
    user_keypairs: &[UserKeyPair<C>],
    num_inputs: usize,
    num_outputs: usize,
    tree_depth: u8,
) -> TransferParamsBuilder<C> {
    let cred_expiry = 9999;

    let amount_input = Amount::from(1u64);
    let amount_inputs = vec![amount_input; num_inputs - 1];

    // Ensure that "sum of input amounts == sum of output amounts"
    let mut amount_outputs: Vec<Amount> = vec![Amount::from((num_inputs - 1) as u128)];
    amount_outputs.extend(vec![Amount::from(0u64); num_outputs - 2].iter());

    TransferParamsBuilder::new_non_native(
        num_inputs,
        num_outputs,
        Some(tree_depth),
        user_keypairs.iter().collect(),
    )
    .set_input_amounts(Amount::from(30u64), &amount_inputs)
    .set_output_amounts(Amount::from(29u64), &amount_outputs)
    .set_input_creds(cred_expiry)
}
