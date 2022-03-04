// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Helper functions to create, save to and fetch from files for prover/verifier
//! parameters.

use crate::{
    errors::TxnApiError,
    proof::{
        self,
        freeze::{self, FreezeProvingKey, FreezeVerifyingKey},
        mint::{self, MintProvingKey, MintVerifyingKey},
        transfer::{self, TransferProvingKey, TransferVerifyingKey},
        UniversalParam,
    },
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    eprint, eprintln, format,
    io::{BufReader, Error as IoError, Read, Write},
    path::PathBuf,
    string::ToString,
    time::Instant,
    vec,
    vec::Vec,
};

const DEFAULT_UNIVERSAL_SRS_FILENAME: &str = "universal_srs";

/// Create and store universal parameter in a file.
///
/// **Only used for demo purposes, use more trust-worthy universal parameter
/// from MPC ceremony for production instead**
///
/// * `max_degree` - the upperbound for polynomial degree, please use
///   `utils::compute_universal_param_size` to calculate.
/// * `dest` - destination file path, save to default path if `None`.
pub fn store_universal_parameter_for_demo(
    max_degree: usize,
    dest: Option<PathBuf>,
) -> Result<(), TxnApiError> {
    let mut rng = ark_std::test_rng();
    let universal_param: UniversalParam = proof::universal_setup(max_degree, &mut rng)?;
    let dest = match dest {
        Some(dest) => dest,
        None => default_path(DEFAULT_UNIVERSAL_SRS_FILENAME, "bin"),
    };

    let now = Instant::now();
    eprint!(
        "Storing universal parameter to: {} ...",
        dest.to_str().unwrap()
    );
    store_data(&universal_param, dest)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(())
}

/// Load universal parameter from a file.
///
/// if `src` is `None`, load from default path.
pub fn load_universal_parameter(src: Option<PathBuf>) -> Result<UniversalParam, TxnApiError> {
    let src = match src {
        Some(src) => src,
        None => default_path(DEFAULT_UNIVERSAL_SRS_FILENAME, "bin"),
    };

    let now = Instant::now();
    eprint!(
        "Loading universal parameter from: {} ...",
        src.to_str().unwrap()
    );
    let param = load_data(src)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(param)
}

/// Create and store transfer prover's proving key
///
/// * `num_input` - number of input in the transfer note
/// * `num_output` - number of output in the transfer note
/// * `tree_depth` - depth of merkle tree for accumulating `RecordCommitment`
/// * `universal_param` - the universal parameter
/// * `dest` - destination file path, save to default path if `None`.
pub fn store_transfer_proving_key(
    num_input: usize,
    num_output: usize,
    tree_depth: u8,
    universal_param: &UniversalParam,
    dest: Option<PathBuf>,
) -> Result<(), TxnApiError> {
    let (proving_key, verifying_key, _) =
        transfer::preprocess(universal_param, num_input, num_output, tree_depth)?;

    {
        let dest = match dest.clone() {
            Some(dest) => dest,
            None => default_transfer_proving_key_path(num_input, num_output, tree_depth),
        };

        let now = Instant::now();
        eprint!(
            "Storing transfer proving key to: {} ...",
            dest.to_str().unwrap()
        );
        store_data(&proving_key, dest)?;
        eprintln!(" done in {} ms", now.elapsed().as_millis());
    }
    {
        // also store verifying key in a separate file
        let dest = match dest {
            Some(dest) => dest,
            None => default_transfer_verifying_key_path(num_input, num_output, tree_depth),
        };

        let now = Instant::now();
        eprint!(
            "Storing transfer verifying key to: {} ...",
            dest.to_str().unwrap()
        );
        store_data(&verifying_key, dest)?;
        eprintln!(" done in {} ms", now.elapsed().as_millis());
    }
    Ok(())
}

/// Load the transfer proving key from `src` file
///
/// if `src` is `None`, load from default path.
pub fn load_transfer_proving_key<'a>(
    num_input: usize,
    num_output: usize,
    tree_depth: u8,
    src: Option<PathBuf>,
) -> Result<TransferProvingKey<'a>, TxnApiError> {
    let src = match src {
        Some(dest) => dest,
        None => default_transfer_proving_key_path(num_input, num_output, tree_depth),
    };

    let now = Instant::now();
    eprint!(
        "Loading transfer proving key from: {} ...",
        src.to_str().unwrap()
    );
    let proving_key = load_data(src)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(proving_key)
}

/// Create and store transfer verifier's verifying key
///
/// NOTE: if you already have stored proving key of the same (num_input,
/// num_output, tree_depth), then you should also have a corresponding verifying
/// key file from which you can directly load the data.
///
/// * `num_input` - number of input in the transfer note
/// * `num_output` - number of output in the transfer note
/// * `tree_depth` - depth of merkle tree for accumulating `RecordCommitment`
/// * `universal_param` - the universal parameter
/// * `dest` - destination file path, save to default path if `None`.
pub fn store_transfer_verifying_key(
    num_input: usize,
    num_output: usize,
    tree_depth: u8,
    universal_param: &UniversalParam,
    dest: Option<PathBuf>,
) -> Result<(), TxnApiError> {
    let dest = match dest {
        Some(dest) => dest,
        None => default_transfer_verifying_key_path(num_input, num_output, tree_depth),
    };

    let (_, verifying_key, _) =
        transfer::preprocess(universal_param, num_input, num_output, tree_depth)?;

    let now = Instant::now();
    eprint!(
        "Storing transfer verifying key to: {} ...",
        dest.to_str().unwrap()
    );
    store_data(&verifying_key, dest)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(())
}

/// Load the transfer verifying key from `src` file
///
/// if `src` is `None`, load from default path.
pub fn load_transfer_verifying_key(
    num_input: usize,
    num_output: usize,
    tree_depth: u8,
    src: Option<PathBuf>,
) -> Result<TransferVerifyingKey, TxnApiError> {
    let src = match src {
        Some(dest) => dest,
        None => default_transfer_verifying_key_path(num_input, num_output, tree_depth),
    };

    let now = Instant::now();
    eprint!(
        "Loading transfer verifying key from: {} ...",
        src.to_str().unwrap()
    );
    let verifying_key = load_data(src)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(verifying_key)
}

/// Create and store mint prover's proving key
///
/// * `tree_depth` - depth of merkle tree for accumulating `RecordCommitment`
/// * `universal_param` - the universal parameter
/// * `dest` - destination file path, save to default path if `None`.
pub fn store_mint_proving_key(
    tree_depth: u8,
    universal_param: &UniversalParam,
    dest: Option<PathBuf>,
) -> Result<(), TxnApiError> {
    let (proving_key, verifying_key, _) = mint::preprocess(universal_param, tree_depth)?;

    {
        let dest = match dest.clone() {
            Some(dest) => dest,
            None => default_mint_proving_key_path(tree_depth),
        };

        let now = Instant::now();
        eprint!(
            "Storing mint proving key to: {} ...",
            dest.to_str().unwrap()
        );
        store_data(&proving_key, dest)?;
        eprintln!(" done in {} ms", now.elapsed().as_millis());
    }
    {
        // also store verifying key in a separate file
        let dest = match dest {
            Some(dest) => dest,
            None => default_mint_verifying_key_path(tree_depth),
        };

        let now = Instant::now();
        eprint!(
            "Storing mint verifying key to: {} ...",
            dest.to_str().unwrap()
        );
        store_data(&verifying_key, dest)?;
        eprintln!(" done in {} ms", now.elapsed().as_millis());
    }
    Ok(())
}

/// Load the mint proving key from `src` file
///
/// if `src` is `None`, load from default path.
pub fn load_mint_proving_key<'a>(
    tree_depth: u8,
    src: Option<PathBuf>,
) -> Result<MintProvingKey<'a>, TxnApiError> {
    let src = match src {
        Some(dest) => dest,
        None => default_mint_proving_key_path(tree_depth),
    };

    let now = Instant::now();
    eprint!(
        "Loading mint proving key from: {} ...",
        src.to_str().unwrap()
    );
    let proving_key = load_data(src)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(proving_key)
}

/// Create and store mint verifier's verifying key
///
/// NOTE: if you already have stored proving key of the same tree_depth, then
/// you should also have a corresponding verifying key file from which you can
/// directly load the data.
///
/// * `tree_depth` - depth of merkle tree for accumulating `RecordCommitment`
/// * `universal_param` - the universal parameter
/// * `dest` - destination file path, save to default path if `None`.
pub fn store_mint_verifying_key(
    tree_depth: u8,
    universal_param: &UniversalParam,
    dest: Option<PathBuf>,
) -> Result<(), TxnApiError> {
    let dest = match dest {
        Some(dest) => dest,
        None => default_mint_verifying_key_path(tree_depth),
    };

    let (_, verifying_key, _) = mint::preprocess(universal_param, tree_depth)?;

    let now = Instant::now();
    eprint!(
        "Storing mint verifying key to: {} ...",
        dest.to_str().unwrap()
    );
    store_data(&verifying_key, dest)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(())
}

/// Load the mint verifying key from `src` file
///
/// if `src` is `None`, load from default path.
pub fn load_mint_verifying_key(
    tree_depth: u8,
    src: Option<PathBuf>,
) -> Result<MintVerifyingKey, TxnApiError> {
    let src = match src {
        Some(dest) => dest,
        None => default_mint_verifying_key_path(tree_depth),
    };

    let now = Instant::now();
    eprint!(
        "Loading mint verifying key from: {} ...",
        src.to_str().unwrap()
    );
    let verifying_key = load_data(src)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(verifying_key)
}

/// Create and store freeze prover's proving key
///
/// * `num_input` - number of input in the transfer note
/// * `tree_depth` - depth of merkle tree for accumulating `RecordCommitment`
/// * `universal_param` - the universal parameter
/// * `dest` - destination file path, save to default path if `None`.
pub fn store_freeze_proving_key(
    num_input: usize,
    tree_depth: u8,
    universal_param: &UniversalParam,
    dest: Option<PathBuf>,
) -> Result<(), TxnApiError> {
    let (proving_key, verifying_key, _) =
        freeze::preprocess(universal_param, num_input, tree_depth)?;

    {
        let dest = match dest.clone() {
            Some(dest) => dest,
            None => default_freeze_proving_key_path(num_input, tree_depth),
        };

        let now = Instant::now();
        eprint!(
            "Storing freeze proving key to: {} ...",
            dest.to_str().unwrap()
        );
        store_data(&proving_key, dest)?;
        eprintln!(" done in {} ms", now.elapsed().as_millis());
    }
    {
        // also store verifying key in a separate file
        let dest = match dest {
            Some(dest) => dest,
            None => default_freeze_verifying_key_path(num_input, tree_depth),
        };

        let now = Instant::now();
        eprint!(
            "Storing freeze verifying key to: {} ...",
            dest.to_str().unwrap()
        );
        store_data(&verifying_key, dest)?;
        eprintln!(" done in {} ms", now.elapsed().as_millis());
    }
    Ok(())
}

/// Load the freeze proving key from `src` file
///
/// if `src` is `None`, load from default path.
pub fn load_freeze_proving_key<'a>(
    num_input: usize,
    tree_depth: u8,
    src: Option<PathBuf>,
) -> Result<FreezeProvingKey<'a>, TxnApiError> {
    let src = match src {
        Some(dest) => dest,
        None => default_freeze_proving_key_path(num_input, tree_depth),
    };

    let now = Instant::now();
    eprint!(
        "Loading freeze proving key from: {} ...",
        src.to_str().unwrap()
    );
    let proving_key = load_data(src)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(proving_key)
}

/// Create and store freeze verifier's verifying key
///
/// NOTE: if you already have stored proving key of the same (num_input,
/// tree_depth), then you should also have a corresponding verifying key file
/// from which you can directly load the data.
///
/// * `num_input` - number of input in the transfer note
/// * `tree_depth` - depth of merkle tree for accumulating `RecordCommitment`
/// * `universal_param` - the universal parameter
/// * `dest` - destination file path, save to default path if `None`.
pub fn store_freeze_verifying_key(
    num_input: usize,
    tree_depth: u8,
    universal_param: &UniversalParam,
    dest: Option<PathBuf>,
) -> Result<(), TxnApiError> {
    let dest = match dest {
        Some(dest) => dest,
        None => default_freeze_verifying_key_path(num_input, tree_depth),
    };

    let (_, verifying_key, _) = freeze::preprocess(universal_param, num_input, tree_depth)?;

    let now = Instant::now();
    eprint!(
        "Storing freeze verifying key to: {} ...",
        dest.to_str().unwrap()
    );
    store_data(&verifying_key, dest)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(())
}

/// Load the freeze verifying key from `src` file
///
/// if `src` is `None`, load from default path.
pub fn load_freeze_verifying_key(
    num_input: usize,
    tree_depth: u8,
    src: Option<PathBuf>,
) -> Result<FreezeVerifyingKey, TxnApiError> {
    let src = match src {
        Some(dest) => dest,
        None => default_freeze_verifying_key_path(num_input, tree_depth),
    };

    let now = Instant::now();
    eprint!(
        "Loading freeze verifying key from: {} ...",
        src.to_str().unwrap()
    );
    let verifying_key = load_data(src)?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(verifying_key)
}

// by default, all parameters are stored in `CURRENT_CARGO_ROOT/data/`
fn default_path(filename: &str, extension: &str) -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("data");
    d.push(filename);
    d.set_extension(extension);
    d
}

fn default_transfer_proving_key_path(
    num_input: usize,
    num_output: usize,
    tree_depth: u8,
) -> PathBuf {
    default_path(
        &format!(
            "transfer_prover_{}_input_{}_output_{}_depth",
            num_input, num_output, tree_depth
        ),
        "bin",
    )
}

fn default_mint_proving_key_path(tree_depth: u8) -> PathBuf {
    default_path(
        &format!("mint_prover_{}_input_{}_output_{}_depth", 1, 2, tree_depth),
        "bin",
    )
}

fn default_freeze_proving_key_path(num_input: usize, tree_depth: u8) -> PathBuf {
    default_path(
        &format!(
            "freeze_prover_{}_input_{}_output_{}_depth",
            num_input, num_input, tree_depth
        ),
        "bin",
    )
}

fn default_transfer_verifying_key_path(
    num_input: usize,
    num_output: usize,
    tree_depth: u8,
) -> PathBuf {
    default_path(
        &format!(
            "transfer_verifier_{}_input_{}_output_{}_depth",
            num_input, num_output, tree_depth
        ),
        "bin",
    )
}

fn default_mint_verifying_key_path(tree_depth: u8) -> PathBuf {
    default_path(
        &format!(
            "mint_verifier_{}_input_{}_output_{}_depth",
            1, 2, tree_depth
        ),
        "bin",
    )
}

fn default_freeze_verifying_key_path(num_input: usize, tree_depth: u8) -> PathBuf {
    default_path(
        &format!(
            "freeze_verifier_{}_input_{}_output_{}_depth",
            num_input, num_input, tree_depth
        ),
        "bin",
    )
}

// serialize any serde-Serializable data using `bincode` and store to `dest`
fn store_data<T>(data: &T, dest: PathBuf) -> Result<(), TxnApiError>
where
    T: CanonicalSerialize,
{
    let mut bytes = Vec::new();
    data.serialize(&mut bytes)?;
    store_bytes(&bytes, dest).map_err(|e| TxnApiError::IoError(e.to_string()))
}

// deserialize any serde-deserializable data using `bincode` from `src`
fn load_data<T>(src: PathBuf) -> Result<T, TxnApiError>
where
    T: CanonicalDeserialize,
{
    let bytes = load_bytes(src).map_err(|e| TxnApiError::IoError(e.to_string()))?;
    let data = T::deserialize(&bytes[..])?;
    Ok(data)
}

fn store_bytes(bytes: &[u8], dest: PathBuf) -> Result<(), IoError> {
    let mut f = ark_std::fs::File::create(dest)?;
    f.write_all(bytes)
}

fn load_bytes(src: PathBuf) -> Result<Vec<u8>, IoError> {
    let f = ark_std::fs::File::open(src)?;
    // maximum 8 KB of buffer for memory exhaustion protection for malicious file
    let mut reader = BufReader::with_capacity(8000, f);

    let mut bytes = vec![];
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{proof::universal_setup, structs::NoteType, utils::compute_universal_param_size};

    #[test]
    #[ignore = "expensive to run in CI, already tested locally"]
    fn store_and_load_for_universal_param() -> Result<(), TxnApiError> {
        let max_degree = compute_universal_param_size(NoteType::Transfer, 2, 2, 10)?;
        store_universal_parameter_for_demo(max_degree, None)?;
        load_universal_parameter(None)?;
        Ok(())
    }

    #[test]
    #[ignore = "expensive to run in CI, already tested locally"]
    fn store_and_load_for_transfer_prover_verifier() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let num_input = 2;
        let num_output = 5;
        let tree_depth = 10;
        let max_degree =
            compute_universal_param_size(NoteType::Transfer, num_input, num_output, tree_depth)?;
        let universal_param = universal_setup(max_degree, rng)?;

        store_transfer_proving_key(num_input, num_output, tree_depth, &universal_param, None)?;
        let proving_key = load_transfer_proving_key(num_input, num_output, tree_depth, None)?;
        assert_eq!(proving_key.n_inputs, num_input);
        assert_eq!(proving_key.n_outputs, num_output);
        assert_eq!(proving_key.tree_depth, tree_depth);

        let verifying_key = load_transfer_verifying_key(num_input, num_output, tree_depth, None)?;
        assert_eq!(verifying_key.n_inputs, num_input);
        assert_eq!(verifying_key.n_outputs, num_output);
        assert_eq!(verifying_key.tree_depth, tree_depth);
        Ok(())
    }

    #[test]
    #[ignore = "expensive to run in CI, already tested locally"]
    fn store_and_load_for_mint_prover_verifier() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let tree_depth = 10;
        let max_degree = compute_universal_param_size(NoteType::Mint, 1, 2, tree_depth)?;
        let universal_param = universal_setup(max_degree, rng)?;

        store_mint_proving_key(tree_depth, &universal_param, None)?;
        let proving_key = load_mint_proving_key(tree_depth, None)?;
        assert_eq!(proving_key.tree_depth, tree_depth);

        let verifying_key = load_mint_verifying_key(tree_depth, None)?;
        assert_eq!(verifying_key.tree_depth, tree_depth);
        Ok(())
    }

    #[test]
    #[ignore = "expensive to run in CI, already tested locally"]
    fn store_and_load_for_freeze_prover_verifier() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let tree_depth = 10;
        let num_inputs = 2;
        let max_degree =
            compute_universal_param_size(NoteType::Freeze, num_inputs, num_inputs, tree_depth)?;
        let universal_param = universal_setup(max_degree, rng)?;

        store_freeze_proving_key(num_inputs, tree_depth, &universal_param, None)?;
        let proving_key = load_freeze_proving_key(num_inputs, tree_depth, None)?;
        assert_eq!(proving_key.num_input, num_inputs);
        assert_eq!(proving_key.tree_depth, tree_depth);

        let verifying_key = load_freeze_verifying_key(num_inputs, tree_depth, None)?;
        assert_eq!(verifying_key.num_input, num_inputs);
        assert_eq!(verifying_key.tree_depth, tree_depth);
        Ok(())
    }
}
