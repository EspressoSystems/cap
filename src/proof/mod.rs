// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! SNARK proofs data structures, generation and verification API
//!
//! # How to use proof-related API
//! ```ignore
//! use crate::proof;
//! use crate::proof::transfer::{self, TransferWitness, TransferPublicInput};
//! use crate::utils::compute_universal_param_size,
//! use crate::structs::NoteType;
//!
//! let rng = &mut ark_std::test_rng();
//!
//! let num_input = 3;
//! let num_output = 3;
//! let depth = 30;
//! let max_degree = compute_universal_param_size(NoteType::Transfer, num_input, num_output, depth).unwrap();
//! // Step 1. Get universal parameters for all types of transaction
//! let universal_param = proof::universal_setup(max_degree, rng).unwrap();
//!
//! // Step 2. Preprocess for specific transaction type (e.g. Transfer)
//! let (proving_key, verifying_key) =
//!   transfer::preprocess(rng, &universal_param, num_input, num_output, depth).unwrap();
//!
//! // Step 3. Prover generate valid proof
//! let witness = TransferWitness::new_unchecked(...);
//! let public_inputs = TransferPublicInput::from_witness(&witness, ...);
//! let validity_proof = transfer::prove(rng, &proving_key, &witness, &public_inputs).unwrap();
//!
//! // Step 4. Verifier verifies the proof
//! assert_eq!(transfer::verify(&verifying_key, &public_inputs, &validity_proof).unwrap(), true);
//! ```

pub mod freeze;
pub mod mint;
pub mod transfer;

use crate::{errors::TxnApiError, prelude::CapConfig};
use ark_std::{
    rand::{CryptoRng, RngCore},
    string::ToString,
};
use jf_plonk::proof_system::{structs::UniversalSrs, UniversalSNARK};

/// One-time universal setup for parameters to be used in proving validity of
/// all transactions, regardless of the transaction type.
///
/// NOTE: this API is reserved for production usage. For now, in testing or
/// staging environment, please use `universal_setup_for_test()` instead!
pub fn universal_setup<R: RngCore + CryptoRng, C: CapConfig>(
    max_degree: usize,
    rng: &mut R,
) -> Result<UniversalSrs<C::PairingCurve>, TxnApiError> {
    use jf_plonk::proof_system::PlonkKzgSnark;

    // either pass degree upperbound as an input parameter
    // or directly access a fixed constant
    PlonkKzgSnark::<C::PairingCurve>::universal_setup(max_degree, rng)
        .map_err(|_| TxnApiError::FailedSnark("Failed to generate universal SRS".to_string()))
}

/// Use Common Reference String parameters from Aztec's MPC ceremony in proving
/// validity of all transactions, regardless of the transaction type.
#[cfg(feature = "bn254")]
pub fn load_srs<C: CapConfig>(
    max_degree: usize,
) -> Result<UniversalSrs<C::PairingCurve>, TxnApiError> {
    use hex_literal::hex;
    use sha2::{Digest, Sha256};

    use ark_serialize::CanonicalDeserialize;
    use ark_std::{eprint, eprintln};

    if max_degree > 2usize.pow(17) {
        return Err(TxnApiError::FailedSnark(
            "Currently only supports 2^17. Please update Aztec's CRS data file if needed."
                .to_string(),
        ));
    }

    let src = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/aztec-crs-131072.bin"
    ));

    // check integrity of the bin file
    let mut hasher = Sha256::new();
    hasher.update(src);
    assert_eq!(
        hasher.finalize()[..],
        hex!("6b81e75fb9c14fd0e58fb2b29e48978cdad5511503685a61f1391dc4a4fc7cbf")[..],
        "Mismatched sha256sum digest, file might be corrupted!"
    );

    let now = ark_std::time::Instant::now();
    eprint!("Unpacking universal parameters...");
    let ret = <_>::deserialize(&src[..])?;
    eprintln!(" done in {} ms", now.elapsed().as_millis());
    Ok(ret)
}

// add two test helper functions with uniformed API
/// load Aztec's universal setup CRS
#[cfg(feature = "bn254")]
/// A unified API for SRS generation for testing/staging environment.
///
/// # Feature Flags
/// - `feature("bn254")`: by default, we load SRS from Aztec's Ignition
///   Ceremony.
/// - otherwise: we generates fresh SRS on the spot (not secure for production
///   use! toxic waste not thrown away).
pub fn universal_setup_for_staging<R: RngCore + CryptoRng, C: CapConfig>(
    max_degree: usize,
    _rng: &mut R,
) -> Result<UniversalSrs<C::PairingCurve>, TxnApiError> {
    load_srs::<C>(max_degree)
}

#[cfg(not(feature = "bn254"))]
/// A unified API for SRS generation for testing/staging environment.
///
/// # Feature Flags
/// - `feature("bn254")`: by default, we load SRS from Aztec's Ignition
///   Ceremony.
/// - otherwise: we generates fresh SRS on the spot (not secure for production
///   use! toxic waste not thrown away).
pub fn universal_setup_for_staging<R: RngCore + CryptoRng, C: CapConfig>(
    max_degree: usize,
    rng: &mut R,
) -> Result<UniversalSrs<C::PairingCurve>, TxnApiError> {
    universal_setup::<R, C>(max_degree, rng)
}
