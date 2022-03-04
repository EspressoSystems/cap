// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! This file implements various wrappers of internal functions and structs.
//! It exposes those APIs under `test_apis` feature.
//! The functions and structs in this file should not be used for other
//! purposes.

#![allow(missing_docs)]

use crate::{
    errors::TxnApiError,
    proof::{self, freeze::FreezeVerifyingKey, transfer::TransferVerifyingKey, UniversalParam},
    structs::{AssetCode, AuditMemo, Nullifier, RecordCommitment},
    transfer::TransferNote,
    BaseField, MintVerifyingKey, PairingEngine,
};
use ark_std::vec::Vec;
use jf_plonk::proof_system::structs::VerifyingKey;
use jf_primitives::merkle_tree::NodeValue;
use rand::{CryptoRng, RngCore};

impl MintVerifyingKey {
    /// Expose the verifying key
    pub fn get_verifying_key(&self) -> VerifyingKey<PairingEngine> {
        self.verifying_key.clone()
    }
}

impl TransferVerifyingKey {
    /// Expose the verifying key
    pub fn get_verifying_key(&self) -> VerifyingKey<PairingEngine> {
        self.verifying_key.clone()
    }
}

impl FreezeVerifyingKey {
    /// Expose the verifying key
    pub fn get_verifying_key(&self) -> VerifyingKey<PairingEngine> {
        self.verifying_key.clone()
    }
}

/// load Aztec's universal setup CRS for testing
pub fn universal_setup_for_test<R: RngCore + CryptoRng>(
    max_degree: usize,
    rng: &mut R,
) -> Result<UniversalParam, TxnApiError> {
    proof::universal_setup_for_test(max_degree, rng)
}

/// Public inputs of a transfer transaction
#[derive(Debug, Clone)]
/// Struct for the public input of a transfer witness
pub struct TransferPublicInput {
    pub merkle_root: NodeValue<BaseField>,
    pub native_asset_code: AssetCode,
    pub valid_until: u64,
    pub fee: u64,
    pub input_nullifiers: Vec<Nullifier>,
    pub output_commitments: Vec<RecordCommitment>,
    pub audit_memo: AuditMemo,
}

impl From<TransferPublicInput> for proof::transfer::TransferPublicInput {
    fn from(other: TransferPublicInput) -> Self {
        Self {
            merkle_root: other.merkle_root,
            native_asset_code: other.native_asset_code,
            valid_until: other.valid_until,
            fee: other.fee,
            input_nullifiers: other.input_nullifiers,
            output_commitments: other.output_commitments,
            audit_memo: other.audit_memo,
        }
    }
}

impl From<proof::transfer::TransferPublicInput> for TransferPublicInput {
    fn from(other: proof::transfer::TransferPublicInput) -> Self {
        Self {
            merkle_root: other.merkle_root,
            native_asset_code: other.native_asset_code,
            valid_until: other.valid_until,
            fee: other.fee,
            input_nullifiers: other.input_nullifiers,
            output_commitments: other.output_commitments,
            audit_memo: other.audit_memo,
        }
    }
}

impl TransferNote {
    /// Anonymous transfer note verification method
    /// * `merkle_root` - candidate state of the accumulator. It must match
    ///   note.aux_info.merkle_root, otherwise it returns
    ///   CustomError::TransferVerification Error.
    /// * `timestamp` - current timestamp
    pub fn check_instance_and_get_public_input(
        &self,
        merkle_root: NodeValue<BaseField>,
        timestamp: u64,
    ) -> Result<TransferPublicInput, TxnApiError> {
        Ok(self
            .check_instance_and_get_public_input_internal(merkle_root, timestamp)?
            .into())
    }
}
