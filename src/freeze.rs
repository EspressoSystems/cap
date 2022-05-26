// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Generation and verification of freezing transfer notes
use crate::{
    errors::TxnApiError,
    keys::FreezerKeyPair,
    proof::freeze::{
        self, FreezeProvingKey, FreezePublicInput, FreezeValidityProof, FreezeVerifyingKey,
        FreezeWitness,
    },
    structs::{Amount, AssetCode, Nullifier, RecordCommitment, RecordOpening, TxnFeeInfo},
    utils::txn_helpers::{freeze::*, *},
    AccMemberWitness, KeyPair, NodeValue, VerKey,
};
use ark_serialize::*;
use ark_std::{
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec::Vec,
};
use serde::{Deserialize, Serialize};

/// Freezing note structure
#[derive(
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct FreezeNote {
    /// nullifiers for freezing/fee inputs
    pub input_nullifiers: Vec<Nullifier>,
    /// generated output commitments
    pub output_commitments: Vec<RecordCommitment>,
    /// proof of freezing
    pub proof: FreezeValidityProof,
    /// Auxiliary information (merkle root, fee)
    pub aux_info: FreezeAuxInfo,
}

/// Auxiliary info of FreezeNote: includes merkle root and fee
#[derive(
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Clone,
)]
pub struct FreezeAuxInfo {
    /// Accumulator state
    pub merkle_root: NodeValue,
    /// proposed fee in native asset type for the transfer
    pub fee: Amount,
    /// Transaction memos signature verification key (usually used for signing
    /// receiver memos)
    pub txn_memo_ver_key: VerKey,
}

/// All necessary information for each freezing input record in the `FreezeNote`
/// generation.
#[derive(Debug, Clone)]
pub struct FreezeNoteInput<'fkp> {
    /// Record opening of the input record.
    pub ro: RecordOpening,
    /// Accumulator membership proof (namely the Merkle proof) of the record
    /// commitment.
    pub acc_member_witness: AccMemberWitness,
    /// Reference of the freezer's freezing key pair.
    pub keypair: &'fkp FreezerKeyPair,
}

impl FreezeNote {
    /// Generates a freezing note. (See "tests/examples.rs" for examples of
    /// use).
    /// * `rng` - Randomness generator
    /// * `inputs` - Freezing note inputs (**excluding fee record**)
    /// * `txn_fee_info` - Amount of transaction fee to pay, fee input record
    ///   and spending information
    /// and fee change output record opening.
    /// * `proving_key` - Prover parameters
    /// * `returns`- On success returns the freezing note, receiver memos,
    ///   signature on receiver memos, and vector of output record openings.
    /// On error return TxnApIError.
    pub fn generate<'a, R: CryptoRng + RngCore>(
        rng: &mut R,
        inputs: Vec<FreezeNoteInput<'a>>,
        txn_fee_info: TxnFeeInfo,
        proving_key: &FreezeProvingKey<'a>,
    ) -> Result<(Self, KeyPair, Vec<RecordOpening>), TxnApiError> {
        // 1. check input correctness
        check_inputs_len(inputs.len())?;
        check_proving_key_consistency(
            proving_key,
            inputs.len() + 1,
            txn_fee_info
                .fee_input
                .acc_member_witness
                .merkle_path
                .nodes
                .len() as u8,
        )?;
        let merkle_root = check_and_get_root(&txn_fee_info.fee_input, &inputs)?;
        check_freezing_policies_are_not_dummy(&inputs)?;
        check_fee(&txn_fee_info)?;
        let output_ros = get_output_ros(rng, &inputs);

        // 2. Sample signing key
        let signing_keypair = KeyPair::generate(rng);

        // 3. build public input and SNARK proof
        let fee_amount = txn_fee_info.fee_amount;
        let witness = FreezeWitness::new_unchecked(inputs, &output_ros, txn_fee_info);
        let public_input = FreezePublicInput::from_witness(&witness)?;
        check_distinct_input_nullifiers(&public_input.input_nullifiers)?;
        let proof = freeze::prove(
            rng,
            proving_key,
            &witness,
            &public_input,
            signing_keypair.ver_key_ref(),
        )?;

        // 4. build note
        let freeze_note = FreezeNote {
            input_nullifiers: public_input.input_nullifiers,
            output_commitments: public_input.output_commitments,
            proof,
            aux_info: FreezeAuxInfo {
                merkle_root,
                fee: fee_amount,
                txn_memo_ver_key: signing_keypair.ver_key(),
            },
        };

        Ok((freeze_note, signing_keypair, output_ros))
    }

    /// Freezing note verification method
    /// * `verifier_key` - Verification key
    /// * `merkle_root` - candidate state of the accumulator. It must match
    ///   note.aux_info.merkle_root, otherwise it returns
    ///   CustomError::TransferVerification Error.
    pub fn verify(
        &self,
        verifying_key: &FreezeVerifyingKey,
        merkle_root: NodeValue,
    ) -> Result<(), TxnApiError> {
        let pub_input = self.check_instance_and_get_public_input(merkle_root)?;
        freeze::verify(
            verifying_key,
            &pub_input,
            &self.proof,
            &self.aux_info.txn_memo_ver_key,
        )
    }

    /// Check the instance and obtain the public input
    /// * `merkle_root` - expected merkle root
    /// * `returns` - public input or error
    pub(crate) fn check_instance_and_get_public_input(
        &self,
        merkle_root: NodeValue,
    ) -> Result<FreezePublicInput, TxnApiError> {
        // check root consistency
        if merkle_root != self.aux_info.merkle_root {
            return Err(TxnApiError::FailedTransactionVerification(
                "Merkle root do not match".to_string(),
            ));
        }

        Ok(FreezePublicInput {
            merkle_root,
            native_asset_code: AssetCode::native(),
            fee: self.aux_info.fee,
            input_nullifiers: self.input_nullifiers.clone(),
            output_commitments: self.output_commitments.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        errors::TxnApiError,
        keys::{FreezerKeyPair, UserKeyPair},
        proof::{
            freeze::{self, FreezeProvingKey, FreezeVerifyingKey},
            universal_setup_for_staging,
        },
        sign_receiver_memos,
        structs::{Amount, AssetDefinition, AssetPolicy, FreezeFlag, ReceiverMemo},
        utils::params_builder::FreezeParamsBuilder,
        TransactionNote,
    };
    use ark_std::{vec, vec::Vec};
    use jf_primitives::{merkle_tree::NodeValue, signatures::schnorr};

    #[test]
    fn test_freeze_note() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let tree_depth = 6;
        let num_input = 3;
        let max_degree = 65538;
        let universal_param = universal_setup_for_staging(max_degree, rng)?;
        let (proving_key, verifying_key, _) =
            freeze::preprocess(&universal_param, num_input, tree_depth)?;

        let input_amounts = vec![Amount::from(20u64), Amount::from(30u64)];
        let fee_input_amount = Amount::from(10u64);
        let fee_keypair = UserKeyPair::generate(rng);
        let freeze_keypair = FreezerKeyPair::generate(rng);

        // ====================================
        // zero fee
        // ====================================
        let fee = Amount::from(0u64);

        let builder = FreezeParamsBuilder::new(
            tree_depth,
            &input_amounts,
            fee_input_amount,
            fee,
            &fee_keypair,
            vec![&freeze_keypair; 2],
        );

        assert!(test_freeze_note_helper(&builder, &proving_key, &verifying_key).is_ok());

        // ====================================
        // non-zero fee
        // ====================================
        let fee = Amount::from(5u64);

        let builder = FreezeParamsBuilder::new(
            tree_depth,
            &input_amounts,
            fee_input_amount,
            fee,
            &fee_keypair,
            vec![&freeze_keypair; 2],
        );

        assert!(test_freeze_note_helper(&builder, &proving_key, &verifying_key).is_ok());

        // ====================================
        // bad path
        // ====================================
        // bad proving key
        {
            let mut bad_proving_key = proving_key.clone();
            bad_proving_key.tree_depth = tree_depth + 1;
            assert!(builder.build_freeze_note(rng, &bad_proving_key).is_err());
            bad_proving_key.tree_depth = tree_depth - 1;
            assert!(builder.build_freeze_note(rng, &bad_proving_key).is_err());
            bad_proving_key.num_input = num_input + 1;
            assert!(builder.build_freeze_note(rng, &bad_proving_key).is_err());
            bad_proving_key.num_input = num_input - 1;
            assert!(builder.build_freeze_note(rng, &bad_proving_key).is_err());
        }

        // empty input
        {
            let mut bad_builder = builder.clone();
            bad_builder.inputs = vec![];
            assert!(bad_builder.build_freeze_note(rng, &proving_key).is_err());
        }

        // the fee input is not native asset definition.
        {
            let bad_builder = builder
                .clone()
                .update_fee_asset_def(AssetDefinition::rand_for_test(rng));
            assert!(bad_builder.build_freeze_note(rng, &proving_key).is_err());
        }

        // inconsistency roots
        {
            let mut bad_builder = builder.clone();
            bad_builder.inputs[1].acc_member_witness.root = NodeValue::default();
            assert!(bad_builder.build_freeze_note(rng, &proving_key).is_err());
        }

        // fee input amount < change amount
        {
            let bad_builder = builder
                .clone()
                .update_fee_input_amount(builder.fee - Amount::from(1u64));
            assert!(bad_builder.build_freeze_note(rng, &proving_key).is_err());
        }

        // the fee input is frozen
        {
            let bad_builder = builder.clone().update_fee_freeze_flag(FreezeFlag::Frozen);
            assert!(bad_builder.build_freeze_note(rng, &proving_key).is_err());
        }

        // dummy freezing policy
        {
            let bad_builder = builder
                .clone()
                .update_input_policy(1, AssetPolicy::default());
            assert!(bad_builder.build_freeze_note(rng, &proving_key).is_err());
        }
        Ok(())
    }

    fn test_freeze_note_helper(
        builder: &FreezeParamsBuilder,
        proving_key: &FreezeProvingKey,
        verifying_key: &FreezeVerifyingKey,
    ) -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();

        let (note, keypair, _fee_chg_ro, record_openings) =
            builder.build_freeze_note(rng, &proving_key)?;

        assert!(note
            .verify(&verifying_key, note.aux_info.merkle_root)
            .is_ok());
        assert!(note.verify(&verifying_key, NodeValue::default()).is_err());

        // note with wrong recv_memos_ver_key should fail
        let mut wrong_note = note.clone();
        wrong_note.aux_info.txn_memo_ver_key = schnorr::KeyPair::generate(rng).ver_key();
        assert!(wrong_note
            .verify(&verifying_key, wrong_note.aux_info.merkle_root)
            .is_err());

        // test receiver memos signature
        let txn: TransactionNote = note.into();
        let recv_memos: Vec<_> = record_openings
            .iter()
            .map(|ro| ReceiverMemo::from_ro(rng, ro, &[]).unwrap())
            .collect();
        let sig = sign_receiver_memos(&keypair, &recv_memos).unwrap();
        assert!(txn
            .verify_receiver_memos_signature(&recv_memos, &sig)
            .is_ok());

        Ok(())
    }
}
