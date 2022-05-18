// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! This module contains functions and data structures for
//! * Computing the public parameters
//! * Computing a Freezing proof
//! * Verifying a Freezing proof

use crate::{
    circuit::freeze::FreezeCircuit,
    errors::TxnApiError,
    freeze::FreezeNoteInput,
    keys::{FreezerKeyPair, FreezerPubKey, UserKeyPair},
    proof::UniversalParam,
    structs::{Amount, AssetCode, Nullifier, RecordCommitment, RecordOpening, TxnFeeInfo},
    AccMemberWitness, BaseField, MerkleTree, NodeValue, PairingEngine, VerKey,
};
use ark_serialize::*;
use ark_std::{format, string::ToString, vec, vec::Vec};
use jf_plonk::{
    circuit::Circuit,
    proof_system::{
        structs::{Proof, ProvingKey, VerifyingKey},
        PlonkKzgSnark, Snark,
    },
    transcript::SolidityTranscript,
};
use jf_utils::{deserialize_canonical_bytes, CanonicalBytes};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Key for proving the validity of a Freeze note during asset freezing.
#[derive(
    Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(from = "CanonicalBytes", into = "CanonicalBytes")]
pub struct FreezeProvingKey<'a> {
    pub(crate) proving_key: ProvingKey<'a, PairingEngine>,
    pub(crate) tree_depth: u8,
    pub(crate) num_input: usize,
}
deserialize_canonical_bytes!(FreezeProvingKey<'a>);

impl<'a> FreezeProvingKey<'a> {
    /// Getter for number of input (fee input included)
    pub fn num_input(&self) -> usize {
        self.num_input
    }

    /// Getter for number of output (fee change output included)
    pub fn num_output(&self) -> usize {
        self.num_input
    }
}
/// Key for verifying the validity of a Freeze note during asset freezing.
#[derive(
    Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(from = "CanonicalBytes", into = "CanonicalBytes")]
pub struct FreezeVerifyingKey {
    pub(crate) verifying_key: VerifyingKey<PairingEngine>,
    pub(crate) tree_depth: u8,
    pub(crate) num_input: usize,
}
deserialize_canonical_bytes!(FreezeVerifyingKey);

impl FreezeVerifyingKey {
    /// Getter for number of input (fee input included)
    pub fn num_input(&self) -> usize {
        self.num_input
    }

    /// Getter for number of output (fee change output included)
    pub fn num_output(&self) -> usize {
        self.num_input
    }
}

/// Proof associated to a Freeze note
pub type FreezeValidityProof = Proof<PairingEngine>;

/// One-time preprocess of the Freezing transaction circuit, proving key and
/// verifying key should be reused for proving/verifying future instances of
/// asset freezing transaction.
pub fn preprocess(
    srs: &UniversalParam,
    num_input: usize,
    tree_depth: u8,
) -> Result<(FreezeProvingKey, FreezeVerifyingKey, usize), TxnApiError> {
    let (dummy_circuit, n_constraints) =
        FreezeCircuit::build_for_preprocessing(tree_depth, num_input)?;

    let (proving_key, verifying_key) =
        PlonkKzgSnark::<PairingEngine>::preprocess(srs, &dummy_circuit.0).map_err(|e| {
            TxnApiError::FailedSnark(format!(
                "Preprocessing Freeze circuit of {}-depth {}-inputs failed: {}",
                tree_depth, num_input, e
            ))
        })?;
    Ok((
        FreezeProvingKey {
            proving_key,
            tree_depth,
            num_input,
        },
        FreezeVerifyingKey {
            verifying_key,
            tree_depth,
            num_input,
        },
        n_constraints,
    ))
}

/// Generate a transaction validity proof (a zk-SNARK proof) given the witness
/// and the proving key.
pub(crate) fn prove<R>(
    rng: &mut R,
    proving_key: &FreezeProvingKey,
    witness: &FreezeWitness,
    pub_input: &FreezePublicInput,
    txn_memo_ver_key: &VerKey,
) -> Result<FreezeValidityProof, TxnApiError>
where
    R: RngCore + CryptoRng,
{
    let (circuit, _) = FreezeCircuit::build(witness, pub_input)
        .map_err(|e| TxnApiError::FailedSnark(format!("Failed to build Freeze circuit: {}", e)))?;

    circuit
        .0
        .check_circuit_satisfiability(&pub_input.to_scalars())
        .map_err(|e| {
            TxnApiError::FailedSnark(format!(
                "Freeze Proof Creation failure, circuit is not satisfied: {:?}",
                e
            ))
        })?;

    let mut ext_msg = Vec::new();
    CanonicalSerialize::serialize(txn_memo_ver_key, &mut ext_msg)?;

    PlonkKzgSnark::<PairingEngine>::prove::<_, _, SolidityTranscript>(
        rng,
        &circuit.0,
        &proving_key.proving_key,
        Some(ext_msg),
    )
    .map_err(|e| TxnApiError::FailedSnark(format!("Freeze Proof creation failure: {:?}", e)))
}

/// Verify a transaction validity proof given the public inputs and verifying
/// key.
pub(crate) fn verify(
    verifying_key: &FreezeVerifyingKey,
    public_inputs: &FreezePublicInput,
    proof: &FreezeValidityProof,
    recv_memos_ver_key: &VerKey,
) -> Result<(), TxnApiError> {
    let mut ext_msg = Vec::new();
    CanonicalSerialize::serialize(recv_memos_ver_key, &mut ext_msg)?;
    PlonkKzgSnark::<PairingEngine>::verify::<SolidityTranscript>(
        &verifying_key.verifying_key,
        &public_inputs.to_scalars(),
        proof,
        Some(ext_msg),
    )
    .map_err(|e| TxnApiError::FailedSnark(format!("Freeze Proof verification failure: {}", e)))?;
    Ok(())
}

#[derive(Debug, Clone)]
/// Witness for a Freeze note
pub(crate) struct FreezeWitness<'a> {
    pub(crate) input_ros: Vec<RecordOpening>,
    pub(crate) input_acc_member_witnesses: Vec<AccMemberWitness>,
    pub(crate) output_ros: Vec<RecordOpening>,
    pub(crate) fee_keypair: &'a UserKeyPair,
    pub(crate) freezing_keypairs: Vec<&'a FreezerKeyPair>,
}

impl<'a> FreezeWitness<'a> {
    pub(crate) fn dummy(
        tree_depth: u8,
        num_input: usize,
        fee_keypair: &'a UserKeyPair,
        freezing_keypair: &'a FreezerKeyPair,
    ) -> Self {
        let input_ros = vec![RecordOpening::default(); num_input];
        let mut mt = MerkleTree::new(tree_depth).unwrap();
        input_ros
            .iter()
            .for_each(|ro| mt.push(ro.derive_record_commitment().to_field_element()));
        let input_acc_member_witnesses: Vec<AccMemberWitness> = (0..num_input)
            .map(|uid| {
                AccMemberWitness::lookup_from_tree(&mt, uid as u64)
                    .expect_ok().unwrap() // safe unwrap()
                    .1
            })
            .collect();
        Self {
            input_ros,
            input_acc_member_witnesses,
            output_ros: vec![RecordOpening::default(); num_input],
            fee_keypair,
            freezing_keypairs: vec![freezing_keypair; num_input - 1],
        }
    }

    pub(crate) fn new_unchecked(
        inputs: Vec<FreezeNoteInput<'a>>,
        output_ros: &[RecordOpening],
        txn_fee_info: TxnFeeInfo<'a>,
    ) -> Self {
        let (mut input_ros, mut input_acc_member_witnesses) = (
            vec![txn_fee_info.fee_input.ro],
            vec![txn_fee_info.fee_input.acc_member_witness],
        );
        let mut freezing_keypairs = vec![];
        for input in inputs.into_iter() {
            input_ros.push(input.ro);
            input_acc_member_witnesses.push(input.acc_member_witness);
            freezing_keypairs.push(input.keypair);
        }
        let mut out_ros = vec![txn_fee_info.fee_chg_ro];
        out_ros.extend_from_slice(output_ros);
        Self {
            input_ros,
            input_acc_member_witnesses,
            output_ros: out_ros,
            fee_keypair: txn_fee_info.fee_input.owner_keypair,
            freezing_keypairs,
        }
    }
}

#[derive(Debug, Clone)]
/// Struct for the public input of a freeze witness
pub(crate) struct FreezePublicInput {
    pub(crate) merkle_root: NodeValue,
    pub(crate) native_asset_code: AssetCode,
    pub(crate) fee: Amount,
    pub(crate) input_nullifiers: Vec<Nullifier>,
    pub(crate) output_commitments: Vec<RecordCommitment>,
}

impl FreezePublicInput {
    /// Compute the public input from witness and ledger info
    pub(crate) fn from_witness(witness: &FreezeWitness) -> Result<Self, TxnApiError> {
        if witness.input_ros.len() <= 1 {
            return Err(TxnApiError::InvalidParameter(
                "freezing: the freezing inputs (excluding fee input) should be non-empty"
                    .to_string(),
            ));
        }
        if witness.input_ros.len() != witness.output_ros.len() {
            return Err(TxnApiError::InvalidParameter(
                "freezing: the number of inputs and outputs should be identical".to_string(),
            ));
        }
        if witness.input_ros.len() != witness.freezing_keypairs.len() + 1 {
            return Err(TxnApiError::InvalidParameter(
                "freezing: the number of inputs should be the number of freezing keypairs + 1"
                    .to_string(),
            ));
        }
        if witness.input_ros[0].amount < witness.output_ros[0].amount {
            return Err(TxnApiError::InvalidParameter(
                "freezing: the change amount is larger than the input amount for fee".to_string(),
            ));
        }
        if witness.input_ros.len() != witness.input_acc_member_witnesses.len() {
            return Err(TxnApiError::InvalidParameter(
                "the number of freezing input ros and acc_member_witnesses should be identical"
                    .to_string(),
            ));
        }
        let merkle_root = witness.input_acc_member_witnesses[0].root;
        let input_nullifiers = witness
            .input_ros
            .iter()
            .zip(witness.input_acc_member_witnesses.iter())
            .enumerate()
            .map(|(i, (ro, acc_wit))| {
                let comm = ro.derive_record_commitment();
                if i == 0 {
                    witness.fee_keypair.nullify(
                        &FreezerPubKey::default(),
                        acc_wit.uid as u64,
                        &comm,
                    )
                } else {
                    witness.freezing_keypairs[i - 1].nullify(
                        &ro.pub_key.address(),
                        acc_wit.uid as u64,
                        &comm,
                    )
                }
            })
            .collect();

        let output_commitments = witness
            .output_ros
            .iter()
            .map(RecordCommitment::from)
            .collect();

        Ok(Self {
            merkle_root,
            native_asset_code: AssetCode::native(),
            fee: witness.input_ros[0].amount - witness.output_ros[0].amount,
            input_nullifiers,
            output_commitments,
        })
    }

    /// Flatten out all pubic input fields into a vector of BaseFields.
    /// Note that the order matters.
    /// TODO: check order consistency with `FreezePubInputVar`.
    pub(crate) fn to_scalars(&self) -> Vec<BaseField> {
        let mut result = vec![
            self.merkle_root.to_scalar(),
            self.native_asset_code.0,
            BaseField::from(self.fee.0),
        ];
        for nullifier in &self.input_nullifiers {
            result.push(nullifier.0);
        }
        for comm in &self.output_commitments {
            result.push(comm.0);
        }
        result
    }
}

#[cfg(test)]
mod test {
    use super::FreezePublicInput;
    use crate::{
        errors::TxnApiError,
        keys::{FreezerKeyPair, UserKeyPair},
        proof::{freeze, universal_setup_for_staging},
        structs::Amount,
        utils::params_builder::FreezeParamsBuilder,
        KeyPair,
    };
    use ark_std::vec;
    use rand::{Rng, RngCore};

    #[test]
    fn test_pub_input_creation() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let fee_keypair = UserKeyPair::generate(rng);
        let freezing_keypair = FreezerKeyPair::generate(rng);
        let input_amounts = vec![Amount(20), Amount(30)];
        let fee_input_amount = Amount(10);
        let fee = Amount(5);
        let builder = FreezeParamsBuilder::new(
            2,
            &input_amounts,
            fee_input_amount,
            fee,
            &fee_keypair,
            vec![&freezing_keypair; 2],
        );
        let mut witness = builder.build_witness();
        assert!(
            FreezePublicInput::from_witness(&witness).is_ok(),
            "create public input from correct witness should succeed"
        );

        // different number of inputs and outputs
        witness.input_ros.pop();
        witness.input_acc_member_witnesses.pop();
        assert!(
            FreezePublicInput::from_witness(&witness).is_err(),
            "create public input from wrong witness with different number of inputs/outputs should fail"
        );

        // different number of input_ros and acc_member_witness
        witness.input_acc_member_witnesses.pop();
        witness.output_ros.pop();
        assert!(
            FreezePublicInput::from_witness(&witness).is_err(),
            "create public input from wrong witness with different number of input ros/acc_member_witness should fail"
        );

        // empty freezing input
        witness.input_ros = witness.input_ros[..1].to_vec();
        witness.output_ros = witness.output_ros[..1].to_vec();
        witness.input_acc_member_witnesses = witness.input_acc_member_witnesses[..1].to_vec();
        assert!(
            FreezePublicInput::from_witness(&witness).is_err(),
            "create public input from wrong witness with empty freezing inputs should fail"
        );

        // negative fee
        let bad_fee = fee_input_amount + Amount(2);
        let builder = FreezeParamsBuilder::new(
            2,
            &input_amounts,
            fee_input_amount,
            fee_input_amount,
            &fee_keypair,
            vec![&freezing_keypair; 2],
        );
        let mut witness = builder.build_witness();
        witness.output_ros[0].amount = bad_fee;
        assert!(
            FreezePublicInput::from_witness(&witness).is_err(),
            "create public input from wrong witness with negative fee should fail"
        );

        Ok(())
    }

    #[test]
    fn test_freeze_validity_proof() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let tree_depth = 6;
        let num_input = 3;
        let max_degree = 65538;
        let universal_param = universal_setup_for_staging(max_degree, rng)?;
        let (proving_key, verifying_key, _) =
            freeze::preprocess(&universal_param, num_input, tree_depth)?;

        let input_amounts = vec![Amount(20), Amount(30)];
        let fee_input_amount = Amount(10);
        let fee = Amount(5);
        let fee_keypair = UserKeyPair::generate(rng);
        let freeze_keypair = FreezerKeyPair::generate(rng);
        let recv_memos_ver_key = KeyPair::generate(rng).ver_key();

        let builder = FreezeParamsBuilder::new(
            tree_depth,
            &input_amounts,
            fee_input_amount,
            fee,
            &fee_keypair,
            vec![&freeze_keypair; 2],
        );
        let (witness, pub_input_1) = builder.build_witness_and_public_input();
        let validity_proof_1 = freeze::prove(
            rng,
            &proving_key,
            &witness,
            &pub_input_1,
            &recv_memos_ver_key,
        )?;
        assert!(freeze::verify(
            &verifying_key,
            &pub_input_1,
            &validity_proof_1,
            &recv_memos_ver_key,
        )
        .is_ok());

        // another instance
        let fee_input_amount = Amount(rng.next_u64() as u128);
        let amounts_2 = Amount(rng.next_u32() as u128);
        let amounts_3 = Amount(rng.next_u32() as u128);
        let fee = Amount(rng.gen_range(1..fee_input_amount.0));
        let fee_keypair = UserKeyPair::generate(rng);
        let freeze_keypair = FreezerKeyPair::generate(rng);
        let builder = FreezeParamsBuilder::new(
            tree_depth,
            &[amounts_2, amounts_3],
            fee_input_amount,
            fee,
            &fee_keypair,
            vec![&freeze_keypair; 2],
        );
        let (witness, pub_input_2) = builder.build_witness_and_public_input();
        let validity_proof_2 = freeze::prove(
            rng,
            &proving_key,
            &witness,
            &pub_input_2,
            &recv_memos_ver_key,
        )?;
        assert!(freeze::verify(
            &verifying_key,
            &pub_input_2,
            &validity_proof_2,
            &recv_memos_ver_key,
        )
        .is_ok());

        // bad paths
        assert!(freeze::verify(
            &verifying_key,
            &pub_input_1,
            &validity_proof_2,
            &recv_memos_ver_key,
        )
        .is_err());
        assert!(freeze::verify(
            &verifying_key,
            &pub_input_2,
            &validity_proof_1,
            &recv_memos_ver_key,
        )
        .is_err());
        let (_, bad_verifying_key, _) = freeze::preprocess(&universal_param, 2, 1)?;
        assert!(freeze::verify(
            &bad_verifying_key,
            &pub_input_1,
            &validity_proof_1,
            &recv_memos_ver_key,
        )
        .is_err());
        // wrong receiver memo ver key
        assert!(freeze::verify(
            &verifying_key,
            &pub_input_1,
            &validity_proof_1,
            &KeyPair::generate(rng).ver_key(),
        )
        .is_err());

        Ok(())
    }
}
