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
//! * Computing a Transfer proof
//! * Verifying a Transfer proof

use crate::{
    circuit::transfer::TransferCircuit,
    errors::TxnApiError,
    keys::{CredIssuerPubKey, UserKeyPair},
    prelude::CapConfig,
    structs::{
        Amount, AssetCode, AssetDefinition, ExpirableCredential, Nullifier, RecordCommitment,
        RecordOpening, ViewableMemo,
    },
    transfer::TransferNoteInput,
    utils::safe_sum_amount,
};
use ark_serialize::*;
use ark_std::{
    borrow::ToOwned,
    format,
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
    UniformRand,
};
use jf_plonk::{
    circuit::Circuit,
    proof_system::{
        structs::{Proof, ProvingKey, UniversalSrs, VerifyingKey},
        PlonkKzgSnark, UniversalSNARK,
    },
    transcript::SolidityTranscript,
};
use jf_primitives::{
    merkle_tree::{AccMemberWitness, MerklePath, MerklePathNode, MerkleTree, NodeValue},
    signatures::schnorr,
};
use jf_utils::{deserialize_canonical_bytes, CanonicalBytes};
use serde::{Deserialize, Serialize};

/// Key for computing the proof associated to a Transfer note
#[derive(
    Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(from = "CanonicalBytes", into = "CanonicalBytes")]
pub struct TransferProvingKey<C: CapConfig> {
    pub(crate) proving_key: ProvingKey<C::PairingCurve>,
    pub(crate) n_inputs: usize,
    pub(crate) n_outputs: usize,
    pub(crate) tree_depth: u8,
}
deserialize_canonical_bytes!(TransferProvingKey<C: CapConfig>);

impl<C: CapConfig> TransferProvingKey<C> {
    /// Getter for number of input (fee input included)
    pub fn num_input(&self) -> usize {
        self.n_inputs
    }

    /// Getter for number of output (fee change output included)
    pub fn num_output(&self) -> usize {
        self.n_outputs
    }
}

/// Key for verifying a Transfer note
#[derive(
    Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(from = "CanonicalBytes", into = "CanonicalBytes")]
/// Verifying key of Transfer note and its attributes
/// (n_inputs,n_outputs,tree_depth)
pub struct TransferVerifyingKey<C: CapConfig> {
    /// SNARK verification key
    pub verifying_key: VerifyingKey<C::PairingCurve>,
    /// num of inputs (incl. fee input)
    pub n_inputs: usize,
    /// num of outputs (incl. fee change output)
    pub n_outputs: usize,
    /// record merkle tree depth
    pub tree_depth: u8,
}
deserialize_canonical_bytes!(TransferVerifyingKey<C: CapConfig>);

impl<C: CapConfig> TransferVerifyingKey<C> {
    /// Getter for number of input (fee input included)
    pub fn num_input(&self) -> usize {
        self.n_inputs
    }

    /// Getter for number of output (fee change output included)
    pub fn num_output(&self) -> usize {
        self.n_outputs
    }
}

impl<C: CapConfig> From<&TransferProvingKey<C>> for TransferVerifyingKey<C> {
    fn from(pk: &TransferProvingKey<C>) -> Self {
        Self {
            verifying_key: pk.proving_key.vk.clone(),
            n_inputs: pk.n_inputs,
            n_outputs: pk.n_outputs,
            tree_depth: pk.tree_depth,
        }
    }
}

/// One-time preprocess of the Transfer transaction circuit, proving key and
/// verifying key should be reused for proving/verifying future instances of
/// transfer transaction.
pub fn preprocess<C: CapConfig>(
    srs: &UniversalSrs<C::PairingCurve>,
    n_inputs: usize,
    n_outputs: usize,
    tree_depth: u8,
) -> Result<(TransferProvingKey<C>, TransferVerifyingKey<C>, usize), TxnApiError> {
    let (dummy_circuit, n_constraints) =
        TransferCircuit::<C>::build_for_preprocessing(n_inputs, n_outputs, tree_depth)?;
    let (proving_key, verifying_key) =
        PlonkKzgSnark::<C::PairingCurve>::preprocess(srs, &dummy_circuit.0).map_err(|e| {
            TxnApiError::FailedSnark(format!(
                "Preprocessing Transfer circuit of {}-in-{}-out-{}-depth failed: {:?}",
                n_inputs, n_outputs, tree_depth, e
            ))
        })?;

    let transfer_proving_key = TransferProvingKey {
        proving_key,
        n_inputs,
        n_outputs,
        tree_depth,
    };

    let transfer_verifying_key = TransferVerifyingKey {
        verifying_key,
        n_inputs,
        n_outputs,
        tree_depth,
    };

    Ok((transfer_proving_key, transfer_verifying_key, n_constraints))
}

/// Generate a transaction validity proof (a zk-SNARK proof) given the witness
/// , public inputs, and the proving key.
pub(crate) fn prove<R: RngCore + CryptoRng, C: CapConfig>(
    rng: &mut R,
    transfer_proving_key: &TransferProvingKey<C>,
    witness: &TransferWitness<C>,
    public_inputs: &TransferPublicInput<C>,
    txn_memo_ver_key: &schnorr::VerKey<C::EmbeddedCurveParam>,
    extra_proof_bound_data: &[u8],
) -> Result<Proof<C::PairingCurve>, TxnApiError> {
    let (circuit, _) = TransferCircuit::build(witness, public_inputs)
        .map_err(|e| TxnApiError::FailedSnark(format!("{:?}", e)))?;
    circuit
        .0
        .check_circuit_satisfiability(&public_inputs.to_scalars())
        .map_err(|e| {
            TxnApiError::FailedSnark(format!(
                "Transfer Proof Creation failure, circuit is not satisfied: {:?}",
                e
            ))
        })?;
    let mut ext_msg = Vec::new();
    CanonicalSerialize::serialize(txn_memo_ver_key, &mut ext_msg)?;
    ext_msg.extend_from_slice(extra_proof_bound_data);
    PlonkKzgSnark::<C::PairingCurve>::prove::<_, _, SolidityTranscript>(
        rng,
        &circuit.0,
        &transfer_proving_key.proving_key,
        Some(ext_msg),
    )
    .map_err(|e| TxnApiError::FailedSnark(format!("Transfer Proof Creation failure: {:?}", e)))
}

/// Verify a transaction validity proof given the public inputs and verifying
/// key.
pub(crate) fn verify<C: CapConfig>(
    transfer_verifying_key: &TransferVerifyingKey<C>,
    public_inputs: &TransferPublicInput<C>,
    proof: &Proof<C::PairingCurve>,
    recv_memos_ver_key: &schnorr::VerKey<C::EmbeddedCurveParam>,
    extra_proof_bound_data: &[u8],
) -> Result<(), TxnApiError> {
    let mut ext_msg = Vec::new();
    CanonicalSerialize::serialize(recv_memos_ver_key, &mut ext_msg)?;
    ext_msg.extend_from_slice(extra_proof_bound_data);
    PlonkKzgSnark::<C::PairingCurve>::verify::<SolidityTranscript>(
        &transfer_verifying_key.verifying_key,
        &public_inputs.to_scalars(),
        proof,
        Some(ext_msg),
    )
    .map_err(|e| {
        TxnApiError::FailedSnark(format!("Transfer Proof Verification failure: {:?}", e))
    })?;
    Ok(())
}

/// Secret witness required to construct a SNARK proof for transfer transaction
#[derive(Debug, Clone)]
pub(crate) struct TransferWitness<'a, C: CapConfig> {
    pub(crate) asset_def: AssetDefinition<C>,
    pub(crate) input_secrets: Vec<InputSecret<'a, C>>,
    pub(crate) output_record_openings: Vec<RecordOpening<C>>,
    pub(crate) viewing_memo_enc_rand: C::EmbeddedCurveScalarField,
}

impl<'a, C: CapConfig> TransferWitness<'a, C> {
    pub(crate) fn dummy(
        num_input: usize,
        num_output: usize,
        tree_depth: u8,
        user_keypair: &'a UserKeyPair<C>,
    ) -> Self {
        let asset_def = AssetDefinition::native();
        let input_secret = {
            let ro = RecordOpening {
                amount: 0u64.into(),
                asset_def: asset_def.clone(),
                pub_key: Default::default(),
                freeze_flag: Default::default(),
                blind: Default::default(),
            };
            let mut mt = MerkleTree::new(tree_depth).unwrap();
            mt.push(ro.derive_record_commitment().to_field_element());
            InputSecret {
                owner_keypair: user_keypair,
                ro,
                acc_member_witness: AccMemberWitness {
                    merkle_path: MerklePath {
                        nodes: vec![MerklePathNode::default(); tree_depth as usize],
                    },
                    ..Default::default()
                },
                cred: ExpirableCredential::dummy_unexpired().unwrap(),
            }
        };
        let output_ro = RecordOpening::default();

        let viewing_memo_enc_rand = C::EmbeddedCurveScalarField::default();
        Self {
            asset_def,
            input_secrets: vec![input_secret; num_input],
            output_record_openings: vec![output_ro; num_output],
            viewing_memo_enc_rand,
        }
    }
    /// Create a new witness from I/O record openings, input keypairs and input
    /// credentials Note that this method should only be invoked after these
    /// input params have passed corresponding checks (e.g. balance
    /// reserved, keypair matched, credential verification), otherwise the
    /// returned witness would be invalid -- namely validity of input
    /// parameters is unchecked.
    pub(crate) fn new_unchecked<R: RngCore + CryptoRng>(
        rng: &mut R,
        inputs: Vec<TransferNoteInput<'a, C>>,
        output_ros: &[RecordOpening<C>],
    ) -> Result<Self, TxnApiError> {
        let mut asset_def = AssetDefinition::native();
        for input in inputs.iter() {
            if !input.ro.asset_def.is_native() && !input.ro.asset_def.is_dummy() {
                asset_def = input.ro.asset_def.clone();
            }
        }

        let input_secrets = inputs.into_iter().map(|input| {
            let cred = if input.ro.asset_def.policy.cred_pk == CredIssuerPubKey::default() {
                ExpirableCredential::dummy_unexpired()?
            } else {
                input.cred.clone().ok_or_else(|| TxnApiError::InvalidParameter("Record with non-empty credential creator should have an ExpirableCredential".to_string()))?
            };
            Ok(
                InputSecret {
                    owner_keypair: input.owner_keypair,
                    ro: input.ro,
                    acc_member_witness: input.acc_member_witness,
                    cred
                }
            )
        }).collect::<Result<Vec<_>, TxnApiError>>()?;
        let output_record_openings = output_ros.to_owned();
        let viewing_memo_enc_rand = C::EmbeddedCurveScalarField::rand(rng);

        Ok(Self {
            asset_def,
            input_secrets,
            output_record_openings,
            viewing_memo_enc_rand,
        })
    }
}
/// Secret witness of an input asset record
#[derive(Debug, Clone)]
pub(crate) struct InputSecret<'a, C: CapConfig> {
    pub(crate) owner_keypair: &'a UserKeyPair<C>,
    pub(crate) ro: RecordOpening<C>,
    pub(crate) acc_member_witness: AccMemberWitness<C::ScalarField>,
    pub(crate) cred: ExpirableCredential<C>,
}

/// Public inputs of a transfer transaction
#[derive(Debug, Clone)]
/// Struct for the public input of a transfer witness
pub struct TransferPublicInput<C: CapConfig> {
    /// record merkle tree root
    pub merkle_root: NodeValue<C::ScalarField>,
    /// native asset code
    pub native_asset_code: AssetCode<C>,
    /// expiry of credentials
    pub valid_until: u64,
    /// transaction fee to pay
    pub fee: Amount,
    /// nullifiers of input records
    pub input_nullifiers: Vec<Nullifier<C>>,
    /// commitments of output commitments
    pub output_commitments: Vec<RecordCommitment<C>>,
    /// memo for viewer
    pub viewing_memo: ViewableMemo<C>,
}

impl<C: CapConfig> TransferPublicInput<C> {
    /// Compute the public input from witness and ledger info
    pub(crate) fn from_witness(
        witness: &TransferWitness<C>,
        valid_until: u64,
    ) -> Result<Self, TxnApiError> {
        let merkle_root = witness
            .input_secrets
            .get(0)
            .ok_or_else(|| TxnApiError::InvalidParameter("At least one input secret".to_string()))?
            .acc_member_witness
            .root;
        // native asset code and transaction fee
        let native_asset_code = witness
            .output_record_openings
            .first()
            .ok_or_else(|| {
                TxnApiError::InvalidParameter(
                    "Malformed transfer witness, expect at least 1 output record".to_string(),
                )
            })?
            .asset_def
            .code;

        // Calculate the fee: when transfer type is native asset type, (sum of
        // input - sum of output) is the fee; when the transfer type is
        // non-native asset type, the amount for the transferred type should be
        // net neutral, thus the same calculation can correctly derive the fee.
        let input_sum: Amount = safe_sum_amount(
            witness
                .input_secrets
                .iter()
                .filter(|x| !x.ro.asset_def.is_dummy())
                .map(|x| x.ro.amount)
                .collect::<Vec<Amount>>()
                .as_slice(),
        )
        .ok_or_else(|| TxnApiError::InvalidParameter("Sum overflow for inputs.".to_string()))?;
        let output_sum: Amount = safe_sum_amount(
            witness
                .output_record_openings
                .iter()
                .map(|x| x.amount)
                .collect::<Vec<Amount>>()
                .as_slice(),
        )
        .ok_or_else(|| TxnApiError::InvalidParameter("Sum overflow for outputs.".to_string()))?;

        let fee = Amount::from(u128::checked_sub(input_sum.0, output_sum.0).ok_or_else(|| {
            TxnApiError::InvalidParameter("The fee cannot be negative".to_string())
        })?);

        let input_nullifiers = witness
            .input_secrets
            .iter()
            .map(|secret| {
                // calculate commitment
                let comm = secret.ro.derive_record_commitment();
                let nk = secret
                    .owner_keypair
                    .derive_nullifier_key(&secret.ro.asset_def.policy.freezer_pk);
                let uid = secret.acc_member_witness.uid;
                Ok(nk.nullify(uid as u64, &comm))
            })
            .collect::<Result<Vec<_>, TxnApiError>>()?;

        let output_commitments = witness
            .output_record_openings
            .iter()
            .map(RecordCommitment::from)
            .collect();

        let viewing_memo = {
            // TODO: (alex) change compute_viewing_memo to accept &[Cow<RecordOpening>] to
            // avoid these unnecessary cloning
            let input_ros: Vec<_> = witness
                .input_secrets
                .iter()
                .map(|secret| secret.ro.clone())
                .collect();
            let output_ros = &witness.output_record_openings;
            let input_creds: Vec<_> = witness
                .input_secrets
                .iter()
                .map(|secret| secret.cred.clone())
                .collect();
            ViewableMemo::new_for_transfer_note(
                &input_ros,
                output_ros,
                &input_creds,
                witness.viewing_memo_enc_rand,
            )?
        };

        Ok(Self {
            merkle_root,
            native_asset_code,
            valid_until,
            fee,
            input_nullifiers,
            output_commitments,
            viewing_memo,
        })
    }

    /// Flatten out all pubic input fields into a vector of BaseFields.
    /// Note that the order matters.
    pub(crate) fn to_scalars(&self) -> Vec<C::ScalarField> {
        let mut result = vec![
            self.merkle_root.to_scalar(),
            self.native_asset_code.0,
            C::ScalarField::from(self.valid_until),
            C::ScalarField::from(self.fee.0),
        ];
        for nullifier in &self.input_nullifiers {
            result.push(nullifier.0);
        }
        for comm in &self.output_commitments {
            result.push(comm.0);
        }
        result.extend_from_slice(&self.viewing_memo.0.to_scalars());
        result
    }
}

#[cfg(test)]
mod test {
    use super::TransferPublicInput;
    use crate::{
        constants::MAX_TIMESTAMP_LEN,
        errors::TxnApiError,
        keys::{CredIssuerPubKey, UserAddress, UserKeyPair},
        prelude::{CapConfig, Config},
        proof::universal_setup_for_staging,
        structs::{Amount, AssetDefinition, ExpirableCredential},
        utils::params_builder::TransferParamsBuilder,
    };
    use ark_std::vec;
    use jf_primitives::signatures::schnorr;

    impl<C: CapConfig> ExpirableCredential<C> {
        /// Return a bit indicating whether the credential is a dummy, unexpired
        /// one. This function only used in test.
        pub(crate) fn is_dummy_unexpired(&self) -> bool {
            self.user_addr == UserAddress::<C>::default()
                && self.creator_pk == CredIssuerPubKey::default()
                && !self.is_expired(2u64.pow(MAX_TIMESTAMP_LEN as u32) - 2)
        }
    }

    #[test]
    fn test_transfer_witness_creation() {
        let rng = &mut ark_std::test_rng();
        let cred_expiry = 9998u64;
        let user_keypair = UserKeyPair::<Config>::generate(rng);
        let user_keypairs = vec![&user_keypair; 2];
        // transfer non-native asset type
        let builder = TransferParamsBuilder::<Config>::new_non_native(2, 6, None, user_keypairs)
            .set_input_amounts(30u64.into(), &[25u64.into()])
            .set_output_amounts(19u64.into(), &Amount::from_vec(&[3, 4, 5, 6, 7])[..])
            .set_input_creds(cred_expiry);
        let witness = builder.build_witness(rng);

        // check asset_def
        assert_eq!(
            witness.asset_def,
            builder.transfer_asset_def.as_ref().unwrap().asset_def
        );

        // check input_secrets
        for (secret, ro) in witness.input_secrets.iter().zip(builder.input_ros.iter()) {
            assert_eq!(&secret.ro, ro);
        }
        for (secret, cred) in witness.input_secrets.iter().zip(builder.input_creds.iter()) {
            if secret.ro.asset_def.policy.cred_pk == CredIssuerPubKey::default() {
                assert!(secret.cred.is_dummy_unexpired());
            } else {
                assert_eq!(&secret.cred, cred.as_ref().unwrap());
            }
        }
        for (secret, keypair) in witness
            .input_secrets
            .iter()
            .zip(builder.input_keypairs.iter())
        {
            assert_eq!(
                secret.owner_keypair.address_secret_ref(),
                keypair.address_secret_ref()
            );
        }

        // check output_record_openings
        assert_eq!(&witness.output_record_openings[0], &builder.fee_chg_ro);
        assert_eq!(&witness.output_record_openings[1..], &builder.output_ros);

        // tranfer native asset type
        let user_keypair = UserKeyPair::<Config>::generate(rng);
        let user_keypairs = vec![&user_keypair; 2];
        let builder = TransferParamsBuilder::new_native(2, 3, None, user_keypairs)
            .set_input_amounts(20u64.into(), &Amount::from_vec(&[10])[..])
            .set_output_amounts(14u64.into(), &Amount::from_vec(&[4, 6])[..])
            .set_input_creds(cred_expiry);
        let witness = builder.build_witness(rng);
        // check asset_def
        assert_eq!(witness.asset_def, AssetDefinition::native());
    }

    #[test]
    fn test_pub_input_creation() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let cred_expiry = 9998u64;
        let valid_until = 1234u64;

        let user_keypair = UserKeyPair::<Config>::generate(rng);
        let user_keypairs = vec![&user_keypair; 2];
        // transfer non-native asset type
        let builder = TransferParamsBuilder::<Config>::new_non_native(2, 3, None, user_keypairs)
            .set_input_amounts(30u64.into(), &Amount::from_vec(&[10])[..])
            .set_output_amounts(19u64.into(), &Amount::from_vec(&[4, 6])[..])
            .set_input_creds(cred_expiry);
        let witness = builder.build_witness(rng);
        assert!(
            TransferPublicInput::from_witness(&witness, valid_until).is_ok(),
            "create public input from correct witness should succeed"
        );

        // 0 output should fail
        let mut bad_witness = witness.clone();
        bad_witness.output_record_openings = vec![];
        assert!(
            TransferPublicInput::from_witness(&bad_witness, valid_until).is_err(),
            "create public input from wrong witness with 0 output ROs should fail"
        );

        // negative fee should fail
        let mut bad_witness = witness.clone();
        bad_witness.output_record_openings[0].amount = 31u64.into();
        assert!(
            TransferPublicInput::from_witness(&bad_witness, valid_until).is_err(),
            "create public input from wrong witness with negative fee should fail"
        );

        // overflow total input amounts should fail
        let mut bad_witness = witness.clone();
        bad_witness.input_secrets[1].ro.amount = Amount::from(u128::MAX - 1);
        assert!(
            TransferPublicInput::from_witness(&bad_witness, valid_until).is_err(),
            "create public input from wrong witness with overflown total input amounts should fail"
        );

        // overflow total output amounts should fail
        let mut bad_witness = witness.clone();
        bad_witness.output_record_openings[1].amount = Amount::from(u128::MAX - 13);
        assert!(TransferPublicInput::from_witness(
            &bad_witness,
            valid_until,
        )
                .is_err(),
            "create public input from wrong witness with overflown total output amounts should fail"
        );
        Ok(())
    }

    #[test]
    fn test_transfer_validity_proof() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        // 2-in-6-out-10-depth is 30740 num of constraints
        // eval domain size is 32768
        let max_degree = 65538;
        let num_input = 2;
        let num_output = 6;
        let depth = 10;
        let universal_param = universal_setup_for_staging::<_, Config>(max_degree, rng)?;
        let (proving_key_1, verifying_key_1, _) =
            super::preprocess::<Config>(&universal_param, num_input, num_output, depth)?;

        let cred_expiry = 9998u64;
        let valid_until = 1234u64;
        let recv_memos_ver_key = schnorr::KeyPair::generate(rng).ver_key();
        let extra_proof_bound_data = "some random data".as_bytes();

        let user_keypair1 = UserKeyPair::generate(rng);
        let user_keypair2 = UserKeyPair::generate(rng);
        let user_keypairs = vec![&user_keypair1, &user_keypair2];
        let builder = TransferParamsBuilder::new_non_native(
            num_input,
            num_output,
            Some(depth),
            user_keypairs,
        )
        .set_input_amounts(30u64.into(), &Amount::from_vec(&[25])[..])
        .set_output_amounts(19u64.into(), &Amount::from_vec(&[3, 4, 5, 6, 7])[..])
        .set_input_creds(cred_expiry);
        let witness_1 = builder.build_witness(rng);
        let pub_input_1 = TransferPublicInput::from_witness(&witness_1, valid_until)?;

        let validity_proof_1 = super::prove(
            rng,
            &proving_key_1,
            &witness_1,
            &pub_input_1,
            &recv_memos_ver_key,
            &extra_proof_bound_data,
        )?;
        assert!(super::verify(
            &verifying_key_1,
            &pub_input_1,
            &validity_proof_1,
            &recv_memos_ver_key,
            &extra_proof_bound_data,
        )
        .is_ok());

        // For bad path, please see negative cases in circuit/transfer.rs,
        // `test_transfer_circuit_build() `, since our prove and verify just passing
        // along the underlying circuit, we skip the repetitive tests with negative/bad
        // proofs here. The combination of test coverage in Plonk proof system and in
        // circuit/transfer.rs already ensure completeness and soundness.

        let num_input = 1;
        let num_output = 2;
        let recv_memos_ver_key = schnorr::KeyPair::generate(rng).ver_key();
        let (proving_key_2, verifying_key_2, _) =
            super::preprocess(&universal_param, num_input, num_output, depth)?;

        let user_keypair = UserKeyPair::generate(rng);
        let user_keypairs = vec![&user_keypair; 1];
        let builder =
            TransferParamsBuilder::new_native(num_input, num_output, Some(depth), user_keypairs)
                .set_input_amounts(30u64.into(), &Amount::from_vec(&[])[..])
                .set_output_amounts(13u64.into(), &Amount::from_vec(&[15])[..])
                .set_input_creds(cred_expiry);
        let witness_2 = builder.build_witness(rng);
        let pub_input_2 = TransferPublicInput::from_witness(&witness_2, valid_until)?;

        let validity_proof_2 = super::prove(
            rng,
            &proving_key_2,
            &witness_2,
            &pub_input_2,
            &recv_memos_ver_key,
            &extra_proof_bound_data,
        )?;
        assert!(super::verify(
            &verifying_key_2,
            &pub_input_2,
            &validity_proof_2,
            &recv_memos_ver_key,
            &extra_proof_bound_data,
        )
        .is_ok());

        // bad paths
        // wrong pub inputs
        assert!(super::verify(
            &verifying_key_1,
            &pub_input_2,
            &validity_proof_1,
            &recv_memos_ver_key,
            &extra_proof_bound_data,
        )
        .is_err());
        assert!(super::verify(
            &verifying_key_2,
            &pub_input_1,
            &validity_proof_2,
            &recv_memos_ver_key,
            &extra_proof_bound_data,
        )
        .is_err());
        // wrong proofs
        assert!(super::verify(
            &verifying_key_1,
            &pub_input_1,
            &validity_proof_2,
            &recv_memos_ver_key,
            &extra_proof_bound_data,
        )
        .is_err());
        assert!(super::verify(
            &verifying_key_2,
            &pub_input_2,
            &validity_proof_1,
            &recv_memos_ver_key,
            &extra_proof_bound_data,
        )
        .is_err());
        // wrong verifying keys
        assert!(super::verify(
            &verifying_key_1,
            &pub_input_2,
            &validity_proof_2,
            &recv_memos_ver_key,
            &extra_proof_bound_data,
        )
        .is_err());
        assert!(super::verify(
            &verifying_key_2,
            &pub_input_1,
            &validity_proof_1,
            &recv_memos_ver_key,
            &extra_proof_bound_data,
        )
        .is_err());
        // wrong receiver memo ver key
        assert!(super::verify(
            &verifying_key_1,
            &pub_input_1,
            &validity_proof_1,
            &schnorr::KeyPair::generate(rng).ver_key(),
            &extra_proof_bound_data,
        )
        .is_err());
        // wrong extra proof bounded data
        assert!(super::verify(
            &verifying_key_1,
            &pub_input_1,
            &validity_proof_1,
            &recv_memos_ver_key,
            &"wrong data".as_bytes(),
        )
        .is_err());

        Ok(())
    }
}
