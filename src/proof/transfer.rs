//! This module contains functions and data structures for
//! * Computing the public parameters
//! * Computing a Transfer proof
//! * Verifying a Transfer proof

use super::UniversalParam;
use crate::{
    circuit::transfer::TransferCircuit,
    errors::TxnApiError,
    keys::{CredIssuerPubKey, UserKeyPair},
    structs::{
        AssetCode, AssetDefinition, AuditMemo, ExpirableCredential, Nullifier, RecordCommitment,
        RecordOpening,
    },
    transfer::TransferNoteInput,
    utils::safe_sum_u64,
    BaseField, CurveParam, PairingEngine, ScalarField,
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
        structs::{Proof, ProvingKey, VerifyingKey},
        PlonkKzgSnark, Snark,
    },
    transcript::SolidityTranscript,
};
use jf_primitives::{
    merkle_tree::{AccMemberWitness, MerklePath, MerklePathNode, MerkleTree, NodeValue},
    schnorr_dsa,
};
use jf_utils::{deserialize_canonical_bytes, CanonicalBytes};
use serde::{Deserialize, Serialize};

/// Key for computing the proof associated to a Transfer note
#[derive(
    Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(from = "CanonicalBytes", into = "CanonicalBytes")]
pub struct TransferProvingKey<'a> {
    pub(crate) proving_key: ProvingKey<'a, PairingEngine>,
    pub(crate) n_inputs: usize,
    pub(crate) n_outputs: usize,
    pub(crate) tree_depth: u8,
}
deserialize_canonical_bytes!(TransferProvingKey<'a>);

impl<'a> TransferProvingKey<'a> {
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
pub struct TransferVerifyingKey {
    /// key
    pub(crate) verifying_key: VerifyingKey<PairingEngine>,
    pub(crate) n_inputs: usize,
    pub(crate) n_outputs: usize,
    pub(crate) tree_depth: u8,
}
deserialize_canonical_bytes!(TransferVerifyingKey);

impl TransferVerifyingKey {
    /// Getter for number of input (fee input included)
    pub fn num_input(&self) -> usize {
        self.n_inputs
    }

    /// Getter for number of output (fee change output included)
    pub fn num_output(&self) -> usize {
        self.n_outputs
    }
}

impl<'a> From<&TransferProvingKey<'a>> for TransferVerifyingKey {
    fn from(pk: &TransferProvingKey<'a>) -> Self {
        Self {
            verifying_key: pk.proving_key.vk.clone(),
            n_inputs: pk.n_inputs,
            n_outputs: pk.n_outputs,
            tree_depth: pk.tree_depth,
        }
    }
}

/// Proof associated to a Transfer note
pub type TransferValidityProof = Proof<PairingEngine>;

/// One-time preprocess of the Transfer transaction circuit, proving key and
/// verifying key should be reused for proving/verifying future instances of
/// transfer transaction.
pub fn preprocess(
    srs: &UniversalParam,
    n_inputs: usize,
    n_outputs: usize,
    tree_depth: u8,
) -> Result<(TransferProvingKey, TransferVerifyingKey, usize), TxnApiError> {
    let (dummy_circuit, n_constraints) =
        TransferCircuit::build_for_preprocessing(n_inputs, n_outputs, tree_depth)?;
    let (proving_key, verifying_key) =
        PlonkKzgSnark::<PairingEngine>::preprocess(srs, &dummy_circuit.0).map_err(|e| {
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
pub(crate) fn prove<'a, R: RngCore + CryptoRng>(
    rng: &mut R,
    transfer_proving_key: &TransferProvingKey<'a>,
    witness: &TransferWitness,
    public_inputs: &TransferPublicInput,
    txn_memo_ver_key: &schnorr_dsa::VerKey<CurveParam>,
    extra_proof_bound_data: &[u8],
) -> Result<TransferValidityProof, TxnApiError> {
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
    PlonkKzgSnark::<PairingEngine>::prove::<_, _, SolidityTranscript>(
        rng,
        &circuit.0,
        &transfer_proving_key.proving_key,
        Some(ext_msg),
    )
    .map_err(|e| TxnApiError::FailedSnark(format!("Transfer Proof Creation failure: {:?}", e)))
}

/// Verify a transaction validity proof given the public inputs and verifying
/// key.
pub(crate) fn verify(
    transfer_verifying_key: &TransferVerifyingKey,
    public_inputs: &TransferPublicInput,
    proof: &TransferValidityProof,
    recv_memos_ver_key: &schnorr_dsa::VerKey<CurveParam>,
    extra_proof_bound_data: &[u8],
) -> Result<(), TxnApiError> {
    let mut ext_msg = Vec::new();
    CanonicalSerialize::serialize(recv_memos_ver_key, &mut ext_msg)?;
    ext_msg.extend_from_slice(extra_proof_bound_data);
    PlonkKzgSnark::<PairingEngine>::verify::<SolidityTranscript>(
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
pub(crate) struct TransferWitness<'a> {
    pub(crate) asset_def: AssetDefinition,
    pub(crate) input_secrets: Vec<InputSecret<'a>>,
    pub(crate) output_record_openings: Vec<RecordOpening>,
    pub(crate) audit_memo_enc_rand: ScalarField,
}

impl<'a> TransferWitness<'a> {
    pub(crate) fn dummy(
        num_input: usize,
        num_output: usize,
        tree_depth: u8,
        user_keypair: &'a UserKeyPair,
    ) -> Self {
        let asset_def = AssetDefinition::native();
        let input_secret = {
            let ro = RecordOpening {
                amount: 0,
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

        let audit_memo_enc_rand = ScalarField::default();
        Self {
            asset_def,
            input_secrets: vec![input_secret; num_input],
            output_record_openings: vec![output_ro; num_output],
            audit_memo_enc_rand,
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
        inputs: Vec<TransferNoteInput<'a>>,
        output_ros: &[RecordOpening],
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
                input.cred.clone().ok_or_else(|| TxnApiError::InvalidParameter("Record with non-empty credential issuer should have an ExpirableCredential".to_string()))?
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
        let audit_memo_enc_rand = ScalarField::rand(rng);

        Ok(Self {
            asset_def,
            input_secrets,
            output_record_openings,
            audit_memo_enc_rand,
        })
    }
}
/// Secret witness of an input asset record
#[derive(Debug, Clone)]
pub(crate) struct InputSecret<'a> {
    pub(crate) owner_keypair: &'a UserKeyPair,
    pub(crate) ro: RecordOpening,
    pub(crate) acc_member_witness: AccMemberWitness<BaseField>,
    pub(crate) cred: ExpirableCredential,
}

/// Public inputs of a transfer transaction
#[derive(Debug, Clone)]
/// Struct for the public input of a transfer witness
pub(crate) struct TransferPublicInput {
    pub(crate) merkle_root: NodeValue<BaseField>,
    pub(crate) native_asset_code: AssetCode,
    pub(crate) valid_until: u64,
    pub(crate) fee: u64,
    pub(crate) input_nullifiers: Vec<Nullifier>,
    pub(crate) output_commitments: Vec<RecordCommitment>,
    pub(crate) audit_memo: AuditMemo,
}

impl TransferPublicInput {
    /// Compute the public input from witness and ledger info
    pub(crate) fn from_witness(
        witness: &TransferWitness,
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
        let input_sum: u64 = safe_sum_u64(
            witness
                .input_secrets
                .iter()
                .filter(|x| !x.ro.asset_def.is_dummy())
                .map(|x| x.ro.amount)
                .collect::<Vec<u64>>()
                .as_slice(),
        )
        .ok_or_else(|| TxnApiError::InvalidParameter("Sum overflow for inputs.".to_string()))?;
        let output_sum: u64 = safe_sum_u64(
            witness
                .output_record_openings
                .iter()
                .map(|x| x.amount)
                .collect::<Vec<u64>>()
                .as_slice(),
        )
        .ok_or_else(|| TxnApiError::InvalidParameter("Sum overflow for outputs.".to_string()))?;

        let fee = u64::checked_sub(input_sum, output_sum).ok_or_else(|| {
            TxnApiError::InvalidParameter("The fee cannot be negative".to_string())
        })?;

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

        let audit_memo = {
            // TODO: (alex) change compute_audit_memo to accept &[Cow<RecordOpening>] to
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
            AuditMemo::new_for_transfer_note(
                &input_ros,
                output_ros,
                &input_creds,
                witness.audit_memo_enc_rand,
            )?
        };

        Ok(Self {
            merkle_root,
            native_asset_code,
            valid_until,
            fee,
            input_nullifiers,
            output_commitments,
            audit_memo,
        })
    }

    /// Flatten out all pubic input fields into a vector of BaseFields.
    /// Note that the order matters.
    pub(crate) fn to_scalars(&self) -> Vec<BaseField> {
        let mut result = vec![
            self.merkle_root.to_scalar(),
            self.native_asset_code.0,
            BaseField::from(self.valid_until),
            BaseField::from(self.fee),
        ];
        for nullifier in &self.input_nullifiers {
            result.push(nullifier.0);
        }
        for comm in &self.output_commitments {
            result.push(comm.0);
        }
        result.extend_from_slice(&self.audit_memo.0.to_scalars());
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
        proof::universal_setup_for_test,
        structs::{AssetDefinition, ExpirableCredential},
        utils::params_builder::TransferParamsBuilder,
    };
    use ark_std::vec;
    use jf_primitives::schnorr_dsa;

    impl ExpirableCredential {
        /// Return a bit indicating whether the credential is a dummy, unexpired
        /// one. This function only used in test.
        pub(crate) fn is_dummy_unexpired(&self) -> bool {
            self.user_addr == UserAddress::default()
                && self.issuer_pk == CredIssuerPubKey::default()
                && !self.is_expired(2u64.pow(MAX_TIMESTAMP_LEN as u32) - 2)
        }
    }

    #[test]
    fn test_transfer_witness_creation() {
        let rng = &mut ark_std::test_rng();
        let cred_expiry = 9998u64;
        let user_keypair = UserKeyPair::generate(rng);
        let user_keypairs = vec![&user_keypair; 2];
        // transfer non-native asset type
        let builder = TransferParamsBuilder::new_non_native(2, 6, None, user_keypairs)
            .set_input_amounts(30, &[25])
            .set_output_amounts(19, &[3, 4, 5, 6, 7])
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
        let user_keypair = UserKeyPair::generate(rng);
        let user_keypairs = vec![&user_keypair; 2];
        let builder = TransferParamsBuilder::new_native(2, 3, None, user_keypairs)
            .set_input_amounts(20, &[10])
            .set_output_amounts(14, &[4, 6])
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

        let user_keypair = UserKeyPair::generate(rng);
        let user_keypairs = vec![&user_keypair; 2];
        // transfer non-native asset type
        let builder = TransferParamsBuilder::new_non_native(2, 3, None, user_keypairs)
            .set_input_amounts(30, &[10])
            .set_output_amounts(19, &[4, 6])
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
        bad_witness.output_record_openings[0].amount = 31;
        assert!(
            TransferPublicInput::from_witness(&bad_witness, valid_until).is_err(),
            "create public input from wrong witness with negative fee should fail"
        );

        // overflow total input amounts should fail
        let mut bad_witness = witness.clone();
        bad_witness.input_secrets[1].ro.amount = u64::MAX - 1;
        assert!(
            TransferPublicInput::from_witness(&bad_witness, valid_until).is_err(),
            "create public input from wrong witness with overflown total input amounts should fail"
        );

        // overflow total output amounts should fail
        let mut bad_witness = witness.clone();
        bad_witness.output_record_openings[1].amount = u64::MAX - 13;
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
        let universal_param = universal_setup_for_test(max_degree, rng)?;
        let (proving_key_1, verifying_key_1, _) =
            super::preprocess(&universal_param, num_input, num_output, depth)?;

        let cred_expiry = 9998u64;
        let valid_until = 1234u64;
        let recv_memos_ver_key = schnorr_dsa::KeyPair::generate(rng).ver_key();
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
        .set_input_amounts(30, &[25])
        .set_output_amounts(19, &[3, 4, 5, 6, 7])
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
        let recv_memos_ver_key = schnorr_dsa::KeyPair::generate(rng).ver_key();
        let (proving_key_2, verifying_key_2, _) =
            super::preprocess(&universal_param, num_input, num_output, depth)?;

        let user_keypair = UserKeyPair::generate(rng);
        let user_keypairs = vec![&user_keypair; 1];
        let builder =
            TransferParamsBuilder::new_native(num_input, num_output, Some(depth), user_keypairs)
                .set_input_amounts(30, &[])
                .set_output_amounts(13, &[15])
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
            &schnorr_dsa::KeyPair::generate(rng).ver_key(),
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
