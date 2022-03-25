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
//! * Computing a Minting proof
//! * Verifying a Minting proof

use super::UniversalParam;
use crate::{
    circuit::mint::MintCircuit,
    errors::TxnApiError,
    keys::UserKeyPair,
    structs::{
        AssetCode, AssetCodeDigest, AssetCodeSeed, AssetDefinition, AssetPolicy, AuditMemo,
        InternalAssetCode, Nullifier, RecordCommitment, RecordOpening,
    },
    BaseField, CurveParam, PairingEngine, ScalarField,
};
use ark_serialize::*;
use ark_std::{format, string::ToString, vec, vec::Vec};
use jf_plonk::{
    proof_system::{
        structs::{Proof, ProvingKey, VerifyingKey},
        PlonkKzgSnark, Snark,
    },
    transcript::SolidityTranscript,
};
use jf_primitives::{
    merkle_tree::{AccMemberWitness, MerkleTree, NodeValue},
    schnorr_dsa,
};
use jf_utils::{deserialize_canonical_bytes, CanonicalBytes};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Key for proving the validity of a Mint note during asset issuance.
#[derive(
    Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(from = "CanonicalBytes", into = "CanonicalBytes")]
pub struct MintProvingKey<'a> {
    pub(crate) proving_key: ProvingKey<'a, PairingEngine>,
    pub(crate) tree_depth: u8,
}
deserialize_canonical_bytes!(MintProvingKey<'a>);

/// Key for verifying the validity of a Mint note during asset issuance.
#[derive(
    Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(from = "CanonicalBytes", into = "CanonicalBytes")]
pub struct MintVerifyingKey {
    pub(crate) verifying_key: VerifyingKey<PairingEngine>,
    pub(crate) tree_depth: u8,
}
deserialize_canonical_bytes!(MintVerifyingKey);

/// Proof associated to a Mint note
pub type MintValidityProof = Proof<PairingEngine>;

/// One-time preprocess of the Mint transaction circuit, proving key and
/// verifying key should be reused for proving/verifying future instances of
/// mint transaction (a.k.a. Asset Issuance).
pub fn preprocess(
    srs: &UniversalParam,
    tree_depth: u8,
) -> Result<(MintProvingKey, MintVerifyingKey, usize), TxnApiError> {
    let (dummy_circuit, n_constraints) = MintCircuit::build_for_preprocessing(tree_depth)?;

    let (proving_key, verifying_key) =
        PlonkKzgSnark::<PairingEngine>::preprocess(srs, &dummy_circuit.0).map_err(|e| {
            TxnApiError::FailedSnark(format!(
                "Preprocessing Mint circuit of {}-depth failed: {}",
                tree_depth, e
            ))
        })?;
    Ok((
        MintProvingKey {
            proving_key,
            tree_depth,
        },
        MintVerifyingKey {
            verifying_key,
            tree_depth,
        },
        n_constraints,
    ))
}

/// Generate a transaction validity proof (a zk-SNARK proof) given the witness
/// , public inputs, and the proving key.
pub(crate) fn prove<R>(
    rng: &mut R,
    proving_key: &MintProvingKey,
    witness: &MintWitness,
    public_inputs: &MintPublicInput,
    txn_memo_ver_key: &schnorr_dsa::VerKey<CurveParam>,
) -> Result<MintValidityProof, TxnApiError>
where
    R: RngCore + CryptoRng,
{
    let (circuit, _) = MintCircuit::build(witness, public_inputs)
        .map_err(|e| TxnApiError::FailedSnark(format!("Failed to build Mint circuit: {}", e)))?;

    let mut ext_msg = Vec::new();
    CanonicalSerialize::serialize(txn_memo_ver_key, &mut ext_msg)?;

    PlonkKzgSnark::<PairingEngine>::prove::<_, _, SolidityTranscript>(
        rng,
        &circuit.0,
        &proving_key.proving_key,
        Some(ext_msg),
    )
    .map_err(|e| TxnApiError::FailedSnark(format!("Mint Proof creation failure: {:?}", e)))
}

/// Verify a transaction validity proof given the public inputs and verifying
/// key.
pub(crate) fn verify(
    verifying_key: &MintVerifyingKey,
    public_inputs: &MintPublicInput,
    proof: &MintValidityProof,
    recv_memos_ver_key: &schnorr_dsa::VerKey<CurveParam>,
) -> Result<(), TxnApiError> {
    let mut ext_msg = Vec::new();
    CanonicalSerialize::serialize(recv_memos_ver_key, &mut ext_msg)?;
    PlonkKzgSnark::<PairingEngine>::verify::<SolidityTranscript>(
        &verifying_key.verifying_key,
        &public_inputs.to_scalars(),
        proof,
        Some(ext_msg),
    )
    .map_err(|e| TxnApiError::FailedSnark(format!("Mint Proof verification failure: {}", e)))?;
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct MintWitness<'a> {
    pub(crate) issuer_keypair: &'a UserKeyPair,
    pub(crate) acc_member_witness: AccMemberWitness<BaseField>,
    pub(crate) fee_ro: RecordOpening,
    pub(crate) mint_ro: RecordOpening,
    pub(crate) chg_ro: RecordOpening,
    pub(crate) ac_seed: AssetCodeSeed,
    pub(crate) ac_digest: AssetCodeDigest,
    pub(crate) audit_memo_enc_rand: ScalarField,
}

impl<'a> MintWitness<'a> {
    pub(crate) fn dummy(tree_depth: u8, issuer_keypair: &'a UserKeyPair) -> Self {
        let fee_ro = RecordOpening {
            asset_def: AssetDefinition::native(),
            ..Default::default()
        };
        let chg_ro = fee_ro.clone();

        let mut mt = MerkleTree::new(tree_depth).unwrap();
        mt.push(fee_ro.derive_record_commitment().to_field_element());
        let acc_member_witness = AccMemberWitness::lookup_from_tree(&mt, 0)
            .expect_ok()
            .unwrap()
            .1; // safe unwrap()
        Self {
            issuer_keypair,
            acc_member_witness,
            fee_ro,
            mint_ro: RecordOpening::default(),
            chg_ro,
            ac_seed: AssetCodeSeed::default(),
            ac_digest: AssetCodeDigest::default(),
            audit_memo_enc_rand: ScalarField::default(),
        }
    }
}

#[derive(Debug, Clone)]
/// Struct for the public input of a mint witness
pub(crate) struct MintPublicInput {
    pub(crate) merkle_root: NodeValue<BaseField>,
    pub(crate) native_asset_code: AssetCode,
    pub(crate) input_nullifier: Nullifier,
    pub(crate) fee: u64,
    pub(crate) mint_rc: RecordCommitment,
    pub(crate) chg_rc: RecordCommitment,
    pub(crate) mint_amount: u64,
    pub(crate) mint_ac: AssetCode,
    pub(crate) mint_internal_ac: InternalAssetCode,
    pub(crate) mint_policy: AssetPolicy,
    pub(crate) audit_memo: AuditMemo,
}

impl MintPublicInput {
    /// Compute the public input from witness and ledger info
    pub(crate) fn from_witness(witness: &MintWitness) -> Result<Self, TxnApiError> {
        if witness.fee_ro.amount < witness.chg_ro.amount {
            return Err(TxnApiError::InvalidParameter(
                "minting: input amount less than change amount".to_string(),
            ));
        }
        let native_asset_def = AssetDefinition::native();
        if witness.chg_ro.asset_def != native_asset_def {
            return Err(TxnApiError::InvalidParameter(
                "minting: change record should be native".to_string(),
            ));
        }
        if witness.fee_ro.asset_def != native_asset_def {
            return Err(TxnApiError::InvalidParameter(
                "minting: input record for fee should be native".to_string(),
            ));
        }
        let fee = witness.fee_ro.amount - witness.chg_ro.amount;
        let native_asset_code = native_asset_def.code;
        let uid = witness.acc_member_witness.uid;
        let fee_rc = witness.fee_ro.derive_record_commitment();
        let input_nullifier = witness
            .issuer_keypair
            .derive_nullifier_key(&witness.fee_ro.asset_def.policy.freezer_pk)
            .nullify(uid as u64, &fee_rc);
        let mint_rc = RecordCommitment::from(&witness.mint_ro);
        let chg_rc = RecordCommitment::from(&witness.chg_ro);
        let mint_amount = witness.mint_ro.amount;
        let mint_internal_ac = InternalAssetCode::new_internal(witness.ac_seed, witness.ac_digest);
        let mint_ac = AssetCode::new_domestic_from_internal(&mint_internal_ac);
        let mint_policy = witness.mint_ro.asset_def.policy.clone();
        let audit_memo =
            AuditMemo::new_for_mint_note(&witness.mint_ro, witness.audit_memo_enc_rand);
        Ok(Self {
            merkle_root: witness.acc_member_witness.root,
            native_asset_code,
            input_nullifier,
            fee,
            mint_rc,
            chg_rc,
            mint_amount,
            mint_ac,
            mint_internal_ac,
            mint_policy,
            audit_memo,
        })
    }

    /// Flatten out all pubic input fields into a vector of BaseFields.
    /// Note that the order matters.
    /// The order: (root, native_ac, input_nullifier, fee, mint_rc, chg_rc,
    /// mint_amount, mint_ac, mint_policy, audit_memo)
    pub(crate) fn to_scalars(&self) -> Vec<BaseField> {
        let mut result = vec![
            self.merkle_root.to_scalar(),
            self.native_asset_code.0,
            self.input_nullifier.0,
            BaseField::from(self.fee),
            self.mint_rc.0,
            self.chg_rc.0,
            BaseField::from(self.mint_amount),
            self.mint_ac.0,
            self.mint_internal_ac.0,
        ];
        result.extend_from_slice(&self.mint_policy.to_scalars());
        result.extend_from_slice(&self.audit_memo.0.to_scalars());
        result
    }
}

#[cfg(test)]
mod test {
    use super::MintPublicInput;
    use crate::{
        errors::TxnApiError,
        keys::{AuditorKeyPair, UserKeyPair},
        proof::{mint, universal_setup_for_staging},
        utils::params_builder::MintParamsBuilder,
    };
    use jf_primitives::schnorr_dsa;
    use rand::{Rng, RngCore};

    #[test]
    fn test_pub_input_creation() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let tree_depth = 2;
        let input_amount = 30;
        let fee = 10;
        let mint_amount = 15;
        let issuer_keypair = UserKeyPair::generate(rng);
        let receiver_keypair = UserKeyPair::generate(rng);
        let auditor_keypair = AuditorKeyPair::generate(rng);

        // transfer non-native asset type
        let builder = MintParamsBuilder::new(
            rng,
            tree_depth,
            input_amount,
            fee,
            mint_amount,
            &issuer_keypair,
            &receiver_keypair,
            &auditor_keypair,
        );
        let witness = builder.build_witness(rng);
        assert!(
            MintPublicInput::from_witness(&witness).is_ok(),
            "create public input from correct witness should succeed"
        );

        // negative fee should fail
        let bad_fee = input_amount + 1;
        let builder = MintParamsBuilder::new(
            rng,
            tree_depth,
            input_amount,
            fee,
            mint_amount,
            &issuer_keypair,
            &receiver_keypair,
            &auditor_keypair,
        );
        let mut witness = builder.build_witness(rng);
        witness.chg_ro.amount = bad_fee;
        assert!(
            MintPublicInput::from_witness(&witness).is_err(),
            "create public input from wrong witness with negative fee should fail"
        );

        Ok(())
    }

    #[test]
    fn test_mint_validity_proof() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let tree_depth = 10;
        let max_degree = 32770;
        let universal_param = universal_setup_for_staging(max_degree, rng)?;
        let (proving_key, verifying_key, _) = mint::preprocess(&universal_param, tree_depth)?;

        let input_amount = 10;
        let fee = 4;
        let mint_amount = 35;
        let issuer_keypair = UserKeyPair::generate(rng);
        let receiver_keypair = UserKeyPair::generate(rng);
        let auditor_keypair = AuditorKeyPair::generate(rng);
        let recv_memo_ver_key = schnorr_dsa::KeyPair::generate(rng).ver_key();

        let builder = MintParamsBuilder::new(
            rng,
            tree_depth,
            input_amount,
            fee,
            mint_amount,
            &issuer_keypair,
            &receiver_keypair,
            &auditor_keypair,
        );
        let witness = builder.build_witness(rng);
        let public_inputs_1 = MintPublicInput::from_witness(&witness)?;

        let validity_proof_1 = mint::prove(
            rng,
            &proving_key,
            &witness,
            &public_inputs_1,
            &recv_memo_ver_key,
        )?;
        assert!(mint::verify(
            &verifying_key,
            &public_inputs_1,
            &validity_proof_1,
            &recv_memo_ver_key,
        )
        .is_ok());

        let wrong_public_input = {
            let mut pub_input = public_inputs_1.clone();
            pub_input.mint_amount = mint_amount - 3;
            pub_input
        };
        assert!(mint::verify(
            &verifying_key,
            &wrong_public_input,
            &validity_proof_1,
            &recv_memo_ver_key,
        )
        .is_err());

        // another instance
        let input_amount = rng.next_u32() as u64;
        let fee = rng.gen_range(1..input_amount);
        let mint_amount = rng.next_u32() as u64;
        let issuer_keypair = UserKeyPair::generate(rng);
        let receiver_keypair = UserKeyPair::generate(rng);
        let auditor_keypair = AuditorKeyPair::generate(rng);

        let builder = MintParamsBuilder::new(
            rng,
            tree_depth,
            input_amount,
            fee,
            mint_amount,
            &issuer_keypair,
            &receiver_keypair,
            &auditor_keypair,
        );
        let witness = builder.build_witness(rng);
        let public_inputs_2 = MintPublicInput::from_witness(&witness)?;

        let validity_proof_2 = mint::prove(
            rng,
            &proving_key,
            &witness,
            &public_inputs_2,
            &recv_memo_ver_key,
        )?;
        assert!(mint::verify(
            &verifying_key,
            &public_inputs_2,
            &validity_proof_2,
            &recv_memo_ver_key,
        )
        .is_ok());

        // bad paths
        assert!(mint::verify(
            &verifying_key,
            &public_inputs_1,
            &validity_proof_2,
            &recv_memo_ver_key,
        )
        .is_err());
        assert!(mint::verify(
            &verifying_key,
            &public_inputs_2,
            &validity_proof_1,
            &recv_memo_ver_key,
        )
        .is_err());
        let (_, bad_verifying_key, _) = mint::preprocess(&universal_param, 1)?;
        assert!(mint::verify(
            &bad_verifying_key,
            &public_inputs_1,
            &validity_proof_1,
            &recv_memo_ver_key,
        )
        .is_err());
        // wrong receiver memo ver key
        assert!(mint::verify(
            &verifying_key,
            &public_inputs_1,
            &validity_proof_1,
            &schnorr_dsa::KeyPair::generate(rng).ver_key(),
        )
        .is_err());

        Ok(())
    }
}
