// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Generation and verification of mint notes (a.k.a Asset Issuance)

use crate::{
    errors::TxnApiError,
    proof::mint::{
        self, MintProvingKey, MintPublicInput, MintValidityProof, MintVerifyingKey, MintWitness,
    },
    structs::{
        Amount, AssetCode, AssetCodeDigest, AssetCodeSeed, AssetDefinition, AuditMemo,
        InternalAssetCode, Nullifier, RecordCommitment, RecordOpening, TxnFeeInfo,
    },
    utils::txn_helpers::{mint::*, *},
    KeyPair, NodeValue, ScalarField, VerKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::{string::ToString, vec, UniformRand};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Asset issuance/Mint note structure for single newly minted asset type.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    CanonicalDeserialize,
    CanonicalSerialize,
    Serialize,
    Deserialize,
)]
pub struct MintNote {
    /// nullifier for the input (i.e. transaction fee record)
    pub input_nullifier: Nullifier,
    /// output commitment for the fee change
    pub chg_comm: RecordCommitment,
    /// output commitment for the minted asset
    pub mint_comm: RecordCommitment,
    /// the amount of the minted asset
    pub mint_amount: Amount,
    /// the asset definition of the asset
    pub mint_asset_def: AssetDefinition,
    /// the asset code
    pub mint_internal_asset_code: InternalAssetCode,
    /// the validity proof of this note
    pub proof: MintValidityProof,
    /// memo for policy compliance specified for the designated auditor
    pub audit_memo: AuditMemo,
    /// auxiliary information
    pub aux_info: MintAuxInfo,
}

/// Auxiliary info of `MintNote`
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    CanonicalDeserialize,
    CanonicalSerialize,
    Serialize,
    Deserialize,
)]
pub struct MintAuxInfo {
    /// Merkle tree accumulator root
    pub merkle_root: NodeValue,
    /// Proposed transaction fee in native asset type
    pub fee: Amount,
    /// Transaction memos signature verification key (usually used for signing
    /// receiver memos)
    pub txn_memo_ver_key: VerKey,
}

impl MintNote {
    /// Generate a mint note.
    ///
    /// * `mint_ro` - Record opening of the minted asset
    /// * `ac_seed` - The asset code seed of the minted asset type
    /// * `ac_digest` - The description digest of the minted asset type
    /// * `proving_key` - The proving key to generate a validity proof.
    ///  Return MintNote, signature keypair bound to the MintNote's proof, and
    /// fee change RecordOpening
    pub fn generate<R>(
        rng: &mut R,
        mint_ro: RecordOpening,
        ac_seed: AssetCodeSeed,
        ac_description: &[u8],
        txn_fee_info: TxnFeeInfo,
        proving_key: &MintProvingKey,
    ) -> Result<(Self, KeyPair), TxnApiError>
    where
        R: RngCore + CryptoRng,
    {
        let acc_member_witness = &txn_fee_info.fee_input.acc_member_witness;
        let merkle_root = acc_member_witness.root;
        let issuer_keypair = txn_fee_info.fee_input.owner_keypair;
        let ac_digest = AssetCodeDigest::from_description(ac_description);
        // check note input
        check_proving_key_consistency(proving_key, acc_member_witness)?;
        check_input_pub_key(&txn_fee_info.fee_input.ro, issuer_keypair)?;
        check_mint_asset_code(&mint_ro, ac_seed, ac_digest)?;
        check_fee(&txn_fee_info)?;
        let outputs = vec![&txn_fee_info.fee_chg_ro, &mint_ro];
        check_unfrozen(&[&txn_fee_info.fee_input.ro], &outputs)?;

        // build public input and snark proof
        let signing_keypair = KeyPair::generate(rng);
        let audit_memo_enc_rand = ScalarField::rand(rng);
        let witness = MintWitness {
            issuer_keypair,
            acc_member_witness: txn_fee_info.fee_input.acc_member_witness,
            fee_ro: txn_fee_info.fee_input.ro,
            mint_ro: mint_ro.clone(),
            chg_ro: txn_fee_info.fee_chg_ro,
            ac_seed,
            ac_digest,
            audit_memo_enc_rand,
        };
        let public_inputs = MintPublicInput::from_witness(&witness)?;
        let proof = mint::prove(
            rng,
            proving_key,
            &witness,
            &public_inputs,
            signing_keypair.ver_key_ref(),
        )?;

        let internal_asset_code = InternalAssetCode::new(ac_seed, ac_description);
        let mint_note = MintNote {
            input_nullifier: public_inputs.input_nullifier,
            chg_comm: public_inputs.chg_rc,
            mint_comm: public_inputs.mint_rc,
            mint_amount: mint_ro.amount,
            mint_asset_def: mint_ro.asset_def,
            mint_internal_asset_code: internal_asset_code,
            proof,
            audit_memo: public_inputs.audit_memo,
            aux_info: MintAuxInfo {
                merkle_root,
                fee: txn_fee_info.fee_amount,
                txn_memo_ver_key: signing_keypair.ver_key(),
            },
        };
        Ok((mint_note, signing_keypair))
    }

    /// Verifying a Mint note.
    pub fn verify(
        &self,
        verifying_key: &MintVerifyingKey,
        merkle_root: NodeValue,
    ) -> Result<(), TxnApiError> {
        let public_inputs = self.check_instance_and_get_public_input(merkle_root)?;
        self.mint_asset_def
            .code
            .verify_domestic(&self.mint_internal_asset_code)?;
        mint::verify(
            verifying_key,
            &public_inputs,
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
    ) -> Result<MintPublicInput, TxnApiError> {
        // check root consistency
        if merkle_root != self.aux_info.merkle_root {
            return Err(TxnApiError::FailedTransactionVerification(
                "Merkle root do not match".to_string(),
            ));
        }
        Ok(MintPublicInput {
            merkle_root,
            native_asset_code: AssetCode::native(),
            input_nullifier: self.input_nullifier,
            fee: self.aux_info.fee,
            mint_rc: self.mint_comm,
            chg_rc: self.chg_comm,
            mint_amount: self.mint_amount,
            mint_ac: self.mint_asset_def.code,
            mint_internal_ac: self.mint_internal_asset_code,
            mint_policy: self.mint_asset_def.policy.clone(),
            audit_memo: self.audit_memo.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        errors::TxnApiError,
        keys::{AuditorKeyPair, UserKeyPair},
        proof::{
            self,
            mint::{MintProvingKey, MintVerifyingKey},
            universal_setup_for_staging,
        },
        sign_receiver_memos,
        structs::{Amount, AssetCodeSeed, AssetDefinition, FreezeFlag, ReceiverMemo},
        utils::params_builder::{MintParamsBuilder, PolicyRevealAttr},
        KeyPair, NodeValue, TransactionNote,
    };
    use ark_std::boxed::Box;

    #[test]
    fn test_mint_note() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let tree_depth = 10;
        // increasing the max_degree since bls12_377 requires a larger one
        let max_degree = 32770;
        let universal_param = universal_setup_for_staging(max_degree, rng)?;
        let (proving_key, verifying_key, _) =
            proof::mint::preprocess(&universal_param, tree_depth)?;

        let input_amount = Amount::from(10u64);
        let mint_amount = Amount::from(35u64);
        let issuer_keypair = UserKeyPair::generate(rng);
        let receiver_keypair = UserKeyPair::generate(rng);
        let auditor_keypair = AuditorKeyPair::generate(rng);

        // ====================================
        // zero fee
        // ====================================
        let fee = Amount::from(0u64);
        let builder = MintParamsBuilder::new(
            rng,
            tree_depth,
            input_amount,
            fee,
            mint_amount,
            &issuer_keypair,
            &receiver_keypair,
            &auditor_keypair,
        )
        .policy_reveal(PolicyRevealAttr::Amount)
        .policy_reveal(PolicyRevealAttr::UserAddr)
        .policy_reveal(PolicyRevealAttr::BlindFactor);

        assert!(test_mint_note_helper(
            &builder,
            mint_amount,
            &proving_key,
            &verifying_key,
            &receiver_keypair,
            &auditor_keypair
        )
        .is_ok());

        // ====================================
        // non-zero fee
        // ====================================
        let fee = Amount::from(4u64);
        let builder = MintParamsBuilder::new(
            rng,
            tree_depth,
            input_amount,
            fee,
            mint_amount,
            &issuer_keypair,
            &receiver_keypair,
            &auditor_keypair,
        )
        .policy_reveal(PolicyRevealAttr::Amount)
        .policy_reveal(PolicyRevealAttr::UserAddr)
        .policy_reveal(PolicyRevealAttr::BlindFactor);

        assert!(test_mint_note_helper(
            &builder,
            mint_amount,
            &proving_key,
            &verifying_key,
            &receiver_keypair,
            &auditor_keypair
        )
        .is_ok());

        // ====================================
        // bad prover
        // ====================================
        {
            let mut bad_proving_key = proving_key.clone();
            bad_proving_key.tree_depth = tree_depth + 1;
            assert!(builder.build_mint_note(rng, &bad_proving_key).is_err());
            bad_proving_key.tree_depth = tree_depth - 1;
            assert!(builder.build_mint_note(rng, &bad_proving_key).is_err());
        }

        // inconsistent issuer keypair
        {
            let mut bad_builder = builder.clone();
            let bad_issuer_keypair = UserKeyPair::generate(rng);
            bad_builder.issuer_keypair = &bad_issuer_keypair;
            assert!(bad_builder.build_mint_note(rng, &proving_key).is_err());
        }

        // wrong seed or digest for minted asset
        {
            let mut bad_builder = builder.clone();
            bad_builder.ac_seed = AssetCodeSeed::generate(rng);
            assert!(bad_builder.build_mint_note(rng, &proving_key).is_err());

            let mut bad_builder = builder.clone();
            bad_builder.ac_description = b"bad description".to_vec();
            assert!(bad_builder.build_mint_note(rng, &proving_key).is_err());
        }

        // all input and outputs are unfrozen
        {
            let mut bad_builder = builder.clone();
            bad_builder.fee_ro.freeze_flag = FreezeFlag::Frozen;
            assert!(bad_builder.build_mint_note(rng, &proving_key).is_err());

            let mut bad_builder = builder.clone();
            bad_builder.mint_ro.freeze_flag = FreezeFlag::Frozen;
            assert!(bad_builder.build_mint_note(rng, &proving_key).is_err());

            // change RO is created inside the body of MintNote::generate(),
            // thus changing builder params won't affect or result in a wrong
            // input, thus skip testing that
        }

        // wrong fee > input amount
        {
            let mut bad_builder = builder.clone();
            bad_builder.fee = bad_builder.fee_ro.amount + Amount::from(1u64);
            assert!(bad_builder.build_mint_note(rng, &proving_key).is_err());
        }

        // non-native fee should fail
        {
            let mut bad_builder = builder.clone();
            bad_builder.fee_ro.asset_def = AssetDefinition::rand_for_test(rng);
            assert!(bad_builder.build_mint_note(rng, &proving_key).is_err());
        }

        Ok(())
    }

    fn test_mint_note_helper(
        builder: &MintParamsBuilder,
        mint_amount: Amount,
        proving_key: &MintProvingKey,
        verifying_key: &MintVerifyingKey,
        receiver_keypair: &UserKeyPair,
        auditor_keypair: &AuditorKeyPair,
    ) -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();

        let (note, sig_keypair, _change_ro) = builder.build_mint_note(rng, &proving_key)?;
        // Check note
        assert!(note
            .verify(&verifying_key, note.aux_info.merkle_root)
            .is_ok());

        assert!(note.verify(&verifying_key, NodeValue::default()).is_err());
        // note with wrong recv_memos_ver_key should fail
        let mut wrong_note = note.clone();
        wrong_note.aux_info.txn_memo_ver_key = KeyPair::generate(rng).ver_key();
        assert!(wrong_note
            .verify(&verifying_key, note.aux_info.merkle_root)
            .is_err());

        // test receiver memos and signature embedding the mint note in a transaction
        // note
        let recv_memos = [ReceiverMemo::from_ro(rng, &builder.mint_ro, &[]).unwrap()];
        let sig = sign_receiver_memos(&sig_keypair, &recv_memos).unwrap();
        let txn = TransactionNote::Mint(Box::new(note.clone()));
        assert!(
            txn.verify_receiver_memos_signature(&recv_memos, &sig)
                .is_ok(),
            "Should have correct receiver memos signature"
        );

        // Check tracer's memo
        let audit_data = auditor_keypair.open_mint_audit_memo(&note);
        assert!(audit_data.is_ok());

        let audit_data = audit_data.unwrap();
        assert_eq!(audit_data.amount, Some(mint_amount));
        assert_eq!(audit_data.user_address, Some(receiver_keypair.address()));
        assert_eq!(audit_data.blinding_factor, Some(builder.mint_ro.blind));
        assert!(audit_data.attributes.is_empty());
        assert_eq!(audit_data.asset_code, builder.asset_def.code);

        // check receiver memos signature
        let txn: TransactionNote = note.into();
        assert!(
            txn.verify_receiver_memos_signature(&recv_memos, &sig)
                .is_ok(),
            "Should have correct receiver memo signature"
        );

        // check that minted receiver memo plaintext is correct
        let decrypted_ro = recv_memos[0].decrypt(
            &receiver_keypair,
            txn.output_commitments().get(1).unwrap(),
            &[],
        )?;
        assert_eq!(decrypted_ro, builder.mint_ro);

        Ok(())
    }
}
