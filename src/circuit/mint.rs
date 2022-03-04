// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Circuit for the issuance of user configurable asset.
use super::{
    gadgets::{Spender, TransactionGadgets},
    gadgets_helper::TransactionGadgetsHelper,
    structs::ViewableMemoVar,
};
use crate::{
    circuit::structs::{AssetPolicyVar, RecordOpeningVar},
    constants::AMOUNT_LEN,
    errors::TxnApiError,
    keys::UserKeyPair,
    proof::mint::{MintPublicInput, MintWitness},
    BaseField, CurveParam,
};
use ark_ff::Zero;
use ark_std::{format, vec};
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};
use jf_primitives::circuit::merkle_tree::AccMemberWitnessVar;
use jf_utils::fr_to_fq;

pub(crate) struct MintCircuit(pub(crate) PlonkCircuit<BaseField>);

impl MintCircuit {
    /// Build a circuit during preprocessing for derivation of proving key and
    /// verifying key.
    pub(crate) fn build_for_preprocessing(tree_depth: u8) -> Result<(Self, usize), TxnApiError> {
        let creator_keypair = UserKeyPair::default();
        let dummy_witness = MintWitness::dummy(tree_depth, &creator_keypair);
        let dummy_pub_input = MintPublicInput::from_witness(&dummy_witness)?;
        Self::build(&dummy_witness, &dummy_pub_input)
            .map_err(|e| TxnApiError::FailedSnark(format!("{:?}", e)))
    }

    /// Build the circuit given a satisfiable assignment of
    /// secret witness and public inputs.
    pub(crate) fn build(
        witness: &MintWitness,
        pub_input: &MintPublicInput,
    ) -> Result<(Self, usize), PlonkError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let witness = MintWitnessVar::new(&mut circuit, witness)?;
        let pub_input = MintPubInputVar::new(&mut circuit, pub_input)?;

        // Check that public commitments are consistent with witness
        let mint_rc = witness.mint_ro.compute_record_commitment(&mut circuit)?;
        circuit.equal_gate(mint_rc, pub_input.mint_rc)?;
        let chg_rc = witness.chg_ro.compute_record_commitment(&mut circuit)?;
        circuit.equal_gate(chg_rc, pub_input.chg_rc)?;

        // Derive asset type code from secret seed and asset type digest
        let mint_internal_ac =
            circuit.derive_internal_asset_code(witness.ac_seed, witness.ac_digest)?;
        circuit.equal_gate(mint_internal_ac, pub_input.mint_internal_ac)?;

        // Preserve balance
        circuit.add_gate(pub_input.fee, witness.chg_ro.amount, witness.fee_ro.amount)?;

        // Proof of spending
        let (nullifier, root) = circuit.prove_spend(
            &witness.fee_ro,
            &witness.acc_member_witness,
            witness.creator_sk,
            Spender::User,
        )?;
        circuit.equal_gate(root, pub_input.root)?;
        circuit.equal_gate(nullifier, pub_input.input_nullifier)?;

        // Check that records are not frozen
        let zero = BaseField::zero();
        circuit.constant_gate(witness.mint_ro.freeze_flag, zero)?;
        circuit.constant_gate(witness.fee_ro.freeze_flag, zero)?;
        circuit.constant_gate(witness.chg_ro.freeze_flag, zero)?;

        // Range-check mint amount, note we do not need to range-check change amount as
        // it's no more than the input amount that has been range-checked before.
        circuit.range_gate(witness.mint_ro.amount, AMOUNT_LEN)?;

        // Check (amount, asset_code, policy) consistency between witness and public
        // input
        circuit.equal_gate(witness.mint_ro.amount, pub_input.mint_amount)?;
        circuit.equal_gate(witness.mint_ro.asset_code, pub_input.mint_ac)?;
        pub_input
            .mint_policy
            .enforce_equal_policy(&mut circuit, &witness.mint_ro.policy)?;

        // Input/Change records should have native asset code and dummy policy
        circuit.equal_gate(witness.chg_ro.asset_code, pub_input.native_asset_code)?;
        circuit.equal_gate(witness.fee_ro.asset_code, pub_input.native_asset_code)?;
        witness.chg_ro.policy.enforce_dummy_policy(&mut circuit)?;
        witness.fee_ro.policy.enforce_dummy_policy(&mut circuit)?;

        // Input/Change records should have identical user addresses
        circuit.point_equal_gate(&witness.fee_ro.owner_addr.0, &witness.chg_ro.owner_addr.0)?;

        // Audit memo is correctly constructed when `viewer_pk` is not null
        let b_dummy_viewing_pk = pub_input.mint_policy.is_dummy_viewing_pk(&mut circuit)?;
        let b_correct_viewing_memo =
            Self::is_correct_viewing_memo(&mut circuit, &witness, &pub_input.viewing_memo)?;
        circuit.logic_or_gate(b_dummy_viewing_pk, b_correct_viewing_memo)?;

        let n_constraints = circuit.num_gates();
        circuit.finalize_for_arithmetization()?;
        Ok((Self(circuit), n_constraints))
    }

    /// Check whether a minting viewing memo has encrypted the correct data,
    /// returns "one" variable if valid, "zero" otherwise
    fn is_correct_viewing_memo(
        circuit: &mut PlonkCircuit<BaseField>,
        witness: &MintWitnessVar,
        viewing_memo: &ViewableMemoVar,
    ) -> Result<Variable, PlonkError> {
        // 1. Prepare message to be encrypted: note (amount, asset_code, policy) are
        // public, thus no need to encrypt
        let mint_ro = &witness.mint_ro;
        let message = vec![
            mint_ro.owner_addr.0.get_x(),
            mint_ro.owner_addr.0.get_y(),
            mint_ro.blind,
        ];

        // 2. Derive viewing memo.
        let derived_viewing_memo = ViewableMemoVar::derive(
            circuit,
            &witness.mint_ro.policy.viewer_pk,
            &message,
            witness.viewing_memo_enc_rand,
        )?;

        // 3. Compare derived viewing_memo with that in the public input.
        viewing_memo.is_equal(circuit, &derived_viewing_memo)
    }
}

#[derive(Debug)]
pub(crate) struct MintWitnessVar {
    pub(crate) mint_ro: RecordOpeningVar,
    pub(crate) creator_sk: Variable,
    pub(crate) fee_ro: RecordOpeningVar,
    pub(crate) acc_member_witness: AccMemberWitnessVar,
    pub(crate) chg_ro: RecordOpeningVar,
    pub(crate) ac_seed: Variable,
    pub(crate) ac_digest: Variable,
    pub(crate) viewing_memo_enc_rand: Variable,
}

impl MintWitnessVar {
    /// Create a variable for a minting witness
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<BaseField>,
        witness: &MintWitness,
    ) -> Result<Self, PlonkError> {
        let mint_ro = RecordOpeningVar::new(circuit, &witness.mint_ro)?;
        let creator_sk = circuit.create_variable(fr_to_fq::<_, CurveParam>(
            witness.creator_keypair.address_secret_ref(),
        ))?;
        let fee_ro = RecordOpeningVar::new(circuit, &witness.fee_ro)?;
        let acc_member_witness =
            AccMemberWitnessVar::new::<_, CurveParam>(circuit, &witness.acc_member_witness)?;
        let chg_ro = RecordOpeningVar::new(circuit, &witness.chg_ro)?;
        let ac_seed = circuit.create_variable(witness.ac_seed.0)?;
        let ac_digest = circuit.create_variable(witness.ac_digest.0)?;
        let viewing_memo_enc_rand =
            circuit.create_variable(fr_to_fq::<_, CurveParam>(&witness.viewing_memo_enc_rand))?;
        Ok(Self {
            mint_ro,
            creator_sk,
            fee_ro,
            acc_member_witness,
            chg_ro,
            ac_seed,
            ac_digest,
            viewing_memo_enc_rand,
        })
    }
}

#[derive(Debug)]
pub(crate) struct MintPubInputVar {
    pub(crate) root: Variable,
    pub(crate) native_asset_code: Variable,
    pub(crate) mint_amount: Variable,
    pub(crate) mint_ac: Variable,
    pub(crate) mint_internal_ac: Variable,
    pub(crate) mint_policy: AssetPolicyVar,
    pub(crate) mint_rc: Variable,
    pub(crate) chg_rc: Variable,
    pub(crate) fee: Variable,
    pub(crate) input_nullifier: Variable,
    pub(crate) viewing_memo: ViewableMemoVar,
}

impl MintPubInputVar {
    /// Create a minting public input variable.
    /// The order: (root, native_ac, input_nullifier, fee, mint_rc, chg_rc,
    /// mint_amount, mint_ac, mint_policy, viewing_memo)
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<BaseField>,
        pub_input: &MintPublicInput,
    ) -> Result<Self, PlonkError> {
        let root = circuit.create_public_variable(pub_input.merkle_root.to_scalar())?;
        let native_asset_code = circuit.create_public_variable(pub_input.native_asset_code.0)?;
        let input_nullifier = circuit.create_public_variable(pub_input.input_nullifier.0)?;
        let fee = circuit.create_public_variable(BaseField::from(pub_input.fee))?;
        let mint_rc = circuit.create_public_variable(pub_input.mint_rc.0)?;
        let chg_rc = circuit.create_public_variable(pub_input.chg_rc.0)?;
        let mint_amount = circuit.create_public_variable(BaseField::from(pub_input.mint_amount))?;
        let mint_ac = circuit.create_public_variable(pub_input.mint_ac.0)?;
        let mint_internal_ac = circuit.create_public_variable(pub_input.mint_internal_ac.0)?;
        let mint_policy = AssetPolicyVar::new(circuit, &pub_input.mint_policy)?;
        mint_policy.set_public(circuit)?;
        let viewing_memo = ViewableMemoVar::new(circuit, &pub_input.viewing_memo)?;
        viewing_memo.set_public(circuit)?;
        Ok(Self {
            root,
            native_asset_code,
            mint_amount,
            mint_ac,
            mint_internal_ac,
            mint_policy,
            mint_rc,
            chg_rc,
            fee,
            input_nullifier,
            viewing_memo,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{MintCircuit, MintPubInputVar, MintPublicInput, MintWitness};
    use crate::{
        errors::TxnApiError,
        keys::{UserKeyPair, ViewerKeyPair},
        structs::{
            AssetCode, AssetCodeDigest, AssetCodeSeed, AssetPolicy, CommitmentValue, FreezeFlag,
            InternalAssetCode, Nullifier, RecordCommitment, RecordOpening, ViewableMemo,
        },
        utils::params_builder::MintParamsBuilder,
        BaseField, ScalarField,
    };
    use ark_ff::Zero;
    use ark_std::{format, UniformRand};
    use jf_plonk::circuit::{Circuit, PlonkCircuit};
    use jf_primitives::merkle_tree::NodeValue;

    #[test]
    fn test_pub_input_to_scalars_order_consistency() {
        let rng = &mut ark_std::test_rng();
        let mint_ro = RecordOpening::rand_for_test(rng);
        let mint_internal_ac = InternalAssetCode::new(AssetCodeSeed::generate(rng), &[]);
        let mint_ac = AssetCode::new_domestic_from_internal(&mint_internal_ac);
        let pub_input = MintPublicInput {
            merkle_root: NodeValue::from_scalar(BaseField::from(10u8)),
            native_asset_code: AssetCode::native(),
            input_nullifier: Nullifier(BaseField::from(5u8)),
            fee: 8u64,
            mint_rc: RecordCommitment::from(&mint_ro),
            chg_rc: RecordCommitment::from(&RecordOpening::rand_for_test(rng)),
            mint_amount: 30u64,
            mint_ac,
            mint_internal_ac,
            mint_policy: AssetPolicy::rand_for_test(rng),
            viewing_memo: ViewableMemo::new_for_mint_note(&mint_ro, ScalarField::rand(rng)),
        };
        let pub_input_vec = pub_input.to_scalars();
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let _pub_input_var = MintPubInputVar::new(&mut circuit, &pub_input).unwrap(); // safe unwrap

        let circuit_pub_input = circuit.public_input().unwrap();
        assert_eq!(pub_input_vec.len(), circuit_pub_input.len());
        pub_input_vec
            .iter()
            .zip(circuit_pub_input.iter())
            .for_each(|(&a, &b)| assert_eq!(a, b));
    }

    #[test]
    fn test_mint_circuit_build() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let creator_keypair = UserKeyPair::generate(rng);
        let receiver_keypair = UserKeyPair::generate(rng);
        let viewer_keypair = ViewerKeyPair::generate(rng);
        let tree_depth = 2;
        let input_amount = 30;
        let fee = 20;
        let mint_amount = 10;
        let builder = MintParamsBuilder::new(
            rng,
            tree_depth,
            input_amount,
            fee,
            mint_amount,
            &creator_keypair,
            &receiver_keypair,
            &viewer_keypair,
        );

        let (witness, pub_input) = builder.build_witness_and_public_input(rng)?;
        check_mint_circuit(&witness, &pub_input, true)?;

        // bad path: wrong asset code seed
        {
            let mut bad_witness = witness.clone();
            bad_witness.ac_seed = AssetCodeSeed::generate(rng);
            let pub_input = MintPublicInput::from_witness(&witness)?;
            check_mint_circuit(&bad_witness, &pub_input, false)?;
        }

        // bad path: wrong asset code digest
        {
            let mut bad_witness = witness.clone();
            bad_witness.ac_digest = AssetCodeDigest::from_description(b"bad description");
            let pub_input = MintPublicInput::from_witness(&witness)?;
            check_mint_circuit(&bad_witness, &pub_input, false)?;
        }

        // bad path: frozen freeze_flag
        {
            let mut bad_witness = witness.clone();
            bad_witness.mint_ro.freeze_flag = FreezeFlag::Frozen;
            let pub_input = MintPublicInput::from_witness(&witness)?;
            check_mint_circuit(&bad_witness, &pub_input, false)?;

            let mut bad_witness = witness.clone();
            bad_witness.fee_ro.freeze_flag = FreezeFlag::Frozen;
            let pub_input = MintPublicInput::from_witness(&witness)?;
            check_mint_circuit(&bad_witness, &pub_input, false)?;

            let mut bad_witness = witness.clone();
            bad_witness.chg_ro.freeze_flag = FreezeFlag::Frozen;
            let pub_input = MintPublicInput::from_witness(&witness)?;
            check_mint_circuit(&bad_witness, &pub_input, false)?;
        }

        // bad path: non-dummy policy for input/change records
        {
            let mut bad_witness = witness.clone();
            bad_witness.fee_ro.asset_def.policy = AssetPolicy::rand_for_test(rng);
            let pub_input = MintPublicInput::from_witness(&witness)?;
            check_mint_circuit(&bad_witness, &pub_input, false)?;

            let mut bad_witness = witness.clone();
            bad_witness.chg_ro.asset_def.policy = AssetPolicy::rand_for_test(rng);
            let pub_input = MintPublicInput::from_witness(&witness)?;
            check_mint_circuit(&bad_witness, &pub_input, false)?;
        }

        // bad path: mint amount out of range
        {
            let mut bad_witness = witness.clone();
            bad_witness.fee_ro.amount = u64::max_value();
            let pub_input = MintPublicInput::from_witness(&witness)?;
            check_mint_circuit(&bad_witness, &pub_input, false)?;
        }

        // bad path: input and change records have different user addresses
        {
            let mut bad_witness = witness.clone();
            bad_witness.chg_ro.pub_key = UserKeyPair::generate(rng).pub_key();
            assert_ne!(bad_witness.fee_ro.pub_key, bad_witness.chg_ro.pub_key);
            let pub_input = MintPublicInput::from_witness(&witness)?;
            check_mint_circuit(&bad_witness, &pub_input, false)?;
        }

        // bad path: fee + change != input amount
        {
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.fee += 1;
            check_mint_circuit(&witness, &bad_pub_input, false)?;
        }

        // bad path: mint or change commitment is not well-formed
        {
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.mint_rc = RecordCommitment(CommitmentValue::rand(rng));
            check_mint_circuit(&witness, &bad_pub_input, false)?;

            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.chg_rc = RecordCommitment(CommitmentValue::rand(rng));
            check_mint_circuit(&witness, &bad_pub_input, false)?;
        }

        // bad path: wrong merkle root
        {
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.merkle_root = NodeValue::default();
            check_mint_circuit(&witness, &bad_pub_input, false)?;
        }

        // bad path: inconsistent public mint amount/asset_code/policy
        {
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.mint_amount = mint_amount + 1;
            check_mint_circuit(&witness, &bad_pub_input, false)?;

            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.mint_internal_ac =
                InternalAssetCode::new(AssetCodeSeed::generate(rng), &[]);
            check_mint_circuit(&witness, &bad_pub_input, false)?;

            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.mint_policy = AssetPolicy::rand_for_test(rng);
            check_mint_circuit(&witness, &bad_pub_input, false)?;
        }

        // bad path: inconsistent native asset code
        {
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.native_asset_code = AssetCode::random(rng).0;
            check_mint_circuit(&witness, &bad_pub_input, false)?;
        }

        // bad path: wrong viewing memo
        {
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.viewing_memo =
                ViewableMemo::new_for_mint_note(&witness.mint_ro, ScalarField::zero());
            check_mint_circuit(&witness, &bad_pub_input, false)?;
        }

        Ok(())
    }

    fn check_mint_circuit(
        witness: &MintWitness,
        pub_input: &MintPublicInput,
        witness_is_valid: bool,
    ) -> Result<(), TxnApiError> {
        let (circuit, _) = MintCircuit::build(witness, pub_input)
            .map_err(|e| TxnApiError::FailedSnark(format!("{}", e)))?;
        let pub_input_vec = pub_input.to_scalars();
        let result = circuit.0.check_circuit_satisfiability(&pub_input_vec[..]);
        if witness_is_valid {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
        Ok(())
    }
}
