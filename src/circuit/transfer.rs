// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Circuit for user configurable asset privacy transfer.
use super::structs::{AssetPolicyVar, ExpirableCredVar, RecordOpeningVar, ViewableMemoVar};
use crate::{
    circuit::{
        gadgets::{Spender, TransactionGadgets},
        structs::UserAddressVar,
    },
    constants::{AMOUNT_LEN, ASSET_TRACING_MAP_LEN, VIEWABLE_DATA_LEN},
    errors::TxnApiError,
    keys::UserKeyPair,
    prelude::CapConfig,
    proof::transfer::{InputSecret, TransferPublicInput, TransferWitness},
};
use ark_ff::Zero;
use ark_std::{format, string::ToString, vec, vec::Vec};
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::{CircuitError::InternalError, PlonkError},
};
use jf_primitives::circuit::merkle_tree::AccMemberWitnessVar;
use jf_utils::fr_to_fq;

pub(crate) struct TransferCircuit<C: CapConfig>(pub(crate) PlonkCircuit<C::ScalarField>);

impl<C: CapConfig> TransferCircuit<C> {
    /// Build a circuit during preprocessing for derivation of proving key and
    /// verifying key.
    pub(crate) fn build_for_preprocessing(
        num_input: usize,
        num_output: usize,
        tree_depth: u8,
    ) -> Result<(Self, usize), TxnApiError> {
        let user_keypair = UserKeyPair::default();
        let dummy_witness =
            TransferWitness::dummy(num_input, num_output, tree_depth, &user_keypair);
        let valid_until = 0;
        let dummy_pub_input = TransferPublicInput::from_witness(&dummy_witness, valid_until)?;

        Self::build(&dummy_witness, &dummy_pub_input)
            .map_err(|e| TxnApiError::FailedSnark(format!("{:?}", e)))
    }

    /// Build the circuit given a satisfiable assignment of
    /// secret witness and public inputs.
    pub(crate) fn build(
        witness: &TransferWitness<C>,
        pub_input: &TransferPublicInput<C>,
    ) -> Result<(Self, usize), PlonkError> {
        if witness.input_secrets.is_empty() {
            return Err(PlonkError::CircuitError(InternalError(
                "the number of transfer inputs cannot be zero".to_string(),
            )));
        }
        if witness.output_record_openings.is_empty() {
            return Err(PlonkError::CircuitError(InternalError(
                "the number of transfer outputs cannot be zero".to_string(),
            )));
        }

        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let witness = TransferWitnessVar::new(&mut circuit, witness)?;
        let pub_input = TransferPubInputVar::new(&mut circuit, pub_input)?;

        for (i, (input, &expected_nl)) in witness
            .input_secrets
            .iter()
            .zip(pub_input.input_nullifiers.iter())
            .enumerate()
        {
            // The input is not frozen.
            circuit.constant_gate(input.ro.freeze_flag, C::ScalarField::zero())?;
            // check if record is dummy
            let is_dummy_record = input.ro.check_asset_code_dummy(&mut circuit)?;
            let is_zero_amount = circuit.check_is_zero(input.ro.amount)?;
            // if records is dummy, then amount must be zero
            // That is, check that either record is not dummy or the amount is zero
            let not_dummy_record = circuit.logic_neg(is_dummy_record)?;
            circuit.logic_or_gate(not_dummy_record, is_zero_amount)?;

            // The first input is with native asset code and is for txn fees.
            if i == 0 {
                circuit.equal_gate(input.ro.asset_code, pub_input.native_asset_code)?;
                input.ro.policy.enforce_dummy_policy(&mut circuit)?;
            } else {
                // if asset type code is dummy, then policy must be dummy
                let is_dummy_policy = input.ro.policy.is_dummy_policy(&mut circuit)?;
                circuit.logic_or_gate(not_dummy_record, is_dummy_policy)?;
                // if asset type code is not dummy, then policy must be the transfers note
                // policy
                let is_equal_policy = input
                    .ro
                    .policy
                    .check_equal_policy(&mut circuit, &witness.policy)?;
                circuit.logic_or_gate(is_dummy_record, is_equal_policy)?;
            }

            let (nullifier, root) = circuit.prove_spend(
                &input.ro,
                &input.acc_member_witness,
                input.addr_secret,
                Spender::User,
            )?;

            circuit.equal_gate(nullifier, expected_nl)?;

            let is_correct_root = circuit.check_equal(root, pub_input.root)?;
            // if dummy, root is allowed to be incorrect
            circuit.logic_or_gate(is_dummy_record, is_correct_root)?;

            // Check credential if credential creator's cred_pk is present.
            let b_dummy_cred_pk = input.ro.policy.is_dummy_cred_pk(&mut circuit)?;
            let b_cred_vfy = input.cred.verify(&mut circuit, pub_input.valid_until)?;
            circuit.logic_or_gate(b_dummy_cred_pk, b_cred_vfy)?;
        }

        for (i, (output_ro, &expected_rc)) in witness
            .output_record_openings
            .iter()
            .zip(pub_input.output_commitments.iter())
            .enumerate()
        {
            // The output is not frozen.
            circuit.constant_gate(output_ro.freeze_flag, C::ScalarField::zero())?;
            // The first output is with native asset code and is for txn fees
            if i == 0 {
                circuit.equal_gate(output_ro.asset_code, pub_input.native_asset_code)?;
                output_ro.policy.enforce_dummy_policy(&mut circuit)?;
            } else {
                circuit.equal_gate(output_ro.asset_code, witness.asset_code)?;
                output_ro
                    .policy
                    .enforce_equal_policy(&mut circuit, &witness.policy)?;
            }

            // commitment
            let rc_out = output_ro.compute_record_commitment(&mut circuit)?;
            circuit.equal_gate(rc_out, expected_rc)?;

            // Range-check `amount`
            // Note we don't need to range-check inputs' `amount`, because those amounts are
            // bound to inputs' accumulated ars, whose underlying amounts have
            // already been range-checked in the transactions that created the
            // inputs' ars.
            circuit.range_gate(output_ro.amount, AMOUNT_LEN)?;
        }

        // The amount balance is preserved
        let amounts_in: Vec<Variable> = witness
            .input_secrets
            .iter()
            .map(|input| input.ro.amount)
            .collect();
        let amounts_out: Vec<Variable> = witness
            .output_record_openings
            .iter()
            .map(|ro| ro.amount)
            .collect();

        let transfer_amount = circuit.preserve_balance(
            pub_input.native_asset_code,
            witness.asset_code,
            pub_input.fee,
            &amounts_in,
            &amounts_out,
        )?;

        // Viewer memo is correctly constructed when `viewer_pk` is not null and
        // `transfer_amount > asset_policy.reveal_threshold`
        let amount_diff = circuit.sub(witness.policy.reveal_threshold, transfer_amount)?;
        let b_under_limit = circuit.check_in_range(amount_diff, AMOUNT_LEN)?;
        let b_dummy_viewing_pk = witness.policy.is_dummy_viewing_pk(&mut circuit)?;
        let under_limit_or_dummy_viewing_pk =
            circuit.logic_or(b_under_limit, b_dummy_viewing_pk)?;
        let b_correct_viewing_memo =
            Self::is_correct_viewing_memo(&mut circuit, &witness, &pub_input)?;
        circuit.logic_or_gate(under_limit_or_dummy_viewing_pk, b_correct_viewing_memo)?;

        let n_constraints = circuit.num_gates();
        circuit.finalize_for_arithmetization()?;
        Ok((Self(circuit), n_constraints))
    }

    /// Check whether a transfer viewing memo has encrypted the correct data,
    /// returns "one" variable if valid, "zero" otherwise
    fn is_correct_viewing_memo(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        witness: &TransferWitnessVar,
        pub_input: &TransferPubInputVar,
    ) -> Result<Variable, PlonkError> {
        // 1. Prepare message to be encrypted
        let mut message: Vec<Variable> = vec![witness.asset_code];
        let reveal_map_vars: Vec<Variable> = circuit.unpack(witness.policy.reveal_map, VIEWABLE_DATA_LEN)?
                                            .into_iter()
                                            .rev() // unpack is in little endian
                                            .collect();
        let dummy_key = UserAddressVar::dummy(circuit);
        for input in witness.input_secrets.iter().skip(1) {
            let is_dummy_record = input.ro.check_asset_code_dummy(circuit)?;
            // if record is dummy, then add dummy key to audit memo so that auditor can
            // recognize dummy records by looking at the key
            let addr_x = circuit.conditional_select(
                is_dummy_record,
                input.ro.owner_addr.0.get_x(),
                dummy_key.0.get_x(),
            )?;
            let addr_y = circuit.conditional_select(
                is_dummy_record,
                input.ro.owner_addr.0.get_y(),
                dummy_key.0.get_y(),
            )?;

            let mut vals = vec![addr_x, addr_y, input.ro.amount, input.ro.blind];
            let mut bit_map_vars = reveal_map_vars[..ASSET_TRACING_MAP_LEN].to_vec();
            // id viewing fields
            for (attr, reveal_bit) in input
                .cred
                .attrs
                .iter()
                .zip(reveal_map_vars.iter().skip(ASSET_TRACING_MAP_LEN))
            {
                vals.push(attr.0);
                bit_map_vars.push(*reveal_bit);
            }

            // reveal if dummy or reveal_bit
            let actual_reveal_bit = circuit.logic_or(is_dummy_record, reveal_map_vars[0])?;
            // it is guaranteed at this point that bit_map_vars[0] == bitmap_vars[1]
            bit_map_vars[0] = actual_reveal_bit;
            bit_map_vars[1] = actual_reveal_bit;

            let revealed_vals = circuit.hadamard_product(&bit_map_vars, &vals)?;
            message.extend_from_slice(&revealed_vals[..]);
        }
        for output_ro in witness.output_record_openings.iter().skip(1) {
            // asset viewing fields
            let vals = vec![
                output_ro.owner_addr.0.get_x(),
                output_ro.owner_addr.0.get_y(),
                output_ro.amount,
                output_ro.blind,
            ];

            let revealed_vals =
                circuit.hadamard_product(&reveal_map_vars[..ASSET_TRACING_MAP_LEN], &vals)?;
            message.extend_from_slice(&revealed_vals[..]);
        }

        // 2. Derive viewing memo.
        let derived_viewing_memo = ViewableMemoVar::derive(
            circuit,
            &witness.policy.viewer_pk,
            &message,
            witness.viewing_memo_enc_rand,
        )?;

        // 3. Compare derived viewing_memo with that in the public input.
        pub_input
            .viewing_memo
            .check_equal(circuit, &derived_viewing_memo)
    }
}

#[derive(Debug)]
pub(crate) struct TransferWitnessVar {
    pub(crate) asset_code: Variable,   // transfer asset code
    pub(crate) policy: AssetPolicyVar, // transfer policy
    pub(crate) input_secrets: Vec<InputSecretVar>,
    pub(crate) output_record_openings: Vec<RecordOpeningVar>,
    pub(crate) viewing_memo_enc_rand: Variable,
}

impl TransferWitnessVar {
    /// Create a variable for a transfer witness
    pub(crate) fn new<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        witness: &TransferWitness<C>,
    ) -> Result<Self, PlonkError> {
        let asset_code = circuit.create_variable(witness.asset_def.code.0)?;
        let policy = AssetPolicyVar::new(circuit, &witness.asset_def.policy)?;
        let input_secrets = witness
            .input_secrets
            .iter()
            .map(|input_secret| InputSecretVar::new(circuit, input_secret))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let output_record_openings = witness
            .output_record_openings
            .iter()
            .map(|ro| RecordOpeningVar::new(circuit, ro))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let viewing_memo_enc_rand = circuit.create_variable(
            fr_to_fq::<_, C::EmbeddedCurveParam>(&witness.viewing_memo_enc_rand),
        )?;
        Ok(Self {
            asset_code,
            policy,
            input_secrets,
            output_record_openings,
            viewing_memo_enc_rand,
        })
    }
}

#[derive(Debug)]
pub(crate) struct TransferPubInputVar {
    pub(crate) root: Variable,
    pub(crate) native_asset_code: Variable,
    pub(crate) valid_until: Variable,
    pub(crate) fee: Variable,
    pub(crate) input_nullifiers: Vec<Variable>,
    pub(crate) output_commitments: Vec<Variable>,
    pub(crate) viewing_memo: ViewableMemoVar,
}

impl TransferPubInputVar {
    /// Create a transfer public input variable.
    pub(crate) fn new<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        pub_input: &TransferPublicInput<C>,
    ) -> Result<Self, PlonkError> {
        let root = circuit.create_public_variable(pub_input.merkle_root.to_scalar())?;
        let native_asset_code = circuit.create_public_variable(pub_input.native_asset_code.0)?;
        let valid_until =
            circuit.create_public_variable(C::ScalarField::from(pub_input.valid_until))?;
        let fee = circuit.create_public_variable(C::ScalarField::from(pub_input.fee.0))?;
        let input_nullifiers = pub_input
            .input_nullifiers
            .iter()
            .map(|&nl| circuit.create_public_variable(nl.0))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let output_commitments = pub_input
            .output_commitments
            .iter()
            .map(|rc| circuit.create_public_variable(rc.0))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let viewing_memo = ViewableMemoVar::new(circuit, &pub_input.viewing_memo)?;
        viewing_memo.set_public(circuit)?;
        Ok(Self {
            root,
            native_asset_code,
            valid_until,
            fee,
            input_nullifiers,
            output_commitments,
            viewing_memo,
        })
    }
}

#[derive(Debug)]
pub(crate) struct InputSecretVar {
    pub(crate) addr_secret: Variable,
    pub(crate) ro: RecordOpeningVar,
    pub(crate) acc_member_witness: AccMemberWitnessVar,
    pub(crate) cred: ExpirableCredVar,
}

impl InputSecretVar {
    /// Create a variable for a transfer input secret.
    pub(crate) fn new<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        input_secret: &InputSecret<C>,
    ) -> Result<Self, PlonkError> {
        let addr_secret = circuit.create_variable(fr_to_fq::<_, C::EmbeddedCurveParam>(
            input_secret.owner_keypair.address_secret_ref(),
        ))?;
        let ro = RecordOpeningVar::new(circuit, &input_secret.ro)?;
        let cred = ExpirableCredVar::new(circuit, &input_secret.cred)?;
        let acc_member_witness = AccMemberWitnessVar::new::<_, C::EmbeddedCurveParam>(
            circuit,
            &input_secret.acc_member_witness,
        )?;
        Ok(Self {
            addr_secret,
            ro,
            acc_member_witness,
            cred,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{TransferCircuit, TransferPubInputVar, TransferPublicInput, TransferWitness};
    use crate::{
        keys::UserKeyPair,
        prelude::{CapConfig, Config},
        structs::{
            Amount, AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy, ExpirableCredential,
            FreezeFlag, Nullifier, RecordCommitment, RecordOpening, ViewableMemo,
        },
        utils::params_builder::TransferParamsBuilder,
    };
    use ark_ff::Zero;
    use ark_std::{vec, vec::Vec, UniformRand};
    use jf_plonk::{
        circuit::{Circuit, PlonkCircuit},
        errors::PlonkError,
    };
    use jf_primitives::merkle_tree::{MerklePathNode, NodeValue};

    type F = <Config as CapConfig>::ScalarField;
    type Fj = <Config as CapConfig>::EmbeddedCurveScalarField;

    #[test]
    fn test_pub_input_to_scalars_order_consistency() {
        let rng = &mut ark_std::test_rng();
        let mut input_ros = vec![RecordOpening::rand_for_test(rng); 5];
        input_ros[0].asset_def = AssetDefinition::native();
        let output_ros = vec![RecordOpening::rand_for_test(rng); 4];
        let input_creds = vec![ExpirableCredential::dummy_unexpired().unwrap(); 5];
        let randomizer = Fj::rand(rng);
        let pub_input = TransferPublicInput {
            merkle_root: NodeValue::from_scalar(F::from(10u8)),
            native_asset_code: AssetCode::native(),
            valid_until: 123u64,
            fee: Amount::from(8u64),
            input_nullifiers: vec![Nullifier(F::from(2u8)); 5],
            output_commitments: vec![RecordCommitment::from(&output_ros[0]); 4],
            viewing_memo: ViewableMemo::new_for_transfer_note(
                &input_ros,
                &output_ros,
                &input_creds,
                randomizer,
            )
            .unwrap(),
        };
        let pub_input_vec = pub_input.to_scalars();
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let _pub_input_var = TransferPubInputVar::new(&mut circuit, &pub_input).unwrap(); // safe unwrap

        let circuit_pub_input = circuit.public_input().unwrap();
        assert_eq!(pub_input_vec.len(), circuit_pub_input.len());
        pub_input_vec
            .iter()
            .zip(circuit_pub_input.iter())
            .for_each(|(&a, &b)| assert_eq!(a, b));
    }

    #[test]
    fn test_threshold_policy() -> Result<(), PlonkError> {
        let rng = &mut ark_std::test_rng();
        let cred_expiry = 9998u64;
        let user_keypair = UserKeyPair::generate(rng);
        let user_keypairs = vec![&user_keypair; 3];

        // transfer amount doesn't exceed the limit, the policy won't be applied
        let builder = TransferParamsBuilder::new_non_native(3, 3, Some(2), user_keypairs.clone())
            .set_reveal_threshold(Amount::from(30u64))
            .set_input_amounts(
                Amount::from(30u64),
                &[Amount::from(20u64), Amount::from(10u64)],
            )
            .set_output_amounts(
                Amount::from(19u64),
                &[Amount::from(17u64), Amount::from(13u64)],
            )
            .set_input_creds(cred_expiry);
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, true)?;
        assert_eq!(
            pub_input.viewing_memo,
            ViewableMemo::dummy_for_transfer_note(
                witness.input_secrets.len(),
                witness.output_record_openings.len(),
                witness.viewing_memo_enc_rand
            )
        );

        // transfer amount exceeds the limit, the policy will be applied
        let builder = TransferParamsBuilder::new_non_native(3, 3, Some(2), user_keypairs.clone())
            .set_reveal_threshold(Amount::from(20u64))
            .set_input_amounts(
                Amount::from(30u64),
                &[Amount::from(20u64), Amount::from(10u64)],
            )
            .set_output_amounts(
                Amount::from(19u64),
                &[Amount::from(17u64), Amount::from(13u64)],
            )
            .set_input_creds(cred_expiry);
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, true)?;
        let input_ros: Vec<_> = witness
            .input_secrets
            .iter()
            .map(|secret| secret.ro.clone())
            .collect();
        let output_ros = witness.output_record_openings.clone();
        let input_creds: Vec<_> = witness
            .input_secrets
            .iter()
            .map(|secret| secret.cred.clone())
            .collect();
        assert_eq!(
            pub_input.viewing_memo,
            ViewableMemo::new_for_transfer_note(
                &input_ros,
                &output_ros,
                &input_creds,
                witness.viewing_memo_enc_rand
            )
            .unwrap()
        );

        // no threshold policy, viewing policy is always applied
        let builder = TransferParamsBuilder::new_non_native(3, 3, Some(2), user_keypairs)
            .set_reveal_threshold(Amount::from(0u64))
            .set_input_amounts(
                Amount::from(1u64),
                &[Amount::from(2u64), Amount::from(1u64)],
            )
            .set_output_amounts(
                Amount::from(1u64),
                &[Amount::from(1u64), Amount::from(2u64)],
            )
            .set_input_creds(cred_expiry);
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, true)?;
        let input_ros: Vec<_> = witness
            .input_secrets
            .iter()
            .map(|secret| secret.ro.clone())
            .collect();
        let output_ros = witness.output_record_openings.clone();
        let input_creds: Vec<_> = witness
            .input_secrets
            .iter()
            .map(|secret| secret.cred.clone())
            .collect();
        assert_eq!(
            pub_input.viewing_memo,
            ViewableMemo::new_for_transfer_note(
                &input_ros,
                &output_ros,
                &input_creds,
                witness.viewing_memo_enc_rand
            )
            .unwrap()
        );

        Ok(())
    }
    #[test]
    fn test_transfer_circuit_build() -> Result<(), PlonkError> {
        let rng = &mut ark_std::test_rng();
        let cred_expiry = 9998u64;
        let user_keypair = UserKeyPair::generate(rng);
        let user_keypairs = vec![&user_keypair; 2];
        // bad path: output amount out of range
        let builder = TransferParamsBuilder::new_non_native(2, 2, Some(2), user_keypairs)
            .set_input_amounts(Amount::from(30u64), &[Amount::from(u128::MAX - 100)])
            .set_output_amounts(Amount::from(19u64), &[Amount::from(u128::MAX - 100)])
            .set_input_creds(cred_expiry);
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, false)?;

        // good path
        let user_keypair = UserKeyPair::generate(rng);
        let user_keypairs = vec![&user_keypair; 3];
        let builder = TransferParamsBuilder::new_non_native(3, 3, Some(2), user_keypairs)
            .set_input_amounts(
                Amount::from(30u64),
                &[Amount::from(20u64), Amount::from(10u64)],
            )
            .set_output_amounts(
                Amount::from(19u64),
                &[Amount::from(17u64), Amount::from(13u64)],
            )
            .set_input_creds(cred_expiry);
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, true)?;

        // bad path: wrong freeze_flag
        let builder = builder.update_input_freeze_flag(0, FreezeFlag::Frozen);
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, false)?;
        let builder = builder.update_input_freeze_flag(0, FreezeFlag::Unfrozen);

        // bad path: wrong asset definition for the 1st input/output,
        // TODO this cannot be tested as we cannot build public input for non_native fee
        // input let builder =
        // builder.update_fee_input_asset_def(AssetDefinition::default());
        // let (witness, pub_input) = create_witness_and_pub_input(&builder);
        // check_transfer_circuit(&witness, &pub_input, false)?;
        // let native_asset_def = AssetDefinition::native();
        // let builder = builder.update_fee_input_asset_def(native_asset_def);
        // return Ok(());

        // bad path: multiple non-native asset codes
        let builder = builder.update_input_asset_def(
            0,
            AssetDefinition::new(
                AssetCode::new_domestic(AssetCodeSeed::generate(rng), b"other digest"),
                AssetPolicy::default(),
            )
            .unwrap(),
        );
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, false)?;
        let transfer_asset_def = builder
            .transfer_asset_def
            .as_ref()
            .unwrap()
            .asset_def
            .clone();
        let builder = builder.update_input_asset_def(0, transfer_asset_def);

        // bad path: wrong balance
        let builder = builder.update_input_amount(0, Amount::from(100u64));
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, false)?;
        let builder = builder.update_input_amount(0, Amount::from(20u64));

        // bad path: wrong output commitment
        let (witness, mut pub_input) = create_witness_and_pub_input(&builder);
        pub_input.output_commitments[0] = RecordCommitment(F::zero());
        check_transfer_circuit(&witness, &pub_input, false)?;

        // bad path: wrong merkle root
        let (witness, mut pub_input) = create_witness_and_pub_input(&builder);
        pub_input.merkle_root = NodeValue::default();
        check_transfer_circuit(&witness, &pub_input, false)?;

        // bad path: wrong input nullifier
        let (witness, mut pub_input) = create_witness_and_pub_input(&builder);
        pub_input.input_nullifiers[0].0 = F::zero();
        check_transfer_circuit(&witness, &pub_input, false)?;

        // bad path: wrong txn fee
        let (witness, mut pub_input) = create_witness_and_pub_input(&builder);
        pub_input.fee = Amount::from(21u128);
        check_transfer_circuit(&witness, &pub_input, false)?;

        // bad path: expired credential
        let (witness, mut pub_input) = create_witness_and_pub_input(&builder);
        pub_input.valid_until = 10000u64;
        check_transfer_circuit(&witness, &pub_input, false)?;

        // bad path: wrong viewing memo
        let (witness, mut pub_input) = create_witness_and_pub_input(&builder);
        let input_ros: Vec<_> = witness
            .input_secrets
            .iter()
            .map(|secret| secret.ro.clone())
            .collect();
        let output_ros = witness.output_record_openings.clone();
        let input_creds: Vec<_> = witness
            .input_secrets
            .iter()
            .map(|secret| secret.cred.clone())
            .collect();
        // replace with an viewing memo encrypted with a wrong randomizer
        pub_input.viewing_memo =
            ViewableMemo::new_for_transfer_note(&input_ros, &output_ros, &input_creds, Fj::zero())
                .unwrap(); // safe unwrap
        check_transfer_circuit(&witness, &pub_input, false)?;

        Ok(())
    }

    #[test]
    fn test_transfer_circuit_build_with_dummy_records() -> Result<(), PlonkError> {
        let rng = &mut ark_std::test_rng();
        let cred_expiry = 9998u64;
        let user_keypair = UserKeyPair::generate(rng);
        let user_keypairs = vec![&user_keypair, &user_keypair, &user_keypair];
        let builder = TransferParamsBuilder::new_non_native(3, 3, Some(2), user_keypairs)
            .set_input_amounts(
                Amount::from(30u64),
                &[Amount::from(30u64), Amount::from(0u64)],
            )
            .set_output_amounts(
                Amount::from(19u64),
                &[Amount::from(17u64), Amount::from(13u64)],
            )
            .set_input_creds(cred_expiry);
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, true)?;

        // wrong asset definition
        let builder = builder
            .update_input_asset_def(1, AssetDefinition::default())
            .set_input_creds(cred_expiry);
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, false)?;

        // test 1: dummy record with non-zero amount should fail
        let user_keypairs = vec![&user_keypair, &user_keypair, &user_keypair];
        let mut builder = TransferParamsBuilder::new_non_native(3, 3, Some(2), user_keypairs)
            .set_input_amounts(
                Amount::from(30u64),
                &[Amount::from(30u64), Amount::from(0u64)],
            )
            .set_output_amounts(
                Amount::from(19u64),
                &[Amount::from(17u64), Amount::from(13u64)],
            )
            .set_dummy_input_record(1)
            .set_input_creds(cred_expiry);
        builder.input_ros[2].amount = Amount::from(10u64); // need to update amount AFTER setting dummy input
        let (witness, pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, false)?;

        // test 2: dummy record with 0 amount should pass
        let user_keypairs = vec![&user_keypair, &user_keypair, &user_keypair];
        let builder = TransferParamsBuilder::new_non_native(3, 3, Some(2), user_keypairs)
            .set_input_amounts(
                Amount::from(30u64),
                &[Amount::from(30u64), Amount::from(0u64)],
            )
            .set_output_amounts(
                Amount::from(19u64),
                &[Amount::from(17u64), Amount::from(13u64)],
            )
            .set_dummy_input_record(1)
            .set_input_creds(cred_expiry);
        let (mut witness, mut pub_input) = create_witness_and_pub_input(&builder);
        check_transfer_circuit(&witness, &pub_input, true)?;

        // bad merkle path shouldn't affect satisfiability
        assert_ne!(witness.input_secrets[2].acc_member_witness.uid, 0);
        assert_ne!(
            witness.input_secrets[2].acc_member_witness.root,
            NodeValue::from(0)
        );
        witness.input_secrets[2].acc_member_witness.uid = 0;
        witness.input_secrets[2].acc_member_witness.root = NodeValue::from(0);
        witness.input_secrets[2]
            .acc_member_witness
            .merkle_path
            .nodes[0] = MerklePathNode::default();
        let dummy_record_commitment = builder.input_ros[2].derive_record_commitment();
        let dummy_nullifier =
            builder.input_keypairs[2].nullify(&Default::default(), 0, &dummy_record_commitment);
        pub_input.input_nullifiers[2] = dummy_nullifier;
        check_transfer_circuit(&witness, &pub_input, true)?;
        Ok(())
    }

    fn create_witness_and_pub_input<'a>(
        builder: &'a TransferParamsBuilder<Config>,
    ) -> (TransferWitness<'a, Config>, TransferPublicInput<Config>) {
        let rng = &mut ark_std::test_rng();
        let witness = builder.build_witness(rng);
        let valid_until = 1234u64;
        let pub_input = TransferPublicInput::from_witness(&witness, valid_until).unwrap();
        (witness, pub_input)
    }

    fn check_transfer_circuit(
        witness: &TransferWitness<Config>,
        pub_input: &TransferPublicInput<Config>,
        witness_is_valid: bool,
    ) -> Result<(), PlonkError> {
        let pub_input_vec = pub_input.to_scalars();
        let (circuit, _) = TransferCircuit::build(witness, pub_input)?;
        let verify = circuit.0.check_circuit_satisfiability(&pub_input_vec[..]);

        if !witness_is_valid {
            if verify.is_ok() {
                Err(PlonkError::WrongProof) // some error
            } else {
                Ok(())
            }
        } else {
            verify
        }
    }
}
