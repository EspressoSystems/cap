// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Circuit for the freezing/releasing of user configurable
//! asset.
use crate::{
    circuit::{
        gadgets::{Spender, TransactionGadgets},
        structs::RecordOpeningVar,
    },
    errors::TxnApiError,
    keys::{FreezerKeyPair, UserKeyPair},
    prelude::CapConfig,
    proof::freeze::{FreezePublicInput, FreezeWitness},
};
use ark_ff::Zero;
use ark_std::{format, rand::SeedableRng, string::ToString, vec::Vec};
use jf_primitives::circuit::merkle_tree::AccMemberWitnessVar;
use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit, Variable};
use jf_utils::fr_to_fq;

pub(crate) struct FreezeCircuit<C: CapConfig>(pub(crate) PlonkCircuit<C::ScalarField>);

impl<C: CapConfig> FreezeCircuit<C> {
    /// Build a circuit during preprocessing for derivation of proving key and
    /// verifying key.
    pub(crate) fn build_for_preprocessing(
        tree_depth: u8,
        num_input: usize,
    ) -> Result<(Self, usize), TxnApiError> {
        let fee_keypair = UserKeyPair::default();
        let rng = &mut ark_std::rand::rngs::StdRng::from_seed([0u8; 32]);
        let freezing_keypair = FreezerKeyPair::generate(rng);
        let dummy_witness =
            FreezeWitness::dummy(tree_depth, num_input, &fee_keypair, &freezing_keypair);
        let pub_input = FreezePublicInput::from_witness(&dummy_witness)?;
        Self::build_unchecked(&dummy_witness, &pub_input)
            .map_err(|e| TxnApiError::FailedSnark(format!("{:?}", e)))
    }

    /// Build the circuit given a satisfiable assignment of
    /// secret witness.
    pub(crate) fn build(
        witness: &FreezeWitness<C>,
        pub_input: &FreezePublicInput<C>,
    ) -> Result<(Self, usize), TxnApiError> {
        // We didn't put this check inside `FreezePublicInput::from_witness` for ease of
        // testing.
        for (input_ro, output_ro) in witness
            .input_ros
            .iter()
            .skip(1)
            .zip(witness.output_ros.iter().skip(1))
        {
            if input_ro.freeze_flag == output_ro.freeze_flag {
                return Err(TxnApiError::InvalidParameter(
                    "the input/output freezing bits should be flipped".to_string(),
                ));
            }
        }
        Self::build_unchecked(witness, pub_input)
            .map_err(|e| TxnApiError::FailedSnark(e.to_string()))
    }

    /// This is only used for testing or called internally by `Self::build()`
    fn build_unchecked(
        witness: &FreezeWitness<C>,
        pub_input: &FreezePublicInput<C>,
    ) -> Result<(Self, usize), CircuitError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let witness = FreezeWitnessVar::new(&mut circuit, witness)?;
        let pub_input = FreezePubInputVar::new(&mut circuit, pub_input)?;

        // Check the first input/output for charging fee
        let first_input = &witness.input_ros[0];
        let first_output = &witness.output_ros[0];
        // The first input/output are with native asset definition
        circuit.enforce_equal(first_input.asset_code, pub_input.native_asset_code)?;
        first_input.policy.enforce_dummy_policy::<C>(&mut circuit)?;
        circuit.enforce_equal(first_output.asset_code, pub_input.native_asset_code)?;
        first_output
            .policy
            .enforce_dummy_policy::<C>(&mut circuit)?;
        // The first input/output are not frozen
        let unfrozen = C::ScalarField::zero();
        circuit.enforce_constant(first_input.freeze_flag.into(), unfrozen)?;
        circuit.enforce_constant(first_output.freeze_flag.into(), unfrozen)?;
        // Fee balance
        circuit.add_gate(first_output.amount, pub_input.fee, first_input.amount)?;
        // Proof of spending
        let (nullifier, root) = TransactionGadgets::<C>::prove_spend(
            &mut circuit,
            first_input,
            &witness.input_acc_member_witnesses[0],
            witness.fee_sk,
            Spender::User,
        )?;
        circuit.enforce_equal(root, pub_input.merkle_root)?;
        circuit.enforce_equal(nullifier, pub_input.input_nullifiers[0])?;

        // Check freezing inputs/outputs consistency
        for (ro_in, ro_out) in witness
            .input_ros
            .iter()
            .skip(1)
            .zip(witness.output_ros.iter().skip(1))
        {
            // Freezing flag flipped
            circuit.add_gate(
                ro_in.freeze_flag.into(),
                ro_out.freeze_flag.into(),
                circuit.one(),
            )?;
            // Output ro preserves the amount, address, asset definition of input ro
            circuit.enforce_equal(ro_in.amount, ro_out.amount)?;
            circuit.enforce_point_equal(&ro_in.owner_addr.0, &ro_out.owner_addr.0)?;
            circuit.enforce_equal(ro_in.asset_code, ro_out.asset_code)?;
            ro_in
                .policy
                .enforce_equal_policy::<C>(&mut circuit, &ro_out.policy)?;
        }

        // Check output commitments correctness
        for (ro_out, &expected_comm) in witness
            .output_ros
            .iter()
            .zip(pub_input.output_commitments.iter())
        {
            let rc_out = ro_out.compute_record_commitment::<C>(&mut circuit)?;
            circuit.enforce_equal(rc_out, expected_comm)?;
        }

        // Check freezing inputs
        for ((ro_in, acc_wit_in), (&freeze_sk, &expected_nl)) in witness
            .input_ros
            .iter()
            .skip(1)
            .zip(witness.input_acc_member_witnesses.iter().skip(1))
            .zip(
                witness
                    .freezing_sks
                    .iter()
                    .zip(pub_input.input_nullifiers.iter().skip(1)),
            )
        {
            // Freezing public key cannot be dummy, unless record is dummy
            let b_dummy_freeze_pk = ro_in.policy.is_dummy_freezer_pk::<C>(&mut circuit)?;
            let b_not_dummy_freeze_pk = circuit.logic_neg(b_dummy_freeze_pk)?;
            let b_is_dummy_ro = ro_in.check_asset_code_dummy::<C>(&mut circuit)?;
            circuit.logic_or_gate(b_not_dummy_freeze_pk, b_is_dummy_ro)?;

            // Proof of spending
            let (nullifier, root) = TransactionGadgets::<C>::prove_spend(
                &mut circuit,
                ro_in,
                acc_wit_in,
                freeze_sk,
                Spender::Freezer,
            )?;
            // enforce correct root if record is not dummy
            let is_correct_mt_root = circuit.is_equal(root, pub_input.merkle_root)?;
            circuit.logic_or_gate(is_correct_mt_root, b_is_dummy_ro)?;
            // check nullifier is correctly computed
            circuit.enforce_equal(nullifier, expected_nl)?;
        }

        let n_constraints = circuit.num_gates();
        circuit.finalize_for_arithmetization()?;
        Ok((Self(circuit), n_constraints))
    }
}

#[derive(Debug)]
pub(crate) struct FreezeWitnessVar {
    pub(crate) input_ros: Vec<RecordOpeningVar>,
    pub(crate) input_acc_member_witnesses: Vec<AccMemberWitnessVar>,
    pub(crate) output_ros: Vec<RecordOpeningVar>,
    pub(crate) fee_sk: Variable,
    pub(crate) freezing_sks: Vec<Variable>,
}

impl FreezeWitnessVar {
    /// Create a variable for a minting witness
    pub(crate) fn new<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        witness: &FreezeWitness<C>,
    ) -> Result<Self, CircuitError> {
        let input_ros = witness
            .input_ros
            .iter()
            .map(|ro| RecordOpeningVar::new(circuit, ro))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let input_acc_member_witnesses = witness
            .input_acc_member_witnesses
            .iter()
            .map(|acc_wit| AccMemberWitnessVar::new::<_, C::EmbeddedCurveParam>(circuit, acc_wit))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let output_ros = witness
            .output_ros
            .iter()
            .map(|ro| RecordOpeningVar::new(circuit, ro))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let fee_sk = circuit.create_variable(fr_to_fq::<_, C::EmbeddedCurveParam>(
            witness.fee_keypair.address_secret_ref(),
        ))?;
        let freezing_sks = witness
            .freezing_keypairs
            .iter()
            .map(|&keypair| {
                circuit.create_variable(fr_to_fq::<_, C::EmbeddedCurveParam>(&keypair.sec_key))
            })
            .collect::<Result<Vec<_>, CircuitError>>()?;
        Ok(Self {
            input_ros,
            input_acc_member_witnesses,
            output_ros,
            fee_sk,
            freezing_sks,
        })
    }
}

#[derive(Debug)]
pub(crate) struct FreezePubInputVar {
    pub(crate) merkle_root: Variable,
    pub(crate) native_asset_code: Variable,
    pub(crate) fee: Variable,
    pub(crate) input_nullifiers: Vec<Variable>,
    pub(crate) output_commitments: Vec<Variable>,
}

impl FreezePubInputVar {
    /// Create a freezing public input variable.
    pub(crate) fn new<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        pub_input: &FreezePublicInput<C>,
    ) -> Result<Self, CircuitError> {
        let merkle_root = circuit.create_public_variable(pub_input.merkle_root.to_scalar())?;
        let native_asset_code = circuit.create_public_variable(pub_input.native_asset_code.0)?;
        let fee = circuit.create_public_variable(C::ScalarField::from(pub_input.fee.0))?;
        let input_nullifiers = pub_input
            .input_nullifiers
            .iter()
            .map(|nl| circuit.create_public_variable(nl.0))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let output_commitments = pub_input
            .output_commitments
            .iter()
            .map(|comm| circuit.create_public_variable(comm.0))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        Ok(Self {
            merkle_root,
            native_asset_code,
            fee,
            input_nullifiers,
            output_commitments,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{FreezeCircuit, FreezePubInputVar, FreezePublicInput, FreezeWitness};
    use crate::{
        keys::{FreezerKeyPair, UserKeyPair, UserPubKey},
        prelude::{CapConfig, Config},
        structs::{
            Amount, AssetCode, AssetDefinition, AssetPolicy, FreezeFlag, Nullifier,
            RecordCommitment,
        },
        utils::params_builder::FreezeParamsBuilder,
    };
    use ark_std::{vec, vec::Vec};
    use jf_primitives::merkle_tree::NodeValue;
    use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit};

    type F = <Config as CapConfig>::ScalarField;

    #[test]
    fn test_pub_input_to_scalars_order_consistency() {
        let input_nullifiers: Vec<Nullifier<Config>> =
            (0..5).map(|i| Nullifier(F::from(i as u8))).collect();
        let output_commitments: Vec<RecordCommitment<Config>> = (6..10)
            .map(|i| RecordCommitment(F::from(i as u8)))
            .collect();
        let pub_input = FreezePublicInput {
            merkle_root: NodeValue::from_scalar(F::from(20u8)),
            native_asset_code: AssetCode::native(),
            fee: Amount::from(30u128),
            input_nullifiers,
            output_commitments,
        };
        let pub_input_vec = pub_input.to_scalars();
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        FreezePubInputVar::new(&mut circuit, &pub_input).unwrap(); // safe unwrap

        let circuit_pub_input = circuit.public_input().unwrap();
        assert_eq!(pub_input_vec.len(), circuit_pub_input.len());
        pub_input_vec
            .iter()
            .zip(circuit_pub_input.iter())
            .for_each(|(&a, &b)| assert_eq!(a, b));
    }

    fn check_freezing_circuit(
        witness: &FreezeWitness<Config>,
        pub_input: &FreezePublicInput<Config>,
        witness_is_valid: bool,
    ) -> Result<(), CircuitError> {
        let pub_input_vec = pub_input.to_scalars();
        let (circuit, _) = FreezeCircuit::build_unchecked(witness, pub_input)?;
        let verify = circuit.0.check_circuit_satisfiability(&pub_input_vec[..]);
        if witness_is_valid {
            assert!(verify.is_ok());
        } else {
            assert!(verify.is_err());
        }
        Ok(())
    }

    #[test]
    fn test_freeze_circuit_build() -> Result<(), CircuitError> {
        let rng = &mut jf_utils::test_rng();
        let tree_depth = 2;
        let fee_keypair = UserKeyPair::generate(rng);
        let freezing_keypair = FreezerKeyPair::generate(rng);
        let input_amounts = vec![Amount::from(20u64), Amount::from(30u64)];
        let fee_input_amount = Amount::from(10u64);
        let fee = Amount::from(5u64);
        let builder = FreezeParamsBuilder::new(
            tree_depth,
            &input_amounts,
            fee_input_amount,
            fee,
            &fee_keypair,
            vec![&freezing_keypair; 2],
        );
        let (witness, pub_input) = builder.build_witness_and_public_input();
        check_freezing_circuit(&witness, &pub_input, true)?;

        // wrong fee balance
        {
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.fee = Amount::from(3u64);
            check_freezing_circuit(&witness, &bad_pub_input, false)?;
        }

        // wrong merkle root
        {
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.merkle_root = NodeValue::default();
            check_freezing_circuit(&witness, &bad_pub_input, false)?;
        }

        // wrong output commitment
        {
            let mut bad_pub_input = pub_input.clone();
            bad_pub_input.output_commitments[0] = RecordCommitment(F::from(10u8));
            check_freezing_circuit(&witness, &bad_pub_input, false)?;
        }

        // inconsistent amount
        {
            let mut bad_witness = witness.clone();
            bad_witness.output_ros[1].amount += Amount::from(1u64);
            let pub_input = FreezePublicInput::from_witness(&bad_witness).unwrap();
            check_freezing_circuit(&bad_witness, &pub_input, false)?;
        }

        // inconsistent address
        {
            let mut bad_witness = witness.clone();
            bad_witness.output_ros[1].pub_key = UserPubKey::default();
            let pub_input = FreezePublicInput::from_witness(&bad_witness).unwrap();
            check_freezing_circuit(&bad_witness, &pub_input, false)?;
        }

        // inconsistent asset code
        {
            let mut bad_witness = witness.clone();
            bad_witness.output_ros[1].asset_def.code = AssetCode::default();
            let pub_input = FreezePublicInput::from_witness(&bad_witness).unwrap();
            check_freezing_circuit(&bad_witness, &pub_input, false)?;
        }

        // inconsistent policy
        {
            let mut bad_witness = witness.clone();
            bad_witness.output_ros[1].asset_def.policy = AssetPolicy::default();
            let pub_input = FreezePublicInput::from_witness(&bad_witness).unwrap();
            check_freezing_circuit(&bad_witness, &pub_input, false)?;
        }

        // fee record asset def is not native
        {
            // wrong asset type, correct asset policy
            let bad_builder = builder.clone().update_fee_asset_def(AssetDefinition {
                code: AssetCode::random(rng).0,
                policy: AssetPolicy::default(),
            });
            let (witness, pub_input) = bad_builder.build_witness_and_public_input();
            check_freezing_circuit(&witness, &pub_input, false)?;

            // correct asset type, wrong asset policy
            let bad_builder = builder.clone().update_fee_asset_def(AssetDefinition {
                code: AssetCode::native(),
                policy: AssetPolicy::rand_for_test(rng),
            });
            let (witness, pub_input) = bad_builder.build_witness_and_public_input();
            check_freezing_circuit(&witness, &pub_input, false)?;
        }

        // frozen fee or fee change
        {
            let bad_builder = builder.clone().update_fee_freeze_flag(FreezeFlag::Frozen);
            let (witness, pub_input) = bad_builder.build_witness_and_public_input();
            check_freezing_circuit(&witness, &pub_input, false)?;

            let mut bad_witness = witness.clone();
            bad_witness.output_ros[0].freeze_flag = FreezeFlag::Frozen;
            let pub_input = FreezePublicInput::from_witness(&bad_witness).unwrap();
            check_freezing_circuit(&bad_witness, &pub_input, false)?;
        }

        // freezing flag not flipped
        {
            let mut bad_witness = witness.clone();
            bad_witness.output_ros[1].freeze_flag = bad_witness.output_ros[1].freeze_flag.flip();
            let pub_input = FreezePublicInput::from_witness(&bad_witness).unwrap();
            check_freezing_circuit(&bad_witness, &pub_input, false)?;
        }

        // input with dummy freezing policy
        {
            let bad_builder = builder
                .clone()
                .update_input_policy(0, AssetPolicy::default());
            let (witness, pub_input) = bad_builder.build_witness_and_public_input();
            check_freezing_circuit(&witness, &pub_input, false)?;
        }
        Ok(())
    }
}
