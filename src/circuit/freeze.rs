//! Circuit for the freezing/releasing of auditable anonymously-transferable
//! asset.
use crate::{
    circuit::{
        gadgets::{Spender, TransactionGadgets},
        structs::RecordOpeningVar,
    },
    errors::TxnApiError,
    keys::{FreezerKeyPair, UserKeyPair},
    proof::freeze::{FreezePublicInput, FreezeWitness},
    BaseField, CurveParam,
};
use ark_ff::Zero;
use ark_std::{format, rand::SeedableRng, string::ToString, vec::Vec};
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};
use jf_primitives::circuit::merkle_tree::AccMemberWitnessVar;
use jf_utils::fr_to_fq;

pub(crate) struct FreezeCircuit(pub(crate) PlonkCircuit<BaseField>);

impl FreezeCircuit {
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
        witness: &FreezeWitness,
        pub_input: &FreezePublicInput,
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
        witness: &FreezeWitness,
        pub_input: &FreezePublicInput,
    ) -> Result<(Self, usize), PlonkError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let witness = FreezeWitnessVar::new(&mut circuit, witness)?;
        let pub_input = FreezePubInputVar::new(&mut circuit, pub_input)?;

        // Check the first input/output for charging fee
        let first_input = &witness.input_ros[0];
        let first_output = &witness.output_ros[0];
        // The first input/output are with native asset definition
        circuit.equal_gate(first_input.asset_code, pub_input.native_asset_code)?;
        first_input.policy.enforce_dummy_policy(&mut circuit)?;
        circuit.equal_gate(first_output.asset_code, pub_input.native_asset_code)?;
        first_output.policy.enforce_dummy_policy(&mut circuit)?;
        // The first input/output are not frozen
        let unfrozen = BaseField::zero();
        circuit.constant_gate(first_input.freeze_flag, unfrozen)?;
        circuit.constant_gate(first_output.freeze_flag, unfrozen)?;
        // Fee balance
        circuit.add_gate(first_output.amount, pub_input.fee, first_input.amount)?;
        // Proof of spending
        let (nullifier, root) = circuit.prove_spend(
            first_input,
            &witness.input_acc_member_witnesses[0],
            witness.fee_sk,
            Spender::User,
        )?;
        circuit.equal_gate(root, pub_input.merkle_root)?;
        circuit.equal_gate(nullifier, pub_input.input_nullifiers[0])?;

        // Check freezing inputs/outputs consistency
        for (ro_in, ro_out) in witness
            .input_ros
            .iter()
            .skip(1)
            .zip(witness.output_ros.iter().skip(1))
        {
            // Freezing flag flipped
            circuit.add_gate(ro_in.freeze_flag, ro_out.freeze_flag, circuit.one())?;
            // Output ro preserves the amount, address, asset definition of input ro
            circuit.equal_gate(ro_in.amount, ro_out.amount)?;
            circuit.point_equal_gate(&ro_in.owner_addr.0, &ro_out.owner_addr.0)?;
            circuit.equal_gate(ro_in.asset_code, ro_out.asset_code)?;
            ro_in
                .policy
                .enforce_equal_policy(&mut circuit, &ro_out.policy)?;
        }

        // Check output commitments correctness
        for (ro_out, &expected_comm) in witness
            .output_ros
            .iter()
            .zip(pub_input.output_commitments.iter())
        {
            let rc_out = ro_out.compute_record_commitment(&mut circuit)?;
            circuit.equal_gate(rc_out, expected_comm)?;
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
            let b_dummy_freeze_pk = ro_in.policy.is_dummy_freezer_pk(&mut circuit)?;
            let b_not_dummy_freeze_pk = circuit.logic_neg(b_dummy_freeze_pk)?;
            let b_is_dummy_ro = ro_in.is_asset_code_dummy(&mut circuit)?;
            circuit.logic_or_gate(b_not_dummy_freeze_pk, b_is_dummy_ro)?;

            // Proof of spending
            let (nullifier, root) =
                circuit.prove_spend(ro_in, acc_wit_in, freeze_sk, Spender::Freezer)?;
            // enforce correct root if record is not dummy
            let is_correct_mt_root = circuit.is_equal(root, pub_input.merkle_root)?;
            circuit.logic_or_gate(is_correct_mt_root, b_is_dummy_ro)?;
            // check nullifier is correctly computed
            circuit.equal_gate(nullifier, expected_nl)?;
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
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<BaseField>,
        witness: &FreezeWitness,
    ) -> Result<Self, PlonkError> {
        let input_ros = witness
            .input_ros
            .iter()
            .map(|ro| RecordOpeningVar::new(circuit, ro))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let input_acc_member_witnesses = witness
            .input_acc_member_witnesses
            .iter()
            .map(|acc_wit| AccMemberWitnessVar::new::<_, CurveParam>(circuit, acc_wit))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let output_ros = witness
            .output_ros
            .iter()
            .map(|ro| RecordOpeningVar::new(circuit, ro))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let fee_sk = circuit.create_variable(fr_to_fq::<_, CurveParam>(
            witness.fee_keypair.address_secret_ref(),
        ))?;
        let freezing_sks = witness
            .freezing_keypairs
            .iter()
            .map(|&keypair| circuit.create_variable(fr_to_fq::<_, CurveParam>(&keypair.sec_key)))
            .collect::<Result<Vec<_>, PlonkError>>()?;
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
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<BaseField>,
        pub_input: &FreezePublicInput,
    ) -> Result<Self, PlonkError> {
        let merkle_root = circuit.create_public_variable(pub_input.merkle_root.to_scalar())?;
        let native_asset_code = circuit.create_public_variable(pub_input.native_asset_code.0)?;
        let fee = circuit.create_public_variable(BaseField::from(pub_input.fee))?;
        let input_nullifiers = pub_input
            .input_nullifiers
            .iter()
            .map(|nl| circuit.create_public_variable(nl.0))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let output_commitments = pub_input
            .output_commitments
            .iter()
            .map(|comm| circuit.create_public_variable(comm.0))
            .collect::<Result<Vec<_>, PlonkError>>()?;
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
        structs::{
            AssetCode, AssetDefinition, AssetPolicy, FreezeFlag, Nullifier, RecordCommitment,
        },
        utils::params_builder::FreezeParamsBuilder,
        BaseField, NodeValue,
    };
    use ark_std::{vec, vec::Vec};
    use jf_plonk::{
        circuit::{Circuit, PlonkCircuit},
        errors::PlonkError,
    };

    #[test]
    fn test_pub_input_to_scalars_order_consistency() {
        let input_nullifiers: Vec<Nullifier> = (0..5)
            .map(|i| Nullifier(BaseField::from(i as u8)))
            .collect();
        let output_commitments: Vec<RecordCommitment> = (6..10)
            .map(|i| RecordCommitment(BaseField::from(i as u8)))
            .collect();
        let pub_input = FreezePublicInput {
            merkle_root: NodeValue::from_scalar(BaseField::from(20u8)),
            native_asset_code: AssetCode::native(),
            fee: 30u64,
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
        witness: &FreezeWitness,
        pub_input: &FreezePublicInput,
        witness_is_valid: bool,
    ) -> Result<(), PlonkError> {
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
    fn test_freeze_circuit_build() -> Result<(), PlonkError> {
        let rng = &mut ark_std::test_rng();
        let tree_depth = 2;
        let fee_keypair = UserKeyPair::generate(rng);
        let freezing_keypair = FreezerKeyPair::generate(rng);
        let input_amounts = vec![20, 30];
        let fee_input_amount = 10;
        let fee = 5;
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
            bad_pub_input.fee = 3;
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
            bad_pub_input.output_commitments[0] = RecordCommitment(BaseField::from(10u8));
            check_freezing_circuit(&witness, &bad_pub_input, false)?;
        }

        // inconsistent amount
        {
            let mut bad_witness = witness.clone();
            bad_witness.output_ros[1].amount += 1;
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