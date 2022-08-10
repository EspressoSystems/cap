// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    circuit::{gadgets_helper::TransactionGadgetsHelper, structs::RecordOpeningVar},
    prelude::CapConfig,
};
use ark_ff::One;
use ark_std::{string::ToString, vec::Vec};
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::{CircuitError::InternalError, PlonkError},
};
use jf_primitives::circuit::merkle_tree::{AccElemVars, AccMemberWitnessVar, MerkleTreeGadget};

#[derive(Clone, PartialEq, Eq, Debug)]
/// Enum for an asset record spender.
pub(crate) enum Spender {
    User,
    Freezer,
}

// High-level transaction related gadgets
pub(crate) trait TransactionGadgets {
    /// Add constraints that enforces the balance between inputs and outputs.
    /// Return the input transfer amount (which excludes the fee input amount).
    /// In case `asset != native_asset`, enforces
    ///   * `amounts_in[0] == amounts_out[0] + fee`
    ///   * `sum_{i=2..n} amounts_in[i] == sum_{i=2..m} amounts_out[i]`
    ///
    /// In case `asset == native asset`, enforces
    ///   * `sum_{i=1..n} amounts_in[i] == fee + sum_{i=1..m} amounts_out[i]`
    ///
    /// The input parameters are:
    /// * `naive_asset` - native asset code variable
    /// * `asset` - asset code variable
    /// * `fee` - transaction fee variable
    /// * `amounts_in` - input amounts, **should be non-empty**
    /// * `amounts_out` - output amounts, **should be non-empty**
    /// * We assume that `amounts_in/out[0]` are with native asset type.
    fn preserve_balance(
        &mut self,
        native_asset: Variable,
        asset: Variable,
        fee: Variable,
        amounts_in: &[Variable],
        amounts_out: &[Variable],
    ) -> Result<Variable, PlonkError>;

    /// Prove the possession of an asset record and spend it,
    /// add the corresponding constraints.
    /// * `ro` - the variables for the asset record opening
    /// * `acc_member_witness` - (uid, merkle path) Merkle proof of record
    /// * `sk` - a secret key variable used to spend the asset
    /// * `spender` - the identity of the spender, can be user or freezer.
    /// * output - (`nullifier`, `root`): nullifier, and the Merkle root value.
    fn prove_spend(
        &mut self,
        ro: &RecordOpeningVar,
        acc_member_witness: &AccMemberWitnessVar,
        sk: Variable,
        spender: Spender,
    ) -> Result<(Variable, Variable), PlonkError>;

    /// Apply hadamard product on `vals` and binary vector `bit_map_vars`.
    fn hadamard_product(
        &mut self,
        bit_map_vars: &[Variable],
        vals: &[Variable],
    ) -> Result<Vec<Variable>, PlonkError>;
}

impl<C: CapConfig> TransactionGadgets for PlonkCircuit<C::ScalarField> {
    fn preserve_balance(
        &mut self,
        native_asset: Variable,
        asset: Variable,
        fee: Variable,
        amounts_in: &[Variable],
        amounts_out: &[Variable],
    ) -> Result<Variable, PlonkError> {
        if amounts_in.is_empty() {
            return Err(PlonkError::CircuitError(InternalError(
                "amounts_in is empty".to_string(),
            )));
        }
        if amounts_out.is_empty() {
            return Err(PlonkError::CircuitError(InternalError(
                "amounts_out is empty".to_string(),
            )));
        }
        let zero_var = self.zero();
        let total_amounts_in = if amounts_in.len() == 1 {
            zero_var
        } else {
            self.sum(&amounts_in[1..])?
        };
        let total_amounts_out = if amounts_out.len() == 1 {
            zero_var
        } else {
            self.sum(&amounts_out[1..])?
        };
        let amount_diff = self.sub(total_amounts_in, total_amounts_out)?;
        let one = C::ScalarField::one();
        let native_amount_diff = self.lc(
            &[amounts_in[0], amounts_out[0], fee, zero_var],
            &[one, -one, -one, one],
        )?;
        let same_asset = self.check_equal(native_asset, asset)?;
        // enforce `same_asset` * (`amount_diff + native_amount_diff`) == 0 (i.e.,
        // `amount_diff` + `native_amount_diff` == 0 when `same_asset == 1`)
        self.mul_add_gate(
            &[
                same_asset,
                amount_diff,
                same_asset,
                native_amount_diff,
                zero_var,
            ],
            &[one, one],
        )?;
        // enforce `same_asset` * `amount_diff` = `amount_diff` (i.e., `amount_diff` ==
        // 0 when `same_asset == 0`)
        self.mul_gate(same_asset, amount_diff, amount_diff)?;
        // enforce `same_asset` * `native_amount_diff` = `native_amount_diff`,
        self.mul_gate(same_asset, native_amount_diff, native_amount_diff)?;

        Ok(total_amounts_in)
    }

    fn prove_spend(
        &mut self,
        ro: &RecordOpeningVar,
        acc_member_witness: &AccMemberWitnessVar,
        sk: Variable,
        spender: Spender,
    ) -> Result<(Variable, Variable), PlonkError> {
        let (uid, path_ref) = (acc_member_witness.uid, &acc_member_witness.merkle_path);
        let (pk1_point, pk2_point) = if spender == Spender::User {
            (&ro.owner_addr.0, &ro.policy.freezer_pk)
        } else {
            (&ro.policy.freezer_pk, &ro.owner_addr.0)
        };

        // PoK of secret key
        let pk = self.derive_user_address(sk)?;
        self.point_equal_gate(&pk.0, pk1_point)?;

        // compute commitment
        let commitment = ro.compute_record_commitment(self)?;

        // derive nullify key and compute nullifier
        let nk = self.derive_nullifier_key(sk, pk2_point)?;
        let nullifier = self.nullify(nk, uid, commitment)?;

        // verify Merkle path
        let root = self.compute_merkle_root(
            AccElemVars {
                uid,
                elem: commitment,
            },
            path_ref,
        )?;

        Ok((nullifier, root))
    }

    fn hadamard_product(
        &mut self,
        bit_map_vars: &[Variable],
        vals: &[Variable],
    ) -> Result<Vec<Variable>, PlonkError> {
        if bit_map_vars.len() != vals.len() {
            return Err(PlonkError::CircuitError(InternalError(
                "expecting the same length for vals and reveal_map".to_string(),
            )));
        }
        bit_map_vars
            .iter()
            .zip(vals.iter())
            .map(|(&bit, &val)| self.mul(bit, val))
            .collect::<Result<Vec<_>, PlonkError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::{Spender, TransactionGadgets};
    use crate::{
        circuit::structs::RecordOpeningVar,
        constants::VIEWABLE_DATA_LEN,
        keys::{FreezerKeyPair, FreezerPubKey, UserKeyPair},
        prelude::{CapConfig, Config},
        structs::{AssetPolicy, RecordCommitment, RecordOpening, RevealMap},
    };
    use ark_ff::{One, Zero};
    use ark_std::{test_rng, vec::Vec};
    use jf_plonk::{
        circuit::{Circuit, PlonkCircuit, Variable},
        errors::PlonkError,
    };
    use jf_primitives::{
        circuit::merkle_tree::{gen_merkle_path_for_test, AccMemberWitnessVar},
        merkle_tree::AccMemberWitness,
    };
    use jf_utils::fr_to_fq;

    type F = <Config as CapConfig>::ScalarField;
    type JubjubParam = <Config as CapConfig>::JubjubParam;

    fn build_preserve_balance_circuit(
        native_asset: F,
        asset: F,
        fee: F,
        amounts_in: &[F],
        amounts_out: &[F],
    ) -> Result<PlonkCircuit<F>, PlonkError> {
        let expected_transfer_amount = amounts_in.iter().skip(1).fold(F::zero(), |acc, &x| acc + x);
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let native_asset = circuit.create_variable(native_asset)?;
        let asset = circuit.create_variable(asset)?;
        let amounts_in: Vec<Variable> = amounts_in
            .iter()
            .map(|&val| circuit.create_variable(val))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let amounts_out: Vec<Variable> = amounts_out
            .iter()
            .map(|&val| circuit.create_variable(val))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let fee = circuit.create_variable(fee)?;
        let transfer_amount =
            circuit.preserve_balance(native_asset, asset, fee, &amounts_in, &amounts_out)?;
        assert_eq!(expected_transfer_amount, circuit.witness(transfer_amount)?);
        Ok(circuit)
    }

    #[test]
    fn test_preserve_balance() -> Result<(), PlonkError> {
        let native_asset = F::from(59u32);
        let asset1 = F::from(59u32);
        let asset2 = F::from(179u32);
        // amounts_in = (10, 9, 8, ..., 2)
        let amounts_in: Vec<F> = (2..11).rev().map(|x| F::from(x as u32)).collect();
        // amounts1_out = (2, 3, ..., 9)
        let amounts1_out: Vec<F> = (2..10).map(|x| F::from(x as u32)).collect();
        // amounts2_out = (1, 2, 3, ..., 9)
        let amounts2_out: Vec<F> = (1..10).map(|x| F::from(x as u32)).collect();
        // The happy path
        // amounts_in.len()==1
        let fee = F::from(5u32);
        let circuit = build_preserve_balance_circuit(
            native_asset,
            asset1,
            fee,
            &amounts_in[..1],
            &amounts1_out[..2],
        )?; // 10 = 5 + 2 + 3
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // amounts_out.len()==1
        let fee = F::from(17u32);
        let circuit = build_preserve_balance_circuit(
            native_asset,
            asset1,
            fee,
            &amounts_in[..2],
            &amounts1_out[..1],
        )?; // 10 + 9 = 17 + 2
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // amounts_in.len()==1 && amounts_out.len()==1
        let fee = F::from(8u32);
        let circuit = build_preserve_balance_circuit(
            native_asset,
            asset1,
            fee,
            &amounts_in[..1],
            &amounts1_out[..1],
        )?; // 10 = 8 + 2
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // asset1 == native asset
        let fee = F::from(10u32);
        let circuit =
            build_preserve_balance_circuit(native_asset, asset1, fee, &amounts_in, &amounts1_out)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // asset2 != native asset
        let fee = F::from(9u32);
        let circuit =
            build_preserve_balance_circuit(native_asset, asset2, fee, &amounts_in, &amounts2_out)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // The error path
        // `asset1 == native asset`
        let fee = F::from(9u32);
        let circuit =
            build_preserve_balance_circuit(native_asset, asset1, fee, &amounts_in, &amounts1_out)?; // 10+9+8+...+2 != 2+3+4+...+9+9
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // `asset1 != native asset`
        let asset1 = F::from(69u32);
        let fee = F::from(10u32);
        let circuit =
            build_preserve_balance_circuit(native_asset, asset1, fee, &amounts_in, &amounts1_out)?; // 9+8+...+2 != 3+4+...+9
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    fn check_prove_spend_circuit(
        ro: &RecordOpening<Config>,
        acc_member_witness: &AccMemberWitness<F>,
        sk: F,
        spender: Spender,
        expected_nullifier: F,
        expected_root: F,
    ) -> Result<(), PlonkError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let ro_var = RecordOpeningVar::new(&mut circuit, ro)?;
        let acc_wit_var =
            AccMemberWitnessVar::new::<_, JubjubParam>(&mut circuit, &acc_member_witness)?;

        let sk_var = circuit.create_variable(sk)?;
        let (nullifier, root) = circuit.prove_spend(&ro_var, &acc_wit_var, sk_var, spender)?;

        assert_eq!(circuit.witness(nullifier)?, expected_nullifier);
        assert_eq!(circuit.witness(root)?, expected_root);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(root) = F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_prove_spend() -> Result<(), PlonkError> {
        let rng = &mut test_rng();

        // Case 1: Asset record with freezing policy
        // Create user/freezer keypairs
        let user_keypair = UserKeyPair::generate(rng);
        let freezer_keypair = FreezerKeyPair::generate(rng);
        // Create user's asset record
        let mut ro = RecordOpening::rand_for_test(rng);
        ro.asset_def.policy.freezer_pk = freezer_keypair.pub_key();
        ro.pub_key = user_keypair.pub_key();
        // Compute expected nullifier and root
        let ro_comm = ro.derive_record_commitment();
        let uid = 2u64;
        let expected_nl = freezer_keypair.nullify(&user_keypair.address(), uid, &ro_comm);
        let (acc_wit, expected_root) = gen_merkle_path_for_test(uid, ro_comm.0);
        // Check user spending
        let usk = fr_to_fq::<_, JubjubParam>(user_keypair.address_secret_ref());
        check_prove_spend_circuit(
            &ro,
            &acc_wit,
            usk,
            Spender::User,
            expected_nl.0,
            expected_root,
        )?;
        // Check freezer spending
        let fsk = fr_to_fq::<_, JubjubParam>(&freezer_keypair.sec_key);
        check_prove_spend_circuit(
            &ro,
            &acc_wit,
            fsk,
            Spender::Freezer,
            expected_nl.0,
            expected_root,
        )?;

        // Case 2: Asset record with no freezing policy.
        let mut ro = RecordOpening::rand_for_test(rng);
        ro.asset_def.policy = AssetPolicy::default();
        ro.pub_key = user_keypair.pub_key();
        let ro_comm = RecordCommitment::from(&ro);
        let uid = 3u64;
        let expected_nl = user_keypair.nullify(&FreezerPubKey::default(), uid, &ro_comm);
        let (acc_wit, expected_root) = gen_merkle_path_for_test(uid, ro_comm.0);
        check_prove_spend_circuit(
            &ro,
            &acc_wit,
            usk,
            Spender::User,
            expected_nl.0,
            expected_root,
        )?;

        Ok(())
    }

    fn check_hadamard_product(
        reveal_map: &RevealMap,
        vals: &[F],
        bit_len: usize,
    ) -> Result<(), PlonkError> {
        let expected_hadamard = reveal_map.hadamard_product(vals);
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let reveal_map_var = circuit.create_variable(F::from(*reveal_map))?;
        let bit_map_vars: Vec<Variable> = circuit
            .unpack(reveal_map_var, VIEWABLE_DATA_LEN)?
            .into_iter()
            .rev()
            .collect();
        let vals = vals
            .iter()
            .map(|&val| circuit.create_variable(val))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let prod = circuit.hadamard_product(&bit_map_vars[..bit_len], &vals[..bit_len])?;

        for i in 0..bit_len {
            assert_eq!(circuit.witness(prod[i])?, expected_hadamard[i]);
        }
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(prod[0]) = F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_hadamard_product() -> Result<(), PlonkError> {
        let mut reveal_map = RevealMap::default();
        reveal_map.reveal_all();
        let vals: Vec<F> = (0..VIEWABLE_DATA_LEN).map(|i| F::from(i as u32)).collect();
        check_hadamard_product(&reveal_map, &vals, VIEWABLE_DATA_LEN)?;

        let reveal_map = RevealMap::default();
        check_hadamard_product(&reveal_map, &vals, VIEWABLE_DATA_LEN)?;

        let rng = &mut ark_std::test_rng();
        let reveal_map = RevealMap::rand_for_test(rng);
        check_hadamard_product(&reveal_map, &vals, VIEWABLE_DATA_LEN)?;

        check_hadamard_product(&reveal_map, &vals, 4)?;
        Ok(())
    }
}
