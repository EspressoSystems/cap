// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{circuit::structs::UserAddressVar, prelude::CapConfig};
use ark_ec::{twisted_edwards_extended::GroupAffine, AffineCurve};
use jf_primitives::circuit::{prf::PrfGadget, rescue::RescueGadget};
use jf_relation::{
    errors::CircuitError, gadgets::ecc::PointVariable, Circuit, PlonkCircuit, Variable,
};

pub(crate) trait TransactionGadgetsHelper<C: CapConfig> {
    fn derive_internal_asset_code(
        &mut self,
        seed: Variable,
        aux: Variable,
    ) -> Result<Variable, CircuitError>;

    fn derive_user_address(&mut self, secret_key: Variable)
        -> Result<UserAddressVar, CircuitError>;

    fn derive_nullifier_key(
        &mut self,
        secret_key: Variable,
        public_key: &PointVariable,
    ) -> Result<Variable, CircuitError>;

    fn nullify(
        &mut self,
        key: Variable,
        uid: Variable,
        commitment: Variable,
    ) -> Result<Variable, CircuitError>;
}

impl<C: CapConfig> TransactionGadgetsHelper<C> for PlonkCircuit<C::ScalarField> {
    fn derive_internal_asset_code(
        &mut self,
        seed: Variable,
        aux: Variable,
    ) -> Result<Variable, CircuitError> {
        self.eval_prf(seed, &[aux])
    }

    fn derive_user_address(
        &mut self,
        secret_key: Variable,
    ) -> Result<UserAddressVar, CircuitError> {
        let base = GroupAffine::<C::EmbeddedCurveParam>::prime_subgroup_generator();
        let address_var = self.fixed_base_scalar_mul(secret_key, &base)?;
        Ok(UserAddressVar(address_var))
    }

    fn derive_nullifier_key(
        &mut self,
        secret_key: Variable,
        public_key: &PointVariable,
    ) -> Result<Variable, CircuitError> {
        let shared_key =
            self.variable_base_scalar_mul::<C::EmbeddedCurveParam>(secret_key, public_key)?;
        let zero = self.zero();
        let derived_key =
            self.rescue_sponge_no_padding(&[shared_key.get_x(), shared_key.get_y(), zero], 1)?[0];
        let bit = self.is_neutral_point::<C::EmbeddedCurveParam>(public_key)?;
        self.conditional_select(bit, derived_key, secret_key)
    }

    fn nullify(
        &mut self,
        key: Variable,
        uid: Variable,
        commitment: Variable,
    ) -> Result<Variable, CircuitError> {
        self.eval_prf(key, &[uid, commitment])
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuit::gadgets_helper::TransactionGadgetsHelper,
        keys::{FreezerKeyPair, NullifierKey},
        prelude::{CapConfig, Config},
        structs::{AssetCodeDigest, AssetCodeSeed, InternalAssetCode, RecordCommitment},
    };
    use ark_ec::ProjectiveCurve;
    use ark_ff::One;
    use ark_std::UniformRand;
    use jf_relation::{errors::CircuitError, gadgets::ecc::Point, Circuit, PlonkCircuit};
    use jf_utils::fr_to_fq;

    type F = <Config as CapConfig>::ScalarField;
    type Fj = <Config as CapConfig>::EmbeddedCurveScalarField;
    type EmbeddedCurveParam = <Config as CapConfig>::EmbeddedCurveParam;

    #[test]
    fn test_internal_asset_code() -> Result<(), CircuitError> {
        let mut prng = ark_std::test_rng();
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let asset_code_seed = AssetCodeSeed::<Config>::generate(&mut prng);
        let aux = AssetCodeDigest::from_description(b"some description");
        let internal_asset_code = InternalAssetCode::new_internal(asset_code_seed, aux);

        let seed_var = circuit.create_variable(asset_code_seed.0)?;
        let aux_var = circuit.create_variable(aux.0)?;
        let asset_code_var = TransactionGadgetsHelper::<Config>::derive_internal_asset_code(
            &mut circuit,
            seed_var,
            aux_var,
        )?;

        // Check asset_code consistency
        assert_eq!(internal_asset_code.0, circuit.witness(asset_code_var)?);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(asset_code_var) = internal_asset_code.0 + F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    #[test]
    fn test_user_address() -> Result<(), CircuitError> {
        let mut prng = ark_std::test_rng();
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let key_pair = crate::keys::UserKeyPair::<Config>::generate(&mut prng);

        let spend_key = fr_to_fq::<_, EmbeddedCurveParam>(key_pair.address_secret_ref());
        let spend_key_var = circuit.create_variable(spend_key)?;
        let address_var =
            TransactionGadgetsHelper::<Config>::derive_user_address(&mut circuit, spend_key_var)?;

        // Check address consistency
        let (address_x, address_y): (F, F) = (&key_pair.address()).into();
        assert_eq!(address_x, circuit.witness(address_var.0.get_x())?);
        assert_eq!(address_y, circuit.witness(address_var.0.get_y())?);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(address_var.0.get_x()) = address_x + F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    #[test]
    fn test_nullifier_key() -> Result<(), CircuitError> {
        let mut prng = ark_std::test_rng();
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let user_key_pair = crate::keys::UserKeyPair::<Config>::generate(&mut prng);
        let user_public_key = user_key_pair.pub_key();
        let spend_key = fr_to_fq::<_, EmbeddedCurveParam>(user_key_pair.address_secret_ref());
        let freezer_keypair = FreezerKeyPair::generate(&mut prng);
        let freezer_public_key = freezer_keypair.pub_key().0.into_affine();

        // Check derivation from freezer secret key
        let spend_key_var = circuit.create_variable(spend_key)?;
        let freezer_pk_var = circuit.create_point_variable(Point::from(freezer_public_key))?;
        let nullifier_key_var = TransactionGadgetsHelper::<Config>::derive_nullifier_key(
            &mut circuit,
            spend_key_var,
            &freezer_pk_var,
        )?;
        let nullifier_key = freezer_keypair.derive_nullifier_key(&user_public_key.address());

        // Check address consistency
        assert_eq!(nullifier_key.0, circuit.witness(nullifier_key_var)?);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(nullifier_key_var) = nullifier_key.0 + F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check derivation from user secret key
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let freezer_key_var =
            circuit.create_variable(fr_to_fq::<_, EmbeddedCurveParam>(&freezer_keypair.sec_key))?;
        let user_pk_var = circuit.create_point_variable(Point::from(
            user_public_key.address_internal().into_affine(),
        ))?;
        let nullifier_key_var = TransactionGadgetsHelper::<Config>::derive_nullifier_key(
            &mut circuit,
            freezer_key_var,
            &user_pk_var,
        )?;
        let nullifier_key_2 = user_key_pair.derive_nullifier_key(&freezer_keypair.pub_key());
        assert_eq!(nullifier_key, nullifier_key_2);

        // Check nullifier key consistency
        assert_eq!(nullifier_key_2.0, circuit.witness(nullifier_key_var)?);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(nullifier_key_var) = nullifier_key_2.0 + F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    #[test]
    fn test_nullifier() -> Result<(), CircuitError> {
        let mut prng = ark_std::test_rng();
        let nullifier_key = NullifierKey::<Config>::from(&Fj::rand(&mut prng));
        let uid = 10u64;
        let uid_scalar = F::from(10u8);
        let commitment = F::from(1234u64);

        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let key_var = circuit.create_variable(nullifier_key.0)?;
        let uid_var = circuit.create_variable(uid_scalar)?;
        let commitment_var = circuit.create_variable(commitment)?;
        let nullifier_var = TransactionGadgetsHelper::<Config>::nullify(
            &mut circuit,
            key_var,
            uid_var,
            commitment_var,
        )?;

        let nullifier = nullifier_key.nullify(uid, &RecordCommitment(commitment));
        // Check nullifier consistency
        assert_eq!(nullifier.0, circuit.witness(nullifier_var)?);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(nullifier_var) = nullifier.0 + F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }
}
