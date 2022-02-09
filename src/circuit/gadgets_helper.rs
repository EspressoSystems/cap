use crate::{circuit::structs::UserAddressVar, BaseField, CurveParam};
use ark_ec::{twisted_edwards_extended::GroupAffine, AffineCurve};
use jf_plonk::{
    circuit::{
        customized::{ecc::PointVariable, rescue::RescueGadget},
        Circuit, PlonkCircuit, Variable,
    },
    errors::PlonkError,
};
use jf_primitives::circuit::prf::PrfGadget;

pub(crate) trait TransactionGadgetsHelper {
    fn derive_internal_asset_code(
        &mut self,
        seed: Variable,
        aux: Variable,
    ) -> Result<Variable, PlonkError>;
    fn derive_user_address(&mut self, secret_key: Variable) -> Result<UserAddressVar, PlonkError>;
    fn derive_nullifier_key(
        &mut self,
        secret_key: Variable,
        public_key: &PointVariable,
    ) -> Result<Variable, PlonkError>;
    fn nullify(
        &mut self,
        key: Variable,
        uid: Variable,
        commitment: Variable,
    ) -> Result<Variable, PlonkError>;
}

impl TransactionGadgetsHelper for PlonkCircuit<BaseField> {
    fn derive_internal_asset_code(
        &mut self,
        seed: Variable,
        aux: Variable,
    ) -> Result<Variable, PlonkError> {
        self.eval_prf(seed, &[aux])
    }

    fn derive_user_address(&mut self, secret_key: Variable) -> Result<UserAddressVar, PlonkError> {
        let base = GroupAffine::<CurveParam>::prime_subgroup_generator();
        let address_var = self.fixed_base_scalar_mul(secret_key, &base)?;
        Ok(UserAddressVar(address_var))
    }

    fn derive_nullifier_key(
        &mut self,
        secret_key: Variable,
        public_key: &PointVariable,
    ) -> Result<Variable, PlonkError> {
        let shared_key = self.variable_base_scalar_mul::<CurveParam>(secret_key, public_key)?;
        let zero = self.zero();
        let derived_key =
            self.rescue_sponge_no_padding(&[shared_key.get_x(), shared_key.get_y(), zero], 1)?[0];
        let bit = self.is_neutral_point::<CurveParam>(public_key)?;
        self.conditional_select(bit, derived_key, secret_key)
    }

    fn nullify(
        &mut self,
        key: Variable,
        uid: Variable,
        commitment: Variable,
    ) -> Result<Variable, PlonkError> {
        self.eval_prf(key, &[uid, commitment])
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuit::gadgets_helper::TransactionGadgetsHelper,
        keys::{FreezerKeyPair, NullifierKey},
        structs::{AssetCodeDigest, AssetCodeSeed, InternalAssetCode, RecordCommitment},
        BaseField, CurveParam, ScalarField,
    };
    use ark_ec::ProjectiveCurve;
    use ark_ff::One;
    use ark_std::UniformRand;
    use jf_plonk::{
        circuit::{customized::ecc::Point, Circuit, PlonkCircuit},
        errors::PlonkError,
    };
    use jf_utils::fr_to_fq;

    #[test]
    fn test_internal_asset_code() -> Result<(), PlonkError> {
        let mut prng = ark_std::test_rng();
        let mut circuit = PlonkCircuit::new_turbo_plonk();

        let asset_code_seed = AssetCodeSeed::generate(&mut prng);
        let aux = AssetCodeDigest::from_description(b"some description");
        let internal_asset_code = InternalAssetCode::new_internal(asset_code_seed, aux);

        let seed_var = circuit.create_variable(asset_code_seed.0)?;
        let aux_var = circuit.create_variable(aux.0)?;
        let asset_code_var = circuit.derive_internal_asset_code(seed_var, aux_var)?;

        // Check asset_code consistency
        assert_eq!(internal_asset_code.0, circuit.witness(asset_code_var)?);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(asset_code_var) = internal_asset_code.0 + BaseField::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    #[test]
    fn test_user_address() -> Result<(), PlonkError> {
        let mut prng = ark_std::test_rng();
        let mut circuit = PlonkCircuit::<BaseField>::new_turbo_plonk();
        let key_pair = crate::keys::UserKeyPair::generate(&mut prng);

        let spend_key = fr_to_fq::<_, CurveParam>(key_pair.address_secret_ref());
        let spend_key_var = circuit.create_variable(spend_key)?;
        let address_var = circuit.derive_user_address(spend_key_var)?;

        // Check address consistency
        let (address_x, address_y): (BaseField, BaseField) = (&key_pair.address()).into();
        assert_eq!(address_x, circuit.witness(address_var.0.get_x())?);
        assert_eq!(address_y, circuit.witness(address_var.0.get_y())?);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(address_var.0.get_x()) = address_x + BaseField::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    #[test]
    fn test_nullifier_key() -> Result<(), PlonkError> {
        let mut prng = ark_std::test_rng();
        let mut circuit = PlonkCircuit::<BaseField>::new_turbo_plonk();
        let user_key_pair = crate::keys::UserKeyPair::generate(&mut prng);
        let user_public_key = user_key_pair.pub_key();
        let spend_key = fr_to_fq::<_, CurveParam>(user_key_pair.address_secret_ref());
        let freezer_keypair = FreezerKeyPair::generate(&mut prng);
        let freezer_public_key = freezer_keypair.pub_key().0.into_affine();

        // Check derivation from freezer secret key
        let spend_key_var = circuit.create_variable(spend_key)?;
        let freezer_pk_var = circuit.create_point_variable(Point::from(freezer_public_key))?;
        let nullifier_key_var = circuit.derive_nullifier_key(spend_key_var, &freezer_pk_var)?;
        let nullifier_key = freezer_keypair.derive_nullifier_key(&user_public_key.address());

        // Check address consistency
        assert_eq!(nullifier_key.0, circuit.witness(nullifier_key_var)?);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(nullifier_key_var) = nullifier_key.0 + BaseField::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check derivation from user secret key
        let mut circuit = PlonkCircuit::<BaseField>::new_turbo_plonk();
        let freezer_key_var =
            circuit.create_variable(fr_to_fq::<_, CurveParam>(&freezer_keypair.sec_key))?;
        let user_pk_var = circuit.create_point_variable(Point::from(
            user_public_key.address_internal().into_affine(),
        ))?;
        let nullifier_key_var = circuit.derive_nullifier_key(freezer_key_var, &user_pk_var)?;
        let nullifier_key_2 = user_key_pair.derive_nullifier_key(&freezer_keypair.pub_key());
        assert_eq!(nullifier_key, nullifier_key_2);

        // Check nullifier key consistency
        assert_eq!(nullifier_key_2.0, circuit.witness(nullifier_key_var)?);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(nullifier_key_var) = nullifier_key_2.0 + BaseField::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }

    #[test]
    fn test_nullifier() -> Result<(), PlonkError> {
        let mut prng = ark_std::test_rng();
        let nullifier_key = NullifierKey::from(&ScalarField::rand(&mut prng));
        let uid = 10u64;
        let uid_scalar = BaseField::from(10u8);
        let commitment = BaseField::from(1234u64);

        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let key_var = circuit.create_variable(nullifier_key.0)?;
        let uid_var = circuit.create_variable(uid_scalar)?;
        let commitment_var = circuit.create_variable(commitment)?;
        let nullifier_var = circuit.nullify(key_var, uid_var, commitment_var)?;

        let nullifier = nullifier_key.nullify(uid, &RecordCommitment(commitment));
        // Check nullifier consistency
        assert_eq!(nullifier.0, circuit.witness(nullifier_var)?);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(nullifier_var) = nullifier.0 + BaseField::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        Ok(())
    }
}
