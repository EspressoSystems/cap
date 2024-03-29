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
    constants::{ATTRS_LEN, MAX_TIMESTAMP_LEN},
    prelude::CapConfig,
    structs::{AssetPolicy, ExpirableCredential, IdentityAttribute, RecordOpening, ViewableMemo},
};
use ark_ec::ProjectiveCurve;
use ark_ff::{One, PrimeField, Zero};
use ark_std::{format, ops::Neg, string::ToString, vec, vec::Vec};
use jf_primitives::circuit::{
    commitment::CommitmentGadget,
    elgamal::{ElGamalEncryptionGadget, ElGamalHybridCtxtVars, EncKeyVars},
    signature::schnorr::{SignatureGadget, SignatureVar, VerKeyVar},
};
use jf_relation::{
    errors::CircuitError,
    gadgets::ecc::{Point, PointVariable},
    BoolVar, Circuit, PlonkCircuit, Variable,
};

#[derive(Debug)]
pub(crate) struct ViewableMemoVar(pub(crate) ElGamalHybridCtxtVars);

impl ViewableMemoVar {
    /// Create a variable for viewing memo
    pub(crate) fn new<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        viewing_memo: &ViewableMemo<C>,
    ) -> Result<Self, CircuitError> {
        let ctxts = circuit.create_ciphertext_variable(&viewing_memo.0)?;
        Ok(Self(ctxts))
    }

    /// Set ViewableMemoVar public
    pub(crate) fn set_public<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
    ) -> Result<(), CircuitError> {
        circuit.set_variable_public(self.0.ephemeral.get_x())?;
        circuit.set_variable_public(self.0.ephemeral.get_y())?;
        for &ctxt_var in self.0.symm_ctxts.iter() {
            circuit.set_variable_public(ctxt_var)?;
        }
        Ok(())
    }

    /// Obtain a bool variable indicating whether it's equal to another viewing
    /// memo `viewing_memo`.
    pub(crate) fn check_equal<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
        viewing_memo: &ViewableMemoVar,
    ) -> Result<BoolVar, CircuitError> {
        if viewing_memo.0.symm_ctxts.len() != self.0.symm_ctxts.len() {
            return Err(CircuitError::ParameterError(
                "the compared viewing memo has different ciphertext length".to_string(),
            ));
        }
        let mut check_equal =
            circuit.is_point_equal(&self.0.ephemeral, &viewing_memo.0.ephemeral)?;
        for (&left, &right) in self
            .0
            .symm_ctxts
            .iter()
            .zip(viewing_memo.0.symm_ctxts.iter())
        {
            let flag = circuit.is_equal(left, right)?;
            check_equal = circuit.logic_and(check_equal, flag)?;
        }
        Ok(check_equal)
    }

    /// Derive viewing memoby encrypting the content with viewer public key
    pub(crate) fn derive<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        viewer_pk: &EncKeyVars,
        data: &[Variable],
        enc_rand: Variable,
    ) -> Result<Self, CircuitError> {
        Ok(Self(
            ElGamalEncryptionGadget::<_, C::EmbeddedCurveParam>::elgamal_encrypt(
                circuit, viewer_pk, data, enc_rand,
            )?,
        ))
    }
}
#[derive(Debug)]
pub(crate) struct UserAddressVar(pub(crate) PointVariable);

impl UserAddressVar {
    pub(crate) fn dummy<F: PrimeField>(circuit: &mut PlonkCircuit<F>) -> Self {
        UserAddressVar(circuit.neutral_point_variable())
    }
}

#[derive(Debug)]
// Circuit variable for the opening of an asset record.
pub(crate) struct RecordOpeningVar {
    pub(crate) amount: Variable,
    pub(crate) asset_code: Variable,
    pub(crate) owner_addr: UserAddressVar,
    pub(crate) policy: AssetPolicyVar,
    pub(crate) freeze_flag: BoolVar,
    pub(crate) blind: Variable,
}

impl RecordOpeningVar {
    /// Create a variable for the opening of an asset record.
    pub(crate) fn new<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        ro: &RecordOpening<C>,
    ) -> Result<Self, CircuitError> {
        let amount = circuit.create_variable(C::ScalarField::from(ro.amount.0))?;
        let asset_code = circuit.create_variable(ro.asset_def.code.0)?;
        let owner_addr = UserAddressVar(
            circuit
                .create_point_variable(Point::from(ro.pub_key.address_internal().into_affine()))?,
        );
        let policy = AssetPolicyVar::new(circuit, &ro.asset_def.policy)?;
        let freeze_flag = circuit.create_boolean_variable(ro.freeze_flag.into())?;
        let blind = circuit.create_variable(ro.blind.0)?;
        Ok(Self {
            amount,
            asset_code,
            owner_addr,
            policy,
            freeze_flag,
            blind,
        })
    }

    /// Build constraints that derive the record commitment from an asset record
    /// opening.
    pub(crate) fn compute_record_commitment<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
    ) -> Result<Variable, CircuitError> {
        // To minimize the number of Rescue calls, combine `reveal_map` and
        // `freeze_flag` to a single variable `reveal_and_freeze := reveal_map << 1 +
        // freeze_flag`
        let zero_var = circuit.zero();
        let reveal_and_freeze = circuit.lc(
            &[
                self.policy.reveal_map,
                self.freeze_flag.into(),
                zero_var,
                zero_var,
            ],
            &[
                C::ScalarField::from(2u32),
                C::ScalarField::one(),
                C::ScalarField::zero(),
                C::ScalarField::zero(),
            ],
        )?;

        let input = vec![
            self.amount,
            self.asset_code,
            self.owner_addr.0.get_x(),
            self.owner_addr.0.get_y(),
            self.policy.viewer_pk.0.get_x(),
            self.policy.viewer_pk.0.get_y(),
            self.policy.cred_pk.0.get_x(),
            self.policy.cred_pk.0.get_y(),
            self.policy.freezer_pk.get_x(),
            self.policy.freezer_pk.get_y(),
            reveal_and_freeze,
            self.policy.reveal_threshold,
        ];
        circuit.commit(&input, self.blind)
    }

    /// Return boolean indicating whether the record's asset code is dummy
    pub(crate) fn check_asset_code_dummy<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
    ) -> Result<BoolVar, CircuitError> {
        let zero_if_dummy =
            circuit.add_constant(self.asset_code, &C::dummy_asset_code().0.neg())?;
        circuit.is_zero(zero_if_dummy)
    }
}
#[derive(Debug)]
// Circuit variable for an asset policy
pub(crate) struct AssetPolicyVar {
    pub(crate) viewer_pk: EncKeyVars,
    pub(crate) cred_pk: VerKeyVar,
    pub(crate) freezer_pk: PointVariable,
    pub(crate) reveal_map: Variable,
    pub(crate) reveal_threshold: Variable,
}

impl AssetPolicyVar {
    /// Create a variable for an asset policy.
    pub(crate) fn new<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        policy: &AssetPolicy<C>,
    ) -> Result<Self, CircuitError> {
        let reveal_map = circuit.create_variable(policy.reveal_map.to_scalar::<C>())?;
        let viewer_pk = circuit.create_enc_key_variable(&policy.viewer_pk.0)?;
        let cred_pk = circuit.create_signature_vk_variable(&policy.cred_pk.0)?;
        let freezer_pk =
            circuit.create_point_variable(Point::from(policy.freezer_pk.0.into_affine()))?;
        let reveal_threshold =
            circuit.create_variable(C::ScalarField::from(policy.reveal_threshold.0))?;
        Ok(Self {
            viewer_pk,
            cred_pk,
            freezer_pk,
            reveal_map,
            reveal_threshold,
        })
    }

    /// Set AssetPolicyVar public
    /// The order: (reveal_map, viewer_pk, cred_pk, freezer_pk,
    /// reveal_threshold)
    pub(crate) fn set_public<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
    ) -> Result<(), CircuitError> {
        circuit.set_variable_public(self.reveal_map)?;
        circuit.set_variable_public(self.viewer_pk.0.get_x())?;
        circuit.set_variable_public(self.viewer_pk.0.get_y())?;
        circuit.set_variable_public(self.cred_pk.0.get_x())?;
        circuit.set_variable_public(self.cred_pk.0.get_y())?;
        circuit.set_variable_public(self.freezer_pk.get_x())?;
        circuit.set_variable_public(self.freezer_pk.get_y())?;
        circuit.set_variable_public(self.reveal_threshold)?;
        Ok(())
    }

    /// Constrain self to be a dummy policy.
    pub(crate) fn enforce_dummy_policy<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
    ) -> Result<(), CircuitError> {
        let neutral_point = circuit.neutral_point_variable();
        circuit.enforce_point_equal(&self.viewer_pk.0, &neutral_point)?;
        circuit.enforce_point_equal(&self.cred_pk.0, &neutral_point)?;
        circuit.enforce_point_equal(&self.freezer_pk, &neutral_point)?;
        circuit.enforce_constant(self.reveal_map, C::ScalarField::zero())?;
        circuit.enforce_constant(self.reveal_threshold, C::ScalarField::zero())?;
        Ok(())
    }

    /// Obtain a bool variable indicating whether `self` is dummy policy.
    pub(crate) fn is_dummy_policy<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
    ) -> Result<BoolVar, CircuitError> {
        let dummy_viewer = self.is_dummy_viewing_pk::<C>(circuit)?;
        let dummy_cred_pk = self.is_dummy_cred_pk::<C>(circuit)?;
        let dummy_freezer_pk = self.is_dummy_freezer_pk::<C>(circuit)?;

        let reveal_map_plus_reveal_threshold =
            circuit.add(self.reveal_map, self.reveal_threshold)?;
        let no_reveal_map_or_reveal_threshold =
            circuit.is_zero(reveal_map_plus_reveal_threshold)?;
        circuit.logic_and_all(&[
            dummy_viewer,
            dummy_cred_pk,
            dummy_freezer_pk,
            no_reveal_map_or_reveal_threshold,
        ])
    }

    /// Constrain `self` to equal to another policy (in terms of values).
    pub(crate) fn enforce_equal_policy<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
        policy: &AssetPolicyVar,
    ) -> Result<(), CircuitError> {
        circuit.enforce_equal(self.reveal_map, policy.reveal_map)?;
        circuit.enforce_equal(self.reveal_threshold, policy.reveal_threshold)?;
        circuit.enforce_point_equal(&self.viewer_pk.0, &policy.viewer_pk.0)?;
        circuit.enforce_point_equal(&self.cred_pk.0, &policy.cred_pk.0)?;
        circuit.enforce_point_equal(&self.freezer_pk, &policy.freezer_pk)?;
        Ok(())
    }

    /// Obtain a bool variable indicating whether `self` to equal to another
    /// policy (in terms of values).
    pub(crate) fn check_equal_policy<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
        policy: &AssetPolicyVar,
    ) -> Result<BoolVar, CircuitError> {
        let a_eq = circuit.is_equal(self.reveal_map, policy.reveal_map)?;
        let b_eq = circuit.is_point_equal(&self.viewer_pk.0, &policy.viewer_pk.0)?;
        let c_eq = circuit.is_point_equal(&self.cred_pk.0, &policy.cred_pk.0)?;
        let d_eq = circuit.is_point_equal(&self.freezer_pk, &policy.freezer_pk)?;
        let e_eq = circuit.is_equal(self.reveal_threshold, policy.reveal_threshold)?;
        // check are all true
        circuit.logic_and_all(&[a_eq, b_eq, c_eq, d_eq, e_eq])
    }

    /// Obtain a bool variable indicating whether the policy's credential
    /// creator public key is dummy.
    pub(crate) fn is_dummy_cred_pk<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
    ) -> Result<BoolVar, CircuitError> {
        circuit.is_neutral_point::<C::EmbeddedCurveParam>(&self.cred_pk.0)
    }

    /// Obtain a bool variable indicating whether the policy's viewer public
    /// key is dummy.
    pub(crate) fn is_dummy_viewing_pk<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
    ) -> Result<BoolVar, CircuitError> {
        circuit.is_neutral_point::<C::EmbeddedCurveParam>(&self.viewer_pk.0)
    }

    /// Obtain a bool variable indicating whether the policy's viewer public
    /// key is dummy.
    pub(crate) fn is_dummy_freezer_pk<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
    ) -> Result<BoolVar, CircuitError> {
        circuit.is_neutral_point::<C::EmbeddedCurveParam>(&self.freezer_pk)
    }
}

// Circuit variable for an identity attribute
#[derive(Debug)]
pub(crate) struct IdAttrVar(pub(crate) Variable);

impl IdAttrVar {
    /// Create a variable for an identity attribute.
    fn new<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        id_attr: &IdentityAttribute<C>,
    ) -> Result<Self, CircuitError> {
        let attr = circuit.create_variable(id_attr.0)?;
        Ok(Self(attr))
    }
}
#[derive(Debug)]
/// Circuit variable for an expirable credential.
pub(crate) struct ExpirableCredVar {
    pub attrs: Vec<IdAttrVar>,
    pub expiry: Variable,
    pub cred: SignatureVar,
    pub user_addr: UserAddressVar,
    pub creator_pk: VerKeyVar,
}

impl ExpirableCredVar {
    /// Create a variable for an expirable credential.
    pub(crate) fn new<C: CapConfig>(
        circuit: &mut PlonkCircuit<C::ScalarField>,
        expirable_cred: &ExpirableCredential<C>,
    ) -> Result<Self, CircuitError> {
        let expiry = circuit.create_variable(C::ScalarField::from(expirable_cred.expiry))?;
        let cred = circuit.create_signature_variable(&expirable_cred.cred.0)?;
        let user_addr = UserAddressVar(circuit.create_point_variable(Point::from(
            expirable_cred.user_addr.internal().into_affine(),
        ))?);
        let creator_pk = circuit.create_signature_vk_variable(&expirable_cred.creator_pk.0)?;
        let attrs = expirable_cred
            .attrs
            .iter()
            .map(|id_attr| IdAttrVar::new(circuit, id_attr))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        Ok(Self {
            attrs,
            expiry,
            cred,
            user_addr,
            creator_pk,
        })
    }

    /// Build constraints that check the correctness of an ExpirableCredential
    /// which includes checking the correctness of actual signature over the
    /// message: (expiry || upk || attributes) AND **constraining** that it has
    /// not expired yet w.r.t the current timestamp
    ///
    /// * `circuit` - the mutable Plonk constraint system.
    /// * `valid_until` - claim that the credential is valid until the timestamp
    ///   `valid_until`.
    /// * output - a bool variable indicating whether the credential signature
    ///   is valid.
    pub(crate) fn verify<C: CapConfig>(
        &self,
        circuit: &mut PlonkCircuit<C::ScalarField>,
        valid_until: Variable,
    ) -> Result<BoolVar, CircuitError> {
        if self.attrs.len() != ATTRS_LEN {
            return Err(CircuitError::InternalError(format!(
                "wrong number of attributes in credential: {0}",
                self.attrs.len()
            )));
        }
        // 1. check credetial expiration time
        let expiry_minus_valid_until = circuit.sub(self.expiry, valid_until)?;
        circuit.enforce_in_range(expiry_minus_valid_until, MAX_TIMESTAMP_LEN)?;

        // 2. check credential signature
        // msg := (expiry || upk || attrs)
        let attrs: Vec<Variable> = self.attrs.iter().map(|id_attr| id_attr.0).collect();
        let msg = [
            vec![
                self.expiry,
                self.user_addr.0.get_x(),
                self.user_addr.0.get_y(),
            ],
            attrs,
        ]
        .concat();
        SignatureGadget::<_, C::EmbeddedCurveParam>::check_signature_validity(
            circuit,
            &self.creator_pk,
            &msg,
            &self.cred,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuit::structs::{AssetPolicyVar, ExpirableCredVar, RecordOpeningVar, ViewableMemoVar},
        keys::{CredIssuerKeyPair, UserKeyPair, ViewerKeyPair},
        prelude::{CapConfig, Config},
        structs::{
            AssetPolicy, ExpirableCredential, IdentityAttribute, RecordOpening, ViewableMemo,
        },
    };
    use ark_ff::{One, Zero};
    use ark_std::{test_rng, vec::Vec};
    use jf_relation::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit};

    type F = <Config as CapConfig>::ScalarField;
    type Fj = <Config as CapConfig>::EmbeddedCurveScalarField;

    ////////////////////////////////////////////////////////////
    // Credential related tests ////////////////////////////////
    ////////////////////////////////////////////////////////////

    fn build_verify_cred_circuit(
        valid_until: F,
        expirable_cred: &ExpirableCredential<Config>,
    ) -> Result<(BoolVar, ExpirableCredVar, PlonkCircuit<F>), CircuitError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let valid_until = circuit.create_variable(valid_until)?;
        let expirable_cred = ExpirableCredVar::new(&mut circuit, expirable_cred)?;
        let b = expirable_cred.verify::<Config>(&mut circuit, valid_until)?;
        Ok((b, expirable_cred, circuit))
    }

    #[test]
    fn test_verify_expirable_credential() -> Result<(), CircuitError> {
        let rng = &mut test_rng();
        let minter_keypair = CredIssuerKeyPair::generate(rng);
        let user = UserKeyPair::<Config>::generate(rng);
        let expiry = 9999u64;
        let attrs = IdentityAttribute::random_vector(rng);
        let expirable_cred =
            ExpirableCredential::create(user.address(), attrs, expiry, &minter_keypair).unwrap();

        // Happy path
        let valid_until = F::from(expiry - 100u64);
        let (b, cred_var, mut circuit) = build_verify_cred_circuit(valid_until, &expirable_cred)?;
        assert_eq!(circuit.witness(b.into())?, F::one());
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Wrong credential (prover response in Schnorr) should fail.
        *circuit.witness_mut(cred_var.cred.s) = F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Expired credential should fail
        let valid_until = F::from(expiry + 3u64);
        let (_, _, circuit) = build_verify_cred_circuit(valid_until, &expirable_cred)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    ////////////////////////////////////////////////////////////
    // Record commitment related tests /////////////////////////
    ////////////////////////////////////////////////////////////

    #[test]
    fn test_compute_record_commitment_consistency() -> Result<(), CircuitError> {
        let rng = &mut test_rng();
        let record_open = RecordOpening::<Config>::rand_for_test(rng);
        let record_comm = record_open.derive_record_commitment();
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let ro_var = RecordOpeningVar::new(&mut circuit, &record_open)?;
        let rc_var = ro_var.compute_record_commitment::<Config>(&mut circuit)?;

        // check output consistency
        assert_eq!(record_comm.0, circuit.witness(rc_var)?);
        // check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(rc_var) = F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    ////////////////////////////////////////////////////////////
    // Asset policy related tests //////////////////////////////
    ////////////////////////////////////////////////////////////

    #[test]
    fn test_enforce_dummy_policy() -> Result<(), CircuitError> {
        // good path
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let dummy_policy = AssetPolicy::<Config>::default();
        let dummy_policy = AssetPolicyVar::new(&mut circuit, &dummy_policy)?;
        dummy_policy.enforce_dummy_policy::<Config>(&mut circuit)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        // bad path
        let rng = &mut test_rng();
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let policy = AssetPolicy::<Config>::rand_for_test(rng);

        let policy = AssetPolicyVar::new(&mut circuit, &policy)?;
        policy.enforce_dummy_policy::<Config>(&mut circuit)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_enforce_equal_policy() -> Result<(), CircuitError> {
        let mut rng = &mut test_rng();
        // happy path
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let policy1 = AssetPolicy::<Config>::rand_for_test(&mut rng);
        let policy2 = policy1.clone();
        let policy1 = AssetPolicyVar::new(&mut circuit, &policy1)?;
        let policy2 = AssetPolicyVar::new(&mut circuit, &policy2)?;
        policy1.enforce_equal_policy::<Config>(&mut circuit, &policy2)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // error path
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let policy1 = AssetPolicy::<Config>::rand_for_test(&mut rng);
        let policy2 = AssetPolicy::<Config>::rand_for_test(&mut rng);
        let policy1 = AssetPolicyVar::new(&mut circuit, &policy1)?;
        let policy2 = AssetPolicyVar::new(&mut circuit, &policy2)?;
        policy1.enforce_equal_policy::<Config>(&mut circuit, &policy2)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    ////////////////////////////////////////////////////////////
    // Viewer memo related tests ////////////////////////////////
    ////////////////////////////////////////////////////////////

    #[test]
    fn test_check_equal_viewing_memo() -> Result<(), CircuitError> {
        let rng = &mut test_rng();
        let data: Vec<F> = (0..10).map(|i| F::from(i as u32)).collect();
        let mut data2 = data.clone();
        data2[0] = F::from(1u32);
        let pk = ViewerKeyPair::<Config>::generate(rng).pub_key();
        let pk2 = ViewerKeyPair::<Config>::generate(rng).pub_key();
        let enc_rand = Fj::from(324u32);
        let enc_rand_2 = Fj::from(23432u32);

        let viewing_memo_1 = ViewableMemo::<Config>(pk.encrypt(enc_rand, &data));
        // different pub_key
        let viewing_memo_2 = ViewableMemo::<Config>(pk2.encrypt(enc_rand, &data));
        // different data
        let viewing_memo_3 = ViewableMemo::<Config>(pk.encrypt(enc_rand, &data2));
        // different enc_rand
        let viewing_memo_4 = ViewableMemo::<Config>(pk.encrypt(enc_rand_2, &data));

        check_check_equal_viewing_memo(&viewing_memo_1, &viewing_memo_1, F::one())?;
        check_check_equal_viewing_memo(&viewing_memo_1, &viewing_memo_2, F::zero())?;
        check_check_equal_viewing_memo(&viewing_memo_1, &viewing_memo_3, F::zero())?;
        check_check_equal_viewing_memo(&viewing_memo_1, &viewing_memo_4, F::zero())?;

        // should return error when compared to an viewing memowith different format
        let viewing_memo_5 = ViewableMemo::<Config>(pk.encrypt(enc_rand, &[]));
        assert!(
            check_check_equal_viewing_memo(&viewing_memo_1, &viewing_memo_5, F::zero()).is_err()
        );

        Ok(())
    }

    fn check_check_equal_viewing_memo(
        viewing_memo_1: &ViewableMemo<Config>,
        viewing_memo_2: &ViewableMemo<Config>,
        expect_equal: F,
    ) -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let viewing_memo_1 = ViewableMemoVar::new(&mut circuit, viewing_memo_1)?;
        let viewing_memo_2 = ViewableMemoVar::new(&mut circuit, viewing_memo_2)?;
        let flag = viewing_memo_1.check_equal::<Config>(&mut circuit, &viewing_memo_2)?;

        assert_eq!(circuit.witness(flag.into())?, expect_equal);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
}
