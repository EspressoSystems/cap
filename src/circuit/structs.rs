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
    constants::{ATTRS_LEN, DUMMY_ASSET_CODE, MAX_TIMESTAMP_LEN},
    structs::{AssetPolicy, AuditMemo, ExpirableCredential, IdentityAttribute, RecordOpening},
    BaseField, CurveParam,
};
use ark_ec::ProjectiveCurve;
use ark_ff::{One, PrimeField, Zero};
use ark_std::{format, ops::Neg, string::ToString, vec, vec::Vec};
use jf_plonk::{
    circuit::{
        customized::ecc::{Point, PointVariable},
        Circuit, PlonkCircuit, Variable,
    },
    errors::{CircuitError::InternalError, PlonkError},
};
use jf_primitives::circuit::{
    commitment::CommitmentGadget,
    elgamal::{ElGamalEncryptionGadget, ElGamalHybridCtxtVars, EncKeyVars},
    signature::schnorr::{SignatureGadget, SignatureVar, VerKeyVar},
};

#[derive(Debug)]
pub(crate) struct AuditMemoVar(pub(crate) ElGamalHybridCtxtVars);

impl AuditMemoVar {
    /// Create a variable for audit memo
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<BaseField>,
        audit_memo: &AuditMemo,
    ) -> Result<Self, PlonkError> {
        let ctxts = circuit.create_ciphertext_variable(&audit_memo.0)?;
        Ok(Self(ctxts))
    }

    /// Set AuditMemoVar public
    pub(crate) fn set_public(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
    ) -> Result<(), PlonkError> {
        circuit.set_variable_public(self.0.ephemeral.get_x())?;
        circuit.set_variable_public(self.0.ephemeral.get_y())?;
        for &ctxt_var in self.0.symm_ctxts.iter() {
            circuit.set_variable_public(ctxt_var)?;
        }
        Ok(())
    }

    /// Obtain a bool variable indicating whether it's equal to another audit
    /// memo `audit_memo`.
    pub(crate) fn check_equal(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
        audit_memo: &AuditMemoVar,
    ) -> Result<Variable, PlonkError> {
        if audit_memo.0.symm_ctxts.len() != self.0.symm_ctxts.len() {
            return Err(PlonkError::CircuitError(InternalError(
                "the compared audit memo has different ciphertext length".to_string(),
            )));
        }
        let mut check_equal =
            circuit.check_equal_point(&self.0.ephemeral, &audit_memo.0.ephemeral)?;
        for (&left, &right) in self.0.symm_ctxts.iter().zip(audit_memo.0.symm_ctxts.iter()) {
            let flag = circuit.check_equal(left, right)?;
            check_equal = circuit.mul(check_equal, flag)?;
        }
        Ok(check_equal)
    }

    /// Derive audit memo by encrypting the content with auditor public key
    pub(crate) fn derive(
        circuit: &mut PlonkCircuit<BaseField>,
        auditor_pk: &EncKeyVars,
        data: &[Variable],
        enc_rand: Variable,
    ) -> Result<Self, PlonkError> {
        Ok(Self(
            ElGamalEncryptionGadget::<_, CurveParam>::elgamal_encrypt(
                circuit, auditor_pk, data, enc_rand,
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
    pub(crate) freeze_flag: Variable,
    pub(crate) blind: Variable,
}

impl RecordOpeningVar {
    /// Create a variable for the opening of an asset record.
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<BaseField>,
        ro: &RecordOpening,
    ) -> Result<Self, PlonkError> {
        let amount = circuit.create_variable(BaseField::from(ro.amount.0))?;
        let asset_code = circuit.create_variable(ro.asset_def.code.0)?;
        let owner_addr = UserAddressVar(
            circuit
                .create_point_variable(Point::from(ro.pub_key.address_internal().into_affine()))?,
        );
        let policy = AssetPolicyVar::new(circuit, &ro.asset_def.policy)?;
        let freeze_flag = circuit.create_bool_variable(ro.freeze_flag.into())?;
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
    pub(crate) fn compute_record_commitment(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
    ) -> Result<Variable, PlonkError> {
        // To minimize the number of Rescue calls, combine `reveal_map` and
        // `freeze_flag` to a single variable `reveal_and_freeze := reveal_map << 1 +
        // freeze_flag`
        let zero_var = circuit.zero();
        let reveal_and_freeze = circuit.lc(
            &[self.policy.reveal_map, self.freeze_flag, zero_var, zero_var],
            &[
                BaseField::from(2u32),
                BaseField::one(),
                BaseField::zero(),
                BaseField::zero(),
            ],
        )?;

        let input = vec![
            self.amount,
            self.asset_code,
            self.owner_addr.0.get_x(),
            self.owner_addr.0.get_y(),
            self.policy.auditor_pk.0.get_x(),
            self.policy.auditor_pk.0.get_y(),
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
    pub(crate) fn check_asset_code_dummy(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
    ) -> Result<Variable, PlonkError> {
        let zero_if_dummy = circuit.add_constant(self.asset_code, &DUMMY_ASSET_CODE.0.neg())?;
        circuit.check_is_zero(zero_if_dummy)
    }
}
#[derive(Debug)]
// Circuit variable for an asset policy
pub(crate) struct AssetPolicyVar {
    pub(crate) auditor_pk: EncKeyVars,
    pub(crate) cred_pk: VerKeyVar,
    pub(crate) freezer_pk: PointVariable,
    pub(crate) reveal_map: Variable,
    pub(crate) reveal_threshold: Variable,
}

impl AssetPolicyVar {
    /// Create a variable for an asset policy.
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<BaseField>,
        policy: &AssetPolicy,
    ) -> Result<Self, PlonkError> {
        let reveal_map = circuit.create_variable(BaseField::from(policy.reveal_map))?;
        let auditor_pk = circuit.create_enc_key_variable(&policy.auditor_pk.0)?;
        let cred_pk = circuit.create_signature_vk_variable(&policy.cred_pk.0)?;
        let freezer_pk =
            circuit.create_point_variable(Point::from(policy.freezer_pk.0.into_affine()))?;
        let reveal_threshold =
            circuit.create_variable(BaseField::from(policy.reveal_threshold.0))?;
        Ok(Self {
            auditor_pk,
            cred_pk,
            freezer_pk,
            reveal_map,
            reveal_threshold,
        })
    }

    /// Set AssetPolicyVar public
    /// The order: (reveal_map, auditor_pk, cred_pk, freezer_pk,
    /// reveal_threshold)
    pub(crate) fn set_public(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
    ) -> Result<(), PlonkError> {
        circuit.set_variable_public(self.reveal_map)?;
        circuit.set_variable_public(self.auditor_pk.0.get_x())?;
        circuit.set_variable_public(self.auditor_pk.0.get_y())?;
        circuit.set_variable_public(self.cred_pk.0.get_x())?;
        circuit.set_variable_public(self.cred_pk.0.get_y())?;
        circuit.set_variable_public(self.freezer_pk.get_x())?;
        circuit.set_variable_public(self.freezer_pk.get_y())?;
        circuit.set_variable_public(self.reveal_threshold)?;
        Ok(())
    }

    /// Constrain self to be a dummy policy.
    pub(crate) fn enforce_dummy_policy(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
    ) -> Result<(), PlonkError> {
        let neutral_point = circuit.neutral_point_variable();
        circuit.point_equal_gate(&self.auditor_pk.0, &neutral_point)?;
        circuit.point_equal_gate(&self.cred_pk.0, &neutral_point)?;
        circuit.point_equal_gate(&self.freezer_pk, &neutral_point)?;
        circuit.constant_gate(self.reveal_map, BaseField::zero())?;
        circuit.constant_gate(self.reveal_threshold, BaseField::zero())?;
        Ok(())
    }

    /// Obtain a bool variable indicating whether `self` is dummy policy.
    pub(crate) fn is_dummy_policy(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
    ) -> Result<Variable, PlonkError> {
        let dummy_auditor = self.is_dummy_audit_pk(circuit)?;
        let dummy_cred_pk = self.is_dummy_cred_pk(circuit)?;
        let dummy_freezer_pk = self.is_dummy_freezer_pk(circuit)?;

        let reveal_map_plus_reveal_threshold =
            circuit.add(self.reveal_map, self.reveal_threshold)?;
        let no_reveal_map_or_reveal_threshold =
            circuit.check_is_zero(reveal_map_plus_reveal_threshold)?;
        // TODO: implement LogicAnd gate for more than 2 variables after adding the new
        // selector for TurboPlonk CS
        circuit.logic_and_all(&[
            dummy_auditor,
            dummy_cred_pk,
            dummy_freezer_pk,
            no_reveal_map_or_reveal_threshold,
        ])
    }

    /// Constrain `self` to equal to another policy (in terms of values).
    pub(crate) fn enforce_equal_policy(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
        policy: &AssetPolicyVar,
    ) -> Result<(), PlonkError> {
        circuit.equal_gate(self.reveal_map, policy.reveal_map)?;
        circuit.equal_gate(self.reveal_threshold, policy.reveal_threshold)?;
        circuit.point_equal_gate(&self.auditor_pk.0, &policy.auditor_pk.0)?;
        circuit.point_equal_gate(&self.cred_pk.0, &policy.cred_pk.0)?;
        circuit.point_equal_gate(&self.freezer_pk, &policy.freezer_pk)?;
        Ok(())
    }

    /// Obtain a bool variable indicating whether `self` to equal to another
    /// policy (in terms of values).
    pub(crate) fn check_equal_policy(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
        policy: &AssetPolicyVar,
    ) -> Result<Variable, PlonkError> {
        let a_eq = circuit.check_equal(self.reveal_map, policy.reveal_map)?;
        let b_eq = circuit.check_equal_point(&self.auditor_pk.0, &policy.auditor_pk.0)?;
        let c_eq = circuit.check_equal_point(&self.cred_pk.0, &policy.cred_pk.0)?;
        let d_eq = circuit.check_equal_point(&self.freezer_pk, &policy.freezer_pk)?;
        let e_eq = circuit.check_equal(self.reveal_threshold, policy.reveal_threshold)?;
        // check are all true
        circuit.logic_and_all(&[a_eq, b_eq, c_eq, d_eq, e_eq])
    }

    /// Obtain a bool variable indicating whether the policy's credential issuer
    /// public key is dummy.
    pub(crate) fn is_dummy_cred_pk(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
    ) -> Result<Variable, PlonkError> {
        circuit.is_neutral_point::<CurveParam>(&self.cred_pk.0)
    }

    /// Obtain a bool variable indicating whether the policy's auditor public
    /// key is dummy.
    pub(crate) fn is_dummy_audit_pk(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
    ) -> Result<Variable, PlonkError> {
        circuit.is_neutral_point::<CurveParam>(&self.auditor_pk.0)
    }

    /// Obtain a bool variable indicating whether the policy's auditor public
    /// key is dummy.
    pub(crate) fn is_dummy_freezer_pk(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
    ) -> Result<Variable, PlonkError> {
        circuit.is_neutral_point::<CurveParam>(&self.freezer_pk)
    }
}

// Circuit variable for an identity attribute
#[derive(Debug)]
pub(crate) struct IdAttrVar(pub(crate) Variable);

impl IdAttrVar {
    /// Create a variable for an identity attribute.
    fn new(
        circuit: &mut PlonkCircuit<BaseField>,
        id_attr: &IdentityAttribute,
    ) -> Result<Self, PlonkError> {
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
    pub issuer_pk: VerKeyVar,
}

impl ExpirableCredVar {
    /// Create a variable for an expirable credential.
    pub(crate) fn new(
        circuit: &mut PlonkCircuit<BaseField>,
        expirable_cred: &ExpirableCredential,
    ) -> Result<Self, PlonkError> {
        let expiry = circuit.create_variable(BaseField::from(expirable_cred.expiry))?;
        let cred = circuit.create_signature_variable(&expirable_cred.cred.0)?;
        let user_addr = UserAddressVar(circuit.create_point_variable(Point::from(
            expirable_cred.user_addr.internal().into_affine(),
        ))?);
        let issuer_pk = circuit.create_signature_vk_variable(&expirable_cred.issuer_pk.0)?;
        let attrs = expirable_cred
            .attrs
            .iter()
            .map(|id_attr| IdAttrVar::new(circuit, id_attr))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        Ok(Self {
            attrs,
            expiry,
            cred,
            user_addr,
            issuer_pk,
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
    pub(crate) fn verify(
        &self,
        circuit: &mut PlonkCircuit<BaseField>,
        valid_until: Variable,
    ) -> Result<Variable, PlonkError> {
        if self.attrs.len() != ATTRS_LEN {
            return Err(PlonkError::CircuitError(InternalError(format!(
                "wrong number of attributes in credential: {0}",
                self.attrs.len()
            ))));
        }
        // 1. check credetial expiration time
        let expiry_minus_valid_until = circuit.sub(self.expiry, valid_until)?;
        circuit.range_gate(expiry_minus_valid_until, MAX_TIMESTAMP_LEN)?;

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
        SignatureGadget::<_, CurveParam>::check_signature_validity(
            circuit,
            &self.issuer_pk,
            &msg,
            &self.cred,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuit::structs::{AssetPolicyVar, AuditMemoVar, ExpirableCredVar, RecordOpeningVar},
        keys::{AuditorKeyPair, CredIssuerKeyPair, UserKeyPair},
        structs::{AssetPolicy, AuditMemo, ExpirableCredential, IdentityAttribute, RecordOpening},
        BaseField, ScalarField,
    };
    use ark_ff::{One, Zero};
    use ark_std::{test_rng, vec::Vec};
    use jf_plonk::{
        circuit::{Circuit, PlonkCircuit, Variable},
        errors::PlonkError,
    };

    ////////////////////////////////////////////////////////////
    // Credential related tests ////////////////////////////////
    ////////////////////////////////////////////////////////////

    fn build_verify_cred_circuit(
        valid_until: BaseField,
        expirable_cred: &ExpirableCredential,
    ) -> Result<(Variable, ExpirableCredVar, PlonkCircuit<BaseField>), PlonkError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let valid_until = circuit.create_variable(valid_until)?;
        let expirable_cred = ExpirableCredVar::new(&mut circuit, expirable_cred)?;
        let b = expirable_cred.verify(&mut circuit, valid_until)?;
        Ok((b, expirable_cred, circuit))
    }

    #[test]
    fn test_verify_expirable_credential() -> Result<(), PlonkError> {
        let rng = &mut test_rng();
        let issuer_keypair = CredIssuerKeyPair::generate(rng);
        let user = UserKeyPair::generate(rng);
        let expiry = 9999u64;
        let attrs = IdentityAttribute::random_vector(rng);
        let expirable_cred =
            ExpirableCredential::issue(user.address(), attrs, expiry, &issuer_keypair).unwrap();

        // Happy path
        let valid_until = BaseField::from(expiry - 100u64);
        let (b, cred_var, mut circuit) = build_verify_cred_circuit(valid_until, &expirable_cred)?;
        assert_eq!(circuit.witness(b)?, BaseField::one());
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Wrong credential (prover response in Schnorr) should fail.
        *circuit.witness_mut(cred_var.cred.s) = BaseField::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Expired credential should fail
        let valid_until = BaseField::from(expiry + 3u64);
        let (_, _, circuit) = build_verify_cred_circuit(valid_until, &expirable_cred)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    ////////////////////////////////////////////////////////////
    // Record commitment related tests /////////////////////////
    ////////////////////////////////////////////////////////////

    #[test]
    fn test_compute_record_commitment_consistency() -> Result<(), PlonkError> {
        let rng = &mut test_rng();
        let record_open = RecordOpening::rand_for_test(rng);
        let record_comm = record_open.derive_record_commitment();
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let ro_var = RecordOpeningVar::new(&mut circuit, &record_open)?;
        let rc_var = ro_var.compute_record_commitment(&mut circuit)?;

        // check output consistency
        assert_eq!(record_comm.0, circuit.witness(rc_var)?);
        // check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(rc_var) = BaseField::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    ////////////////////////////////////////////////////////////
    // Asset policy related tests //////////////////////////////
    ////////////////////////////////////////////////////////////

    #[test]
    fn test_enforce_dummy_policy() -> Result<(), PlonkError> {
        // good path
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let dummy_policy = AssetPolicy::default();
        let dummy_policy = AssetPolicyVar::new(&mut circuit, &dummy_policy)?;
        dummy_policy.enforce_dummy_policy(&mut circuit)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        // bad path
        let rng = &mut test_rng();
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let policy = AssetPolicy::rand_for_test(rng);

        let policy = AssetPolicyVar::new(&mut circuit, &policy)?;
        policy.enforce_dummy_policy(&mut circuit)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    #[test]
    fn test_enforce_equal_policy() -> Result<(), PlonkError> {
        let mut rng = &mut test_rng();
        // happy path
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let policy1 = AssetPolicy::rand_for_test(&mut rng);
        let policy2 = policy1.clone();
        let policy1 = AssetPolicyVar::new(&mut circuit, &policy1)?;
        let policy2 = AssetPolicyVar::new(&mut circuit, &policy2)?;
        policy1.enforce_equal_policy(&mut circuit, &policy2)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // error path
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let policy1 = AssetPolicy::rand_for_test(&mut rng);
        let policy2 = AssetPolicy::rand_for_test(&mut rng);
        let policy1 = AssetPolicyVar::new(&mut circuit, &policy1)?;
        let policy2 = AssetPolicyVar::new(&mut circuit, &policy2)?;
        policy1.enforce_equal_policy(&mut circuit, &policy2)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    ////////////////////////////////////////////////////////////
    // Audit memo related tests ////////////////////////////////
    ////////////////////////////////////////////////////////////

    #[test]
    fn test_check_equal_audit_memo() -> Result<(), PlonkError> {
        let rng = &mut test_rng();
        let data: Vec<BaseField> = (0..10).map(|i| BaseField::from(i as u32)).collect();
        let mut data2 = data.clone();
        data2[0] = BaseField::from(1u32);
        let pk = AuditorKeyPair::generate(rng).pub_key();
        let pk2 = AuditorKeyPair::generate(rng).pub_key();
        let enc_rand = ScalarField::from(324u32);
        let enc_rand_2 = ScalarField::from(23432u32);

        let audit_memo_1 = AuditMemo(pk.encrypt(enc_rand, &data));
        // different pub_key
        let audit_memo_2 = AuditMemo(pk2.encrypt(enc_rand, &data));
        // different data
        let audit_memo_3 = AuditMemo(pk.encrypt(enc_rand, &data2));
        // different enc_rand
        let audit_memo_4 = AuditMemo(pk.encrypt(enc_rand_2, &data));

        check_check_equal_audit_memo(&audit_memo_1, &audit_memo_1, BaseField::one())?;
        check_check_equal_audit_memo(&audit_memo_1, &audit_memo_2, BaseField::zero())?;
        check_check_equal_audit_memo(&audit_memo_1, &audit_memo_3, BaseField::zero())?;
        check_check_equal_audit_memo(&audit_memo_1, &audit_memo_4, BaseField::zero())?;

        // should return error when compared to an audit memo with different format
        let audit_memo_5 = AuditMemo(pk.encrypt(enc_rand, &[]));
        assert!(
            check_check_equal_audit_memo(&audit_memo_1, &audit_memo_5, BaseField::zero()).is_err()
        );

        Ok(())
    }

    fn check_check_equal_audit_memo(
        audit_memo_1: &AuditMemo,
        audit_memo_2: &AuditMemo,
        expect_equal: BaseField,
    ) -> Result<(), PlonkError> {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let audit_memo_1 = AuditMemoVar::new(&mut circuit, audit_memo_1)?;
        let audit_memo_2 = AuditMemoVar::new(&mut circuit, audit_memo_2)?;
        let flag = audit_memo_1.check_equal(&mut circuit, &audit_memo_2)?;

        assert_eq!(circuit.witness(flag)?, expect_equal);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        Ok(())
    }
}
