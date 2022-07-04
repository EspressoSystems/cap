// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Utility structures and functions needed for internal purposes, writing tests
//! or benchmarks.
pub mod params_builder;

use crate::{
    circuit::{freeze::FreezeCircuit, mint::MintCircuit, transfer::TransferCircuit},
    errors::TxnApiError,
    keys::FreezerPubKey,
    structs::{Amount, AssetDefinition, NoteType, RecordOpening},
    BaseField,
};
use ark_ec::ProjectiveCurve;
use ark_std::{format, string::ToString};
use jf_plonk::circuit::Arithmetization;
pub use params_builder::TxnsParams;

impl From<&FreezerPubKey> for (BaseField, BaseField) {
    fn from(pk: &FreezerPubKey) -> Self {
        let point = pk.0.into_affine();
        (point.x, point.y)
    }
}

/// Compute the asset definition being transferred given the input ROs
pub(crate) fn get_asset_def_in_transfer_txn(
    input_ros: &[RecordOpening],
) -> Result<&AssetDefinition, TxnApiError> {
    if input_ros.is_empty() {
        return Err(TxnApiError::InternalError("Empty ROs!".to_string()));
    }
    if !input_ros[0].asset_def.is_native() {
        return Err(TxnApiError::InternalError(
            "First input is not native!".to_string(),
        ));
    }

    // First input is always native asset
    // Other non-dummy inputs are all native (transfering or freezeing native
    // assets) or all the same non-native
    for input in input_ros.iter().skip(1) {
        if !input.asset_def.is_dummy() {
            return Ok(&input.asset_def); // native asset or txn asset
        }
    }
    Ok(&input_ros[0].asset_def)
}

/// Don't use in production, only for testing purpose, its robustness is poor.
#[allow(dead_code)]
pub(crate) fn next_power_of_three(current: usize) -> usize {
    let mut exp = ((current as f64).log10() / 3f64.log10()).floor() as u32;
    let mut result = 3usize.pow(exp);
    while result < current {
        exp += 1;
        result = 3usize.pow(exp);
    }
    result
}

/// Computes the sum of Amount elements. If the final results overflows
/// returns an error
pub(crate) fn safe_sum_amount(elems: &[Amount]) -> Option<Amount> {
    let res = elems
        .iter()
        .fold(Some(0u128), |acc, elem| acc?.checked_add((*elem).0));
    res.map(|x| x.into())
}
/// Computes the size of the universal parameters given the type and the
/// parameters of a note
/// * `note_type` - Type of note (Transfer,Mint,Freeze)
/// * `num_inputs` - number of inputs. This parameter is ignored in the case of
///   Mint notes.
/// * `num_outputs` - number of outputs. This parameter is ignored in the case
///   of Mint/Freeze notes
/// * `tree_depth` - depth of the Merkle tree
/// * `returns` - size of the srs or an error
// TODO add number of identity attributes as a parameter
pub fn compute_universal_param_size(
    note_type: NoteType,
    num_inputs: usize,
    num_outputs: usize,
    tree_depth: u8,
) -> Result<usize, TxnApiError> {
    let circuit = match note_type {
        NoteType::Transfer => {
            TransferCircuit::build_for_preprocessing(num_inputs, num_outputs, tree_depth)?
                .0
                 .0
        },
        NoteType::Mint => MintCircuit::build_for_preprocessing(tree_depth)?.0 .0,
        NoteType::Freeze => {
            FreezeCircuit::build_for_preprocessing(tree_depth, num_inputs)?
                .0
                 .0
        },
    };

    Ok(circuit
        .eval_domain_size()
        .map_err(|e| TxnApiError::FailedSnark(format!("{:?}", e)))?
        + 2) // +2 for handling zero-knowledge
}

#[cfg(test)]
mod tests {
    use crate::{
        keys::UserKeyPair,
        structs::{Amount, AssetDefinition, FreezeFlag, NoteType, RecordOpening},
        utils::{compute_universal_param_size, get_asset_def_in_transfer_txn, safe_sum_amount},
    };

    #[test]
    fn test_safe_sum_amount() {
        let safe_input_values = Amount::from_vec(&[3_u128, 10_u128, 20_u128]);
        assert_eq!(
            safe_sum_amount(&safe_input_values[..]).unwrap(),
            33_u128.into()
        );

        let unsafe_input_values = Amount::from_vec(&[u128::MAX, 1_u128]);
        assert!(safe_sum_amount(&unsafe_input_values).is_none());
    }

    #[test]
    fn test_compute_srs_size() {
        // Transfer
        #[cfg(not(feature = "bls12_377"))]
        assert_eq!(
            65538,
            compute_universal_param_size(NoteType::Transfer, 3, 5, 26).unwrap()
        );
        #[cfg(feature = "bls12_377")]
        assert_eq!(
            131074,
            compute_universal_param_size(NoteType::Transfer, 3, 5, 26).unwrap()
        );
        #[cfg(not(feature = "bls12_377"))]
        assert_eq!(
            32770,
            compute_universal_param_size(NoteType::Transfer, 2, 2, 10).unwrap()
        );
        #[cfg(feature = "bls12_377")]
        assert_eq!(
            65538,
            compute_universal_param_size(NoteType::Transfer, 2, 2, 10).unwrap()
        );

        // Mint
        #[cfg(not(feature = "bls12_377"))]
        assert_eq!(
            16386,
            compute_universal_param_size(NoteType::Mint, 0, 0, 26).unwrap()
        );
        #[cfg(feature = "bls12_377")]
        assert_eq!(
            32770,
            compute_universal_param_size(NoteType::Mint, 0, 0, 26).unwrap()
        );
        // Freeze
        #[cfg(not(feature = "bls12_377"))]
        assert_eq!(
            16386,
            compute_universal_param_size(NoteType::Freeze, 2, 0, 5).unwrap()
        );
        #[cfg(feature = "bls12_377")]
        assert_eq!(
            32770,
            compute_universal_param_size(NoteType::Freeze, 2, 0, 5).unwrap()
        );

        #[cfg(not(feature = "bls12_377"))]
        assert_eq!(
            65538,
            compute_universal_param_size(NoteType::Freeze, 5, 0, 26).unwrap()
        );
        #[cfg(feature = "bls12_377")]
        assert_eq!(
            131074,
            compute_universal_param_size(NoteType::Freeze, 5, 0, 26).unwrap()
        );
    }

    #[test]
    fn test_get_asset_def_in_transfer_txn() {
        let mut rng = ark_std::test_rng();

        let asset_def_native = AssetDefinition::native();
        let asset_def_2 = AssetDefinition::rand_for_test(&mut rng);
        let asset_def_3 = AssetDefinition::rand_for_test(&mut rng);
        let user_keypair = UserKeyPair::generate(&mut rng);

        let ro_1 = RecordOpening::new(
            &mut rng,
            23u64.into(),
            asset_def_native.clone(),
            user_keypair.pub_key(),
            FreezeFlag::Unfrozen,
        );

        let ro_2 = RecordOpening::new(
            &mut rng,
            23u64.into(),
            asset_def_2.clone(),
            user_keypair.pub_key(),
            FreezeFlag::Unfrozen,
        );

        let ro_3 = RecordOpening::new(
            &mut rng,
            23u64.into(),
            asset_def_3.clone(),
            user_keypair.pub_key(),
            FreezeFlag::Unfrozen,
        );
        let (ro_dummy, _keypair_dummy) = RecordOpening::dummy(&mut rng, FreezeFlag::Unfrozen);

        assert!(get_asset_def_in_transfer_txn(&[]).is_err());
        assert_eq!(
            *get_asset_def_in_transfer_txn(&[ro_1.clone()]).unwrap(),
            asset_def_native
        );
        assert_eq!(
            *get_asset_def_in_transfer_txn(&[ro_1.clone(), ro_2.clone()]).unwrap(),
            asset_def_2
        );
        assert_eq!(
            *get_asset_def_in_transfer_txn(&[ro_1.clone(), ro_2.clone(), ro_3.clone()]).unwrap(),
            asset_def_2
        );
        assert_eq!(
            *get_asset_def_in_transfer_txn(&[ro_1.clone(), ro_1.clone(), ro_1.clone()]).unwrap(),
            asset_def_native
        );
        assert_eq!(
            *get_asset_def_in_transfer_txn(&[ro_1.clone(), ro_dummy.clone(), ro_dummy.clone()])
                .unwrap(),
            asset_def_native
        );
        assert_eq!(
            *get_asset_def_in_transfer_txn(&[ro_1.clone(), ro_dummy.clone(), ro_2.clone()])
                .unwrap(),
            asset_def_2
        );
        assert_eq!(
            *get_asset_def_in_transfer_txn(&[ro_1.clone(), ro_2.clone(), ro_dummy.clone()])
                .unwrap(),
            asset_def_2
        );
        assert!(get_asset_def_in_transfer_txn(&[ro_2.clone(), ro_1.clone()]).is_err());
        assert!(get_asset_def_in_transfer_txn(&[ro_dummy.clone(), ro_1.clone()]).is_err());
    }
}

#[test]
fn test_next_power_of_three() {
    assert_eq!(next_power_of_three(0), 1);
    assert_eq!(next_power_of_three(8), 9);
    assert_eq!(next_power_of_three(9), 9);
    assert_eq!(next_power_of_three(14), 27);
}

/// TODO: (alex) make many reusable functions in this module generic and not
/// just bounded to transfer input.
pub(crate) mod txn_helpers {

    use crate::{
        errors::TxnApiError,
        keys::{AuditorPubKey, CredIssuerPubKey, FreezerPubKey},
        structs::{Amount, BlindFactor, FreezeFlag, Nullifier, RecordOpening},
        transfer::TransferNoteInput,
    };

    use crate::{
        structs::{ReceiverMemo, TxnFeeInfo},
        BaseField, NodeValue,
    };
    use ark_serialize::CanonicalSerialize;
    use ark_std::{
        collections::{BTreeSet, HashMap},
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
    use jf_primitives::merkle_tree::{MerkleLeaf, MerkleLeafProof, MerkleTree};
    use jf_utils::hash_to_field;
    use rand::{CryptoRng, RngCore};

    pub(crate) fn check_distinct_input_nullifiers(
        nullifiers: &[Nullifier],
    ) -> Result<(), TxnApiError> {
        let mut seen = BTreeSet::new();
        if nullifiers.iter().all(|nf| seen.insert(*nf)) {
            Ok(())
        } else {
            Err(TxnApiError::InvalidParameter(
                "Repeated input nullifier".to_string(),
            ))
        }
    }

    pub(crate) mod mint {
        use super::*;
        use crate::{
            keys::UserKeyPair,
            proof::mint::MintProvingKey,
            structs::{AssetCode, AssetCodeDigest, AssetCodeSeed},
        };
        use jf_primitives::merkle_tree::AccMemberWitness;

        pub(crate) fn check_proving_key_consistency(
            proving_key: &MintProvingKey,
            acc_member_witness: &AccMemberWitness<BaseField>,
        ) -> Result<(), TxnApiError> {
            if acc_member_witness.merkle_path.nodes.len() != proving_key.tree_depth as usize {
                return Err(TxnApiError::InvalidParameter(
                    "The Merkle path lengths is inconsistent with with ProvingKey parameters"
                        .to_string(),
                ));
            }
            Ok(())
        }

        pub(crate) fn check_input_pub_key(
            ro_fee: &RecordOpening,
            issuer_keypair: &UserKeyPair,
        ) -> Result<(), TxnApiError> {
            if ro_fee.pub_key != issuer_keypair.pub_key() {
                return Err(TxnApiError::InvalidParameter(
                    "The key pair does not match the public key in the input record".to_string(),
                ));
            }
            Ok(())
        }

        pub(crate) fn check_mint_asset_code(
            ro_mint: &RecordOpening,
            ac_seed: AssetCodeSeed,
            ac_digest: AssetCodeDigest,
        ) -> Result<(), TxnApiError> {
            if ro_mint.asset_def.code != AssetCode::new_domestic_from_digest(ac_seed, ac_digest) {
                return Err(TxnApiError::InvalidParameter(
                    "Wrong asset code seed and digest".to_string(),
                ));
            }
            Ok(())
        }
    }

    pub(crate) mod transfer {
        use super::*;
        use crate::{proof::transfer::TransferProvingKey, structs::AssetDefinition};

        pub(crate) fn check_proving_key_consistency(
            proving_key: &TransferProvingKey,
            inputs: &[TransferNoteInput],
            output_len: usize,
        ) -> Result<(), TxnApiError> {
            if proving_key.n_inputs != inputs.len() {
                return Err(TxnApiError::InvalidParameter(
                    "The number of inputs is inconsistent with ProvingKey parameters.".to_string(),
                ));
            }

            if proving_key.n_outputs != output_len {
                return Err(TxnApiError::InvalidParameter(
                    "The number of outputs is inconsistent with ProvingKey parameters".to_string(),
                ));
            }

            let is_correct_depth = inputs.iter().all(|input| {
                input.acc_member_witness.merkle_path.nodes.len() == proving_key.tree_depth as usize
            });
            if !is_correct_depth {
                return Err(TxnApiError::InvalidParameter(
                    "The Merkle path lengths is inconsistent with with ProvingKey parameters"
                        .to_string(),
                ));
            }
            Ok(())
        }
        /// Check that inputs record opening and keypair matched.
        pub(crate) fn check_input_pub_keys(
            inputs: &[TransferNoteInput],
        ) -> Result<(), TxnApiError> {
            let is_pub_key_matched = inputs
                .iter()
                .filter(|input| !input.ro.asset_def.is_dummy())
                .all(|input| input.ro.pub_key == input.owner_keypair.pub_key());
            if !is_pub_key_matched {
                return Err(TxnApiError::InvalidParameter(String::from(
                    "The keypair provided does not match the public key in the input.",
                )));
            }
            Ok(())
        }

        /// Check the following:
        /// 1. the first record in inputs and outputs is of native asset def
        /// 2. the rest of records in inputs and outputs are of the same asset
        /// code (namely the transferred asset code)
        /// 3. when freezer_pk is non-dummy, the auditor_pk must be non-dummy,
        /// since freezing depends on auditor to retrieve record
        /// plaintext data
        pub(crate) fn check_asset_def(
            inputs: &[&RecordOpening],
            outputs: &[&RecordOpening],
        ) -> Result<(), TxnApiError> {
            assert!(
                !inputs.is_empty() && !outputs.is_empty(),
                "Must provide at least 1 input record and 1 output record"
            );
            let native_asset_definition = AssetDefinition::native();
            // first input must match native asset definition
            if inputs[0].asset_def != native_asset_definition {
                return Err(TxnApiError::InvalidParameter(
                    "The first input must be the native asset".to_string(),
                ));
            }
            if outputs[0].asset_def != native_asset_definition {
                return Err(TxnApiError::InvalidParameter(
                    "The first output must be the native asset".to_string(),
                ));
            }
            let mut xfr_asset_def = &native_asset_definition;
            for input in inputs[1..].iter() {
                if input.asset_def != AssetDefinition::dummy() {
                    xfr_asset_def = &input.asset_def;
                    break;
                }
            }

            let inconsistent_input_asset_def_flag = inputs.iter().skip(1).any(|input| {
                input.asset_def != AssetDefinition::dummy() && input.asset_def != *xfr_asset_def
            });
            if inconsistent_input_asset_def_flag {
                return Err(TxnApiError::InvalidParameter("The input records are not consistent with the asset definition of the records being transferred.".to_string()));
            }
            let inconsistent_output_asset_def_flag = outputs
                .iter()
                .skip(1)
                .any(|output| output.asset_def != *xfr_asset_def);
            if inconsistent_output_asset_def_flag {
                return Err(TxnApiError::InvalidParameter("The output records are not consistent with the asset definition of the records being transferred.".to_string()));
            }

            let non_null_freezer_null_auditor_flag =
                inputs.iter().chain(outputs.iter()).any(|ro| {
                    ro.asset_def.policy.freezer_pk != FreezerPubKey::default()
                        && ro.asset_def.policy.auditor_pk == AuditorPubKey::default()
                });
            if non_null_freezer_null_auditor_flag {
                return Err(TxnApiError::InvalidParameter(
                    "Freezing requires tracing enabled.".to_string(),
                ));
            }
            Ok(())
        }

        /// Check that the merkle roots in input asset records are consistent
        /// Returns the merkle root, or error if inconsistent merkle roots were
        /// found.
        pub(crate) fn check_and_get_roots(
            inputs: &[TransferNoteInput],
        ) -> Result<NodeValue, TxnApiError> {
            if inputs.is_empty() {
                return Err(TxnApiError::InternalError(
                    "Must provide at least 1 input".to_string(),
                ));
            }

            let assumed_root = inputs[0].acc_member_witness.root;
            if inputs
                .iter()
                .filter(|input| !input.ro.is_dummy())
                .any(|input| input.acc_member_witness.root != assumed_root)
            {
                return Err(TxnApiError::InvalidParameter(
                    "The root provided is inconsistent with the root of some of the inputs."
                        .to_string(),
                ));
            }

            Ok(assumed_root)
        }

        /// Check that input credentials are present and valid when tracing
        /// policy's cred_pk is non-empty
        pub(crate) fn check_creds(
            inputs: &[TransferNoteInput],
            valid_until: u64,
        ) -> Result<(), TxnApiError> {
            for input in inputs {
                if input.ro.asset_def.policy.cred_pk != CredIssuerPubKey::default() {
                    if let Some(cred) = &input.cred {
                        cred.verify(valid_until)?
                    } else {
                        return Err(TxnApiError::InvalidParameter(
                            "Missing credentials.".to_string(),
                        ));
                    }
                }
            }
            Ok(())
        }
    }

    pub(crate) mod freeze {
        use super::*;
        use crate::{freeze::FreezeNoteInput, proof::freeze::FreezeProvingKey, structs::FeeInput};

        pub(crate) fn check_freezing_policies_are_not_dummy(
            inputs: &[FreezeNoteInput],
        ) -> Result<(), TxnApiError> {
            for (i, input) in inputs.iter().enumerate() {
                if !input.ro.is_dummy()
                    && input.ro.asset_def.policy.freezer_pk == FreezerPubKey::default()
                {
                    return Err(TxnApiError::InvalidParameter(format!(
                        "The freezing policy of the {0}-th input is dummy.",
                        i
                    )));
                }
            }
            Ok(())
        }

        // `inputs` is guaranteed to be non-empty
        pub(crate) fn check_and_get_root(
            fee_input: &FeeInput,
            inputs: &[FreezeNoteInput],
        ) -> Result<NodeValue, TxnApiError> {
            let assumed_root = fee_input.acc_member_witness.root;
            if inputs
                .iter()
                .filter(|input| !input.ro.is_dummy())
                .any(|input| input.acc_member_witness.root != assumed_root)
            {
                return Err(TxnApiError::InvalidParameter(
                    "The root provided is inconsistent with the root of some of the inputs."
                        .to_string(),
                ));
            }
            Ok(assumed_root)
        }

        pub(crate) fn check_inputs_len(input_len: usize) -> Result<(), TxnApiError> {
            if input_len == 0 {
                return Err(TxnApiError::InvalidParameter(format!(
                    "freezing note should have at least 1 input beside fee input, but got: {0}",
                    input_len
                )));
            }
            Ok(())
        }
        pub(crate) fn check_proving_key_consistency(
            proving_key: &FreezeProvingKey,
            num_input: usize,
            tree_depth: u8,
        ) -> Result<(), TxnApiError> {
            if proving_key.num_input != num_input || proving_key.tree_depth != tree_depth {
                return Err(TxnApiError::InvalidParameter(
                    format!("FreezeProvingKey(num_input={0}, tree_depth={1}) does not match num_input={2}, tree_depth={3}", proving_key.num_input, proving_key.tree_depth, num_input, tree_depth) 
                ));
            }

            Ok(())
        }

        pub(crate) fn get_output_ros<R: RngCore + CryptoRng>(
            rng: &mut R,
            inputs: &[FreezeNoteInput],
        ) -> Vec<RecordOpening> {
            let mut output_ros = vec![];
            for input in inputs.iter() {
                let flipped_flag = input.ro.freeze_flag.flip();
                let mut flipped_ro = input.ro.clone();
                flipped_ro.freeze_flag = flipped_flag;
                flipped_ro.blind = BlindFactor::rand(rng);
                output_ros.push(flipped_ro);
            }
            output_ros
        }
    }

    pub(crate) fn check_fee(fee: &TxnFeeInfo) -> Result<(), TxnApiError> {
        if fee.fee_amount > fee.fee_input.ro.amount {
            return Err(TxnApiError::InvalidParameter(
                "Specified fee higher than fee record value".to_string(),
            ));
        }
        if fee.fee_input.ro.amount - fee.fee_amount != fee.fee_chg_ro.amount {
            return Err(TxnApiError::InvalidParameter(
                "Incorrect fee change value".to_string(),
            ));
        }
        if !fee.fee_input.ro.asset_def.is_native() {
            return Err(TxnApiError::InvalidParameter(
                "Fee record should be of native asset type".to_string(),
            ));
        }
        if !fee.fee_chg_ro.asset_def.is_native() {
            return Err(TxnApiError::InvalidParameter(
                "Fee change record should be of native asset type".to_string(),
            ));
        }
        if fee.fee_chg_ro.pub_key != fee.fee_input.ro.pub_key {
            return Err(TxnApiError::InvalidParameter(
                "Fee input and fee change records' public key do not match".to_string(),
            ));
        }
        // Check that the merkle path is valid w.r.t. ro, path and root.
        MerkleTree::check_proof(
            fee.fee_input.acc_member_witness.root,
            fee.fee_input.acc_member_witness.uid,
            &MerkleLeafProof {
                leaf: MerkleLeaf(
                    fee.fee_input
                        .ro
                        .derive_record_commitment()
                        .to_field_element(),
                ),
                path: fee.fee_input.acc_member_witness.merkle_path.clone(),
            },
        )
        .map_err(|e| {
            TxnApiError::InvalidParameter(format!(
                "Incorrect Merkle path on fee input; got a different merkle root: {:?}",
                e
            ))
        })
    }

    /// check the sum of inputs equals to sum of output and returns the fee if
    /// balance is preserved.
    pub(crate) fn check_balance(
        inputs: &[&RecordOpening],
        outputs: &[&RecordOpening],
    ) -> Result<Amount, TxnApiError> {
        let fee = derive_fee(inputs, outputs)?;
        check_asset_amount(inputs, outputs, fee)?;
        Ok(fee)
    }

    /// Compute fee amount from inputs and outputs;
    /// returns error if the computed amount is non-positive;
    /// `inputs` and `outputs` are guaranteed to be non-empty;
    fn derive_fee(
        inputs: &[&RecordOpening],
        outputs: &[&RecordOpening],
    ) -> Result<Amount, TxnApiError> {
        // if transfer asset code != native_asset_code, fee = inputs[0].amount -
        // outputs[0].amount, else fee = (\sum_{i=0...} inputs[i].amount) -
        // (\sum_{i=0...} outputs[i].amount)
        let mut is_native_xfr = true;
        for input in inputs {
            if !input.asset_def.is_native() && !input.asset_def.is_dummy() {
                is_native_xfr = false;
                break;
            }
        }

        let fee: i128 = if is_native_xfr {
            let inputs_sum: i128 = inputs.iter().map(|x| x.amount.0 as i128).sum();
            let outputs_sum: i128 = outputs.iter().map(|x| x.amount.0 as i128).sum();
            inputs_sum - outputs_sum
        } else {
            (inputs[0].amount.0 as i128) - (outputs[0].amount.0 as i128)
        };

        if fee < 0 {
            return Err(TxnApiError::InvalidParameter(String::from(
                "The fee is negative.",
            )));
        }
        Ok((fee as u128).into())
    }

    /// Check that all inputs and outputs are unfrozen
    pub(crate) fn check_unfrozen(
        inputs: &[&RecordOpening],
        outputs: &[&RecordOpening],
    ) -> Result<(), TxnApiError> {
        if inputs
            .iter()
            .chain(outputs.iter())
            .any(|oar| oar.freeze_flag == FreezeFlag::Frozen)
        {
            return Err(TxnApiError::InvalidParameter(
                "Input and output records must be unfrozen ones.".to_string(),
            ));
        }
        Ok(())
    }

    /// Check that for each asset code `total input amount == total output
    /// amount`
    fn check_asset_amount(
        inputs: &[&RecordOpening],
        outputs: &[&RecordOpening],
        fee: Amount,
    ) -> Result<(), TxnApiError> {
        let mut balances = HashMap::new();

        let native_ac = inputs[0].asset_def.code; // assume already checked first is native
        balances.insert(native_ac, -(fee.0 as i128));

        // add inputs
        for record in inputs.iter().filter(|input| !input.asset_def.is_dummy()) {
            if let Some(x) = balances.get_mut(&record.asset_def.code) {
                *x += record.amount.0 as i128;
            } else {
                balances.insert(record.asset_def.code, record.amount.0 as i128);
            }
        }

        // subtract outputs
        for record in outputs.iter() {
            if let Some(x) = balances.get_mut(&record.asset_def.code) {
                *x -= record.amount.0 as i128;
            } else {
                balances.insert(record.asset_def.code, -(record.amount.0 as i128));
            }
        }

        // check 0 balance
        for (&at, &sum) in balances.iter() {
            if sum != 0i128 {
                return Err(TxnApiError::InvalidParameter(format!(
                    "Unbalanced input and output amounts for asset code:{:?}",
                    at.0.to_string()
                )));
            }
        }
        Ok(())
    }

    /// Check that a) first input is not dummy, and b) dummy inputs records have
    /// zero amount value
    pub(crate) fn check_dummy_inputs(inputs: &[&RecordOpening]) -> Result<(), TxnApiError> {
        if inputs[0].is_dummy() {
            return Err(TxnApiError::InvalidParameter(
                "First input cannot be dummy".to_string(),
            ));
        }
        if inputs
            .iter()
            .skip(1)
            .any(|input| input.asset_def.is_dummy() && input.amount != Amount::from(0u32))
        {
            Err(TxnApiError::InvalidParameter(
                "Dummy inputs must have 0 amount".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    // Returns the hash digest of all serialized receiver memos
    pub(crate) fn get_receiver_memos_digest(
        receiver_memos: &[ReceiverMemo],
    ) -> Result<BaseField, TxnApiError> {
        if receiver_memos.is_empty() {
            return Err(TxnApiError::InternalError(
                "Internal error: receiver_memo list should NOT be empty!".to_string(),
            ));
        }
        let mut bytes = Vec::new();
        for memo in receiver_memos.iter() {
            let mut buf = Vec::new();
            memo.0.serialize(&mut buf)?;
            bytes = [bytes, buf].concat();
        }
        Ok(hash_to_field(bytes))
    }

    #[cfg(test)]
    mod tests {
        use crate::{
            keys::{AuditorPubKey, UserKeyPair},
            structs::{AssetDefinition, FreezeFlag, Nullifier, RecordOpening},
            utils::txn_helpers::{
                check_distinct_input_nullifiers, derive_fee, transfer::check_asset_def,
            },
        };
        use ark_std::test_rng;

        #[test]
        fn test_derive_fee() {
            let mut rng = ark_std::test_rng();

            let asset_def_native = AssetDefinition::native();
            let asset_def_non_native = AssetDefinition::rand_for_test(&mut rng);
            let user_keypair = UserKeyPair::generate(&mut rng);

            let ro_in_1 = RecordOpening::new(
                &mut rng,
                10u64.into(),
                asset_def_native.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_out_1 = RecordOpening::new(
                &mut rng,
                5u64.into(),
                asset_def_native.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let inputs = [&ro_in_1];
            let outputs = [&ro_out_1];
            assert_eq!(derive_fee(&inputs, &outputs).unwrap(), 5u64.into());

            // input amount is lower than output amount
            assert!(derive_fee(&outputs, &inputs).is_err());

            // Many records openings, all of which are native
            let ro_in_2 = RecordOpening::new(
                &mut rng,
                7u64.into(),
                asset_def_native.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_out_2 = RecordOpening::new(
                &mut rng,
                5u64.into(),
                asset_def_native.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_out_3 = RecordOpening::new(
                &mut rng,
                6u64.into(),
                asset_def_native.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let inputs = [&ro_in_1, &ro_in_2];
            let outputs = [&ro_out_1, &ro_out_2, &ro_out_3];
            assert_eq!(derive_fee(&inputs, &outputs).unwrap(), 1u64.into());

            // input amount is lower than output amount
            assert!(derive_fee(&outputs, &inputs).is_err());

            // Many records openings, some of which are non native
            let ro_in_non_native = RecordOpening::new(
                &mut rng,
                7u64.into(),
                asset_def_non_native.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_out_non_native = RecordOpening::new(
                &mut rng,
                7u64.into(),
                asset_def_non_native.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let inputs = [&ro_in_1, &ro_in_non_native];
            let outputs = [&ro_out_1, &ro_out_non_native];
            assert_eq!(derive_fee(&inputs, &outputs).unwrap(), 5u64.into());

            // input amount is lower than output amount
            assert!(derive_fee(&outputs, &inputs).is_err());
        }

        #[test]
        fn test_distinct_input_nullifier() {
            let rng = &mut test_rng();
            let nullifier1 = Nullifier::random_for_test(rng);
            let nullifier2 = Nullifier::random_for_test(rng);
            assert!(check_distinct_input_nullifiers(&[nullifier1]).is_ok());
            assert!(check_distinct_input_nullifiers(&[nullifier1, nullifier1]).is_err());
            assert!(check_distinct_input_nullifiers(&[nullifier1, nullifier2]).is_ok());
        }

        #[test]
        fn test_check_asset_def() {
            let mut rng = ark_std::test_rng();

            let asset_def_native = AssetDefinition::native();
            let asset_def_non_native_1 = AssetDefinition::rand_for_test(&mut rng);
            let asset_def_non_native_2 = AssetDefinition::rand_for_test(&mut rng);
            let mut asset_def_freezer_key_non_null_tracer_key_null = asset_def_non_native_2.clone();
            asset_def_freezer_key_non_null_tracer_key_null
                .policy
                .auditor_pk = AuditorPubKey::default();
            let user_keypair = UserKeyPair::generate(&mut rng);

            let ro_in_non_native = RecordOpening::new(
                &mut rng,
                10u64.into(),
                asset_def_non_native_1.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_in_native = RecordOpening::new(
                &mut rng,
                10u64.into(),
                asset_def_native.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_in_asset_1 = ro_in_non_native.clone();
            let ro_in_asset_2 = RecordOpening::new(
                &mut rng,
                10u64.into(),
                asset_def_non_native_2.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_in_non_native_bad_policy = RecordOpening::new(
                &mut rng,
                5u64.into(),
                asset_def_freezer_key_non_null_tracer_key_null.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_out_native = RecordOpening::new(
                &mut rng,
                5u64.into(),
                asset_def_native.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_out_non_native = RecordOpening::new(
                &mut rng,
                5u64.into(),
                asset_def_non_native_1.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_out_non_native_bad_policy = RecordOpening::new(
                &mut rng,
                5u64.into(),
                asset_def_freezer_key_non_null_tracer_key_null.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let ro_out_asset_1 = ro_out_non_native.clone();
            let ro_out_asset_2 = RecordOpening::new(
                &mut rng,
                5u64.into(),
                asset_def_non_native_2.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );

            let inputs = [&ro_in_native];
            let outputs = [&ro_out_native];
            assert!(check_asset_def(&inputs, &outputs).is_ok());

            let inputs = [&ro_in_non_native];
            let outputs = [&ro_out_native];
            assert!(check_asset_def(&inputs, &outputs).is_err());

            let inputs = [&ro_in_native];
            let outputs = [&ro_out_non_native];
            assert!(check_asset_def(&inputs, &outputs).is_err());

            let inputs = [&ro_in_native, &ro_in_asset_1, &ro_in_asset_1];
            let outputs = [&ro_out_native, &ro_out_asset_1, &ro_out_asset_1];
            assert!(check_asset_def(&inputs, &outputs).is_ok());

            let inputs = [&ro_in_native, &ro_in_asset_1, &ro_in_asset_2];
            let outputs = [&ro_out_native, &ro_out_asset_1, &ro_out_asset_1];
            assert!(check_asset_def(&inputs, &outputs).is_err());

            let inputs = [&ro_in_native, &ro_in_asset_1, &ro_in_asset_1];
            let outputs = [&ro_out_native, &ro_out_asset_1, &ro_out_asset_2];
            assert!(check_asset_def(&inputs, &outputs).is_err());

            let inputs = [&ro_in_native, &ro_in_asset_1, &ro_in_asset_1];
            let outputs = [&ro_out_native, &ro_out_asset_2, &ro_out_asset_2];
            assert!(check_asset_def(&inputs, &outputs).is_err());

            let inputs = [&ro_in_native, &ro_in_non_native_bad_policy];
            let outputs = [&ro_out_native, &ro_out_non_native_bad_policy];
            assert!(check_asset_def(&inputs, &outputs).is_err());
        }
    }
}
