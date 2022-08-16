// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Utilities used for tests and benchmarks.

#![allow(dead_code)]
use super::txn_helpers::freeze::get_output_ros;
use crate::{
    constants::{MAX_TIMESTAMP_LEN, VIEWABLE_DATA_LEN},
    errors::TxnApiError,
    freeze::{FreezeNote, FreezeNoteInput},
    keys::{
        CredIssuerKeyPair, CredIssuerPubKey, FreezerKeyPair, UserKeyPair, UserPubKey, ViewerKeyPair,
    },
    mint::MintNote,
    prelude::CapConfig,
    proof::{
        self, freeze,
        freeze::{FreezeProvingKey, FreezePublicInput, FreezeWitness},
        mint,
        mint::{MintProvingKey, MintPublicInput, MintWitness},
        transfer::{self, TransferProvingKey, TransferWitness},
    },
    sign_receiver_memos,
    structs::{
        Amount, AssetCode, AssetCodeDigest, AssetCodeSeed, AssetDefinition, AssetPolicy,
        ExpirableCredential, FeeInput, FreezeFlag, IdentityAttribute, NoteType, ReceiverMemo,
        RecordOpening, RevealMap, TxnFeeInfo,
    },
    transfer::{TransferNote, TransferNoteInput},
    utils::{compute_universal_param_size, next_power_of_three},
    TransactionNote, TransactionVerifyingKey,
};
use ark_std::{boxed::Box, rand::prelude::*, rc::Rc, vec, vec::Vec, UniformRand};
use jf_primitives::{
    merkle_tree::{AccMemberWitness, MerkleTree, NodeValue},
    signatures::schnorr,
};
use rayon::prelude::*;

#[derive(Debug, Clone)]
/// Parameters **for testing only**!
pub struct TxnsParams<C: CapConfig> {
    /// transaction notes generated
    pub txns: Vec<TransactionNote<C>>,
    /// verifying keys for transaction validity proofs
    pub verifying_keys: Vec<Rc<TransactionVerifyingKey<C>>>,
    /// these txns are valid until `valid_until`
    pub valid_until: u64,
    /// these txns are prove against this `merkle_root`
    pub merkle_root: NodeValue<C::ScalarField>,
}

impl<C: CapConfig> TxnsParams<C> {
    /// Randomly generate a list of transaction of different types
    pub fn generate_txns<R>(
        rng: &mut R,
        num_transfer_txn: usize,
        num_mint_txn: usize,
        num_freeze_txn: usize,
        tree_depth: u8,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let transfer_num_input = 2;
        let transfer_num_output = 3;
        let freeze_num_input = 3;

        let domain_size = compute_universal_param_size::<C>(
            NoteType::Transfer,
            transfer_num_input,
            transfer_num_output,
            tree_depth,
        )
        .unwrap();
        let srs = proof::universal_setup_for_staging::<_, C>(domain_size, rng).unwrap();
        let (transfer_prover_key, transfer_verifier_key, _) =
            transfer::preprocess(&srs, transfer_num_input, transfer_num_output, tree_depth)
                .unwrap();
        let (mint_prover_key, mint_verifier_key, _) = mint::preprocess(&srs, tree_depth).unwrap();
        let (freeze_prover_key, freeze_verifier_key, _) =
            freeze::preprocess(&srs, freeze_num_input, tree_depth).unwrap();

        let valid_until = 1000;
        let user_keypairs: Vec<UserKeyPair<C>> = (0..transfer_num_input)
            .into_iter()
            .map(|_| UserKeyPair::generate(rng))
            .collect();
        let mut transfer_builders: Vec<_> = (0..num_transfer_txn)
            .into_par_iter()
            .map(|_| {
                let rng = &mut ark_std::test_rng();
                let user_keypairs_slice = user_keypairs.iter().collect();
                TransferParamsBuilder::rand(
                    rng,
                    transfer_num_input,
                    transfer_num_output,
                    Some(tree_depth),
                    user_keypairs_slice,
                    valid_until,
                )
            })
            .collect();

        let mut minter_keypairs = vec![];
        let mut recv_keypairs = vec![];
        let mut viewer_keypairs = vec![];
        (0..num_mint_txn).for_each(|_| {
            minter_keypairs.push(UserKeyPair::generate(rng));
            recv_keypairs.push(UserKeyPair::generate(rng));
            viewer_keypairs.push(ViewerKeyPair::generate(rng));
        });
        let mut mint_builders: Vec<_> = (0..num_mint_txn)
            .into_par_iter()
            .map(|i| {
                let rng = &mut ark_std::test_rng();
                MintParamsBuilder::rand(
                    rng,
                    tree_depth,
                    &minter_keypairs[i],
                    &recv_keypairs[i],
                    &viewer_keypairs[i],
                )
            })
            .collect();

        let mut fee_keypairs = vec![];
        let mut freezing_keypairs: Vec<Vec<FreezerKeyPair<C>>> = vec![];
        (0..num_freeze_txn).for_each(|_| {
            fee_keypairs.push(UserKeyPair::generate(rng));
            let freezers = (0..freeze_num_input - 1)
                .map(|_| FreezerKeyPair::generate(rng))
                .collect();
            freezing_keypairs.push(freezers);
        });
        let mut freeze_builders: Vec<_> = (0..num_freeze_txn)
            .into_par_iter()
            .map(|i| {
                let rng = &mut ark_std::test_rng();
                let freezing_keypairs = freezing_keypairs[i].iter().collect();
                FreezeParamsBuilder::rand(rng, tree_depth, &fee_keypairs[i], freezing_keypairs)
            })
            .collect();

        let mut mt = MerkleTree::new(tree_depth).unwrap();
        for builder in transfer_builders.iter() {
            for ro in builder.input_ros.iter() {
                mt.push(ro.derive_record_commitment().to_field_element());
            }
        }
        for builder in mint_builders.iter() {
            mt.push(builder.fee_ro.derive_record_commitment().to_field_element());
        }
        for builder in freeze_builders.iter() {
            for ro in builder.input_ros().iter() {
                mt.push(ro.derive_record_commitment().to_field_element());
            }
            mt.push(
                builder
                    .fee_ro()
                    .derive_record_commitment()
                    .to_field_element(),
            );
        }
        let mut offset: u64 = 0;
        for builder in transfer_builders.iter_mut() {
            let uids = (offset..offset + builder.input_ros.len() as u64).collect();
            builder.update_acc_member_witness(&mt, Some(uids));
            offset += builder.input_ros.len() as u64;
        }
        for builder in mint_builders.iter_mut() {
            let uid = offset;
            builder.update_acc_member_witness(&mt, Some(uid));
            offset += 1;
        }
        for builder in freeze_builders.iter_mut() {
            let uids = (offset..offset + builder.input_ros().len() as u64).collect();
            builder.update_acc_member_witness(
                &mt,
                Some(uids),
                Some(offset + builder.input_ros().len() as u64),
            );
            offset += builder.input_ros().len() as u64 + 1;
        }

        let transfer_txns: Vec<TransactionNote<C>> = transfer_builders
            .into_par_iter()
            .map(|builder| {
                let rng = &mut ark_std::test_rng();
                let mut extra_proof_bound_data = [0u8; 32];
                rng.fill_bytes(&mut extra_proof_bound_data);
                let (note, ..) = builder
                    .build_transfer_note(
                        rng,
                        &transfer_prover_key,
                        valid_until,
                        extra_proof_bound_data.to_vec(),
                    )
                    .unwrap();
                TransactionNote::Transfer(Box::new(note))
            })
            .collect();
        let mint_txns: Vec<_> = mint_builders
            .into_par_iter()
            .map(|builder| {
                let rng = &mut ark_std::test_rng();
                let (note, ..) = builder.build_mint_note(rng, &mint_prover_key).unwrap();
                TransactionNote::Mint(Box::new(note))
            })
            .collect();
        let freeze_txns: Vec<_> = freeze_builders
            .into_par_iter()
            .map(|builder| {
                let rng = &mut ark_std::test_rng();
                let (note, ..) = builder.build_freeze_note(rng, &freeze_prover_key).unwrap();
                TransactionNote::Freeze(Box::new(note))
            })
            .collect();
        let txns = [transfer_txns, mint_txns, freeze_txns].concat();

        let verifying_keys = vec![
            Rc::new(TransactionVerifyingKey::Transfer(transfer_verifier_key)),
            Rc::new(TransactionVerifyingKey::Mint(mint_verifier_key)),
            Rc::new(TransactionVerifyingKey::Freeze(freeze_verifier_key)),
        ];

        Self {
            txns,
            verifying_keys,
            valid_until,
            merkle_root: mt.commitment().root_value,
        }
    }

    pub(crate) fn get_verifying_keys(&self) -> Vec<Rc<TransactionVerifyingKey<C>>> {
        let mut keys = vec![];
        for txn in &self.txns {
            match txn {
                TransactionNote::Transfer(_) => keys.push(self.verifying_keys[0].clone()),
                TransactionNote::Mint(_) => keys.push(self.verifying_keys[1].clone()),
                TransactionNote::Freeze(_) => keys.push(self.verifying_keys[2].clone()),
            }
        }
        keys
    }

    pub(crate) fn get_merkle_roots(&self) -> Vec<NodeValue<C::ScalarField>> {
        vec![self.merkle_root; self.txns.len()]
    }

    pub(crate) fn update_recv_memos_ver_key(
        mut self,
        idx: usize,
        recv_memos_ver_key: schnorr::VerKey<C::EmbeddedCurveParam>,
    ) -> Self {
        assert!(idx < self.txns.len());
        match &mut self.txns[idx] {
            TransactionNote::Transfer(note) => {
                note.aux_info.txn_memo_ver_key = recv_memos_ver_key;
            },
            TransactionNote::Mint(note) => {
                note.aux_info.txn_memo_ver_key = recv_memos_ver_key;
            },
            TransactionNote::Freeze(note) => {
                note.aux_info.txn_memo_ver_key = recv_memos_ver_key;
            },
        };
        self
    }
}
pub(crate) enum PolicyRevealAttr {
    UserAddr,
    Amount,
    BlindFactor,
    IdAttr(usize),
    AllIdAttr,
}

/// Struct that allows to build Transfer notes parameters
pub struct TransferParamsBuilder<'a, C: CapConfig> {
    num_input: usize,
    num_output: usize,
    tree_depth: u8,
    pub(crate) transfer_asset_def: Option<NonNativeAssetDefinition<C>>,
    /// Input records
    pub input_ros: Vec<RecordOpening<C>>,
    /// Output records
    pub output_ros: Vec<RecordOpening<C>>,
    /// fee change record
    pub fee_chg_ro: RecordOpening<C>,
    /// List of input key pairs
    pub input_keypairs: Vec<&'a UserKeyPair<C>>,
    /// List of credentials
    pub input_creds: Vec<Option<ExpirableCredential<C>>>,
    pub(crate) input_acc_member_witnesses: Vec<AccMemberWitness<C::ScalarField>>,
    /// Root of the Merkle tree
    pub root: NodeValue<C::ScalarField>,
    rng: StdRng,
}

impl<'a, C: CapConfig> TransferParamsBuilder<'a, C> {
    pub(crate) fn new_native(
        num_input: usize,
        num_output: usize,
        tree_depth: Option<u8>,
        user_keypairs: Vec<&'a UserKeyPair<C>>,
    ) -> Self {
        assert_eq!(user_keypairs.len(), num_input);
        let tree_depth = Self::calculate_tree_depth(num_input, num_output, tree_depth);
        Self {
            num_input,
            num_output,
            tree_depth,
            transfer_asset_def: None,
            input_ros: vec![],
            output_ros: vec![],
            fee_chg_ro: RecordOpening::default(),
            input_keypairs: user_keypairs,
            input_creds: vec![None; num_input],
            input_acc_member_witnesses: vec![AccMemberWitness::default(); num_input],
            root: NodeValue::default(),
            rng: ark_std::test_rng(),
        }
    }

    /// Create  non native Transfer note parameters
    /// * `num_input` - number of inputs
    /// * `num_output` - number of outputs
    /// * `tree_depth` - depth of the tree
    /// * `user_keypairs` - list of sender key pairs
    pub fn new_non_native(
        num_input: usize,
        num_output: usize,
        tree_depth: Option<u8>,
        user_keypairs: Vec<&'a UserKeyPair<C>>,
    ) -> Self {
        assert_eq!(user_keypairs.len(), num_input);
        let tree_depth = Self::calculate_tree_depth(num_input, num_output, tree_depth);
        let mut rng = ark_std::test_rng();
        let transfer_asset_def = NonNativeAssetDefinition::generate(&mut rng);

        Self {
            num_input,
            num_output,
            tree_depth,
            transfer_asset_def: Some(transfer_asset_def),
            input_ros: vec![],
            output_ros: vec![],
            fee_chg_ro: RecordOpening::default(),
            input_keypairs: user_keypairs,
            input_creds: vec![None; num_input],
            input_acc_member_witnesses: vec![AccMemberWitness::default(); num_input],
            root: NodeValue::default(),
            rng,
        }
    }

    pub(crate) fn policy_reveal(mut self, reveal_type: PolicyRevealAttr) -> Self {
        assert!(
            self.transfer_asset_def.is_some(),
            "reveal map cannot be set on native asset"
        );
        // change transfer_asset_definition
        let mut asset_def = self.transfer_asset_def.unwrap();
        match reveal_type {
            PolicyRevealAttr::UserAddr => {
                asset_def.asset_def.policy.reveal_map.reveal_user_address();
            },
            PolicyRevealAttr::Amount => {
                asset_def.asset_def.policy.reveal_map.reveal_amount();
            },
            PolicyRevealAttr::BlindFactor => {
                asset_def
                    .asset_def
                    .policy
                    .reveal_map
                    .reveal_blinding_factor();
            },
            PolicyRevealAttr::IdAttr(i) => {
                asset_def
                    .asset_def
                    .policy
                    .reveal_map
                    .reveal_ith_id_attribute(i)
                    .unwrap();
            },
            PolicyRevealAttr::AllIdAttr => {
                asset_def
                    .asset_def
                    .policy
                    .reveal_map
                    .reveal_all_id_attributes();
            },
        }
        self.transfer_asset_def = Some(asset_def);
        // if inputs are set, assign reveal map to policy
        self.input_ros
            .iter_mut()
            .skip(1)// first one is used for fee
            .chain(self.output_ros.iter_mut())
            .for_each(|ro| match reveal_type {
                PolicyRevealAttr::UserAddr => {
                    ro.asset_def.policy =
                        ro.asset_def.policy.clone().reveal_user_address().unwrap();
                },
                PolicyRevealAttr::Amount => {
                    ro.asset_def.policy = ro.asset_def.policy.clone().reveal_amount().unwrap();
                },
                PolicyRevealAttr::BlindFactor => {
                    ro.asset_def.policy = ro
                        .asset_def
                        .policy
                        .clone()
                        .reveal_blinding_factor()
                        .unwrap();
                },
                PolicyRevealAttr::IdAttr(i) => {
                    ro.asset_def.policy =
                        ro.asset_def.policy.clone().reveal_ith_attribute(i).unwrap();
                },
                PolicyRevealAttr::AllIdAttr => {
                    ro.asset_def.policy =
                        ro.asset_def.policy.clone().reveal_all_attributes().unwrap();
                },
            });
        self.refresh_merkle_root()
    }

    pub(crate) fn set_reveal_threshold(mut self, reveal_threshold: Amount) -> Self {
        assert!(
            self.transfer_asset_def.is_some(),
            "reveal_threshold cannot be set on native asset"
        );
        // change transfer_asset_definition
        let mut asset_def = self.transfer_asset_def.unwrap();
        asset_def.asset_def.policy.reveal_threshold = reveal_threshold;
        self.transfer_asset_def = Some(asset_def);
        // if inputs are set, assign reveal map to policy
        self.input_ros
            .iter_mut()
            .skip(1)// first one reserved for fee
            .for_each(|ro| ro.asset_def.policy.reveal_threshold = reveal_threshold);
        self.output_ros
            .iter_mut()
            .for_each(|ro| ro.asset_def.policy.reveal_threshold = reveal_threshold);
        self.refresh_merkle_root()
    }

    pub(crate) fn set_policy_reveal_map(mut self, reveal_map: RevealMap) -> Self {
        assert!(
            self.transfer_asset_def.is_some(),
            "reveal map cannot be set on native asset"
        );
        // change transfer_asset_definition
        let mut asset_def = self.transfer_asset_def.unwrap();
        asset_def.asset_def.policy.reveal_map = reveal_map;
        self.transfer_asset_def = Some(asset_def);
        // if inputs are set, assign reveal map to policy
        self.input_ros
            .iter_mut()
            .skip(1)// first one reserved for fee
            .for_each(|ro| ro.asset_def.policy.reveal_map = reveal_map);
        self.output_ros
            .iter_mut()
            .for_each(|ro| ro.asset_def.policy.reveal_map = reveal_map);
        self.refresh_merkle_root()
    }

    /// Define the input amounts of a Transfer note
    /// * `fee_input` amount of record used to pay fees, in case of native
    ///   transfers, this amount can also be transferred, and fee is taken from
    ///   overall left over amount
    /// * `amounts` - list of input amounts (the first amount corresponds to the
    ///   native asset)
    pub fn set_input_amounts(mut self, fee_input: Amount, amounts: &[Amount]) -> Self {
        assert!(self.input_ros.is_empty(), "Input records already set");
        assert_eq!(
            amounts.len() + 1,
            self.num_input,
            "mismatched number of input amounts"
        );
        let input_user_pk = self.input_upk_at(0);
        let fee_ro = RecordOpening::new(
            &mut self.rng,
            fee_input,
            AssetDefinition::native(),
            input_user_pk,
            FreezeFlag::Unfrozen,
        );
        self.input_ros.push(fee_ro);

        for (i, amount) in amounts.iter().enumerate() {
            let input_user_pk = self.input_upk_at(i + 1);
            let ro = match self.transfer_asset_def.as_ref() {
                Some(non_native_asset) => RecordOpening::new(
                    &mut self.rng,
                    *amount,
                    non_native_asset.asset_def.clone(),
                    input_user_pk,
                    FreezeFlag::Unfrozen,
                ),
                None => RecordOpening::new(
                    &mut self.rng,
                    *amount,
                    AssetDefinition::native(),
                    input_user_pk,
                    FreezeFlag::Unfrozen,
                ),
            };
            self.input_ros.push(ro);
        }
        self.refresh_merkle_root()
    }

    /// Define the outputs amounts of a Transfer note
    /// * `amounts` - list of input amounts (the first amount corresponds to the
    ///   native asset)
    pub fn set_output_amounts(mut self, fee_chg: Amount, amounts: &[Amount]) -> Self {
        assert!(self.output_ros.is_empty(), "Output records already set");
        assert_eq!(
            amounts.len() + 1,
            self.num_output,
            "mismatched number of output amounts"
        );
        let output_user_pk = self.input_upk_at(0);
        let fee_change_ro = RecordOpening::new(
            &mut self.rng,
            fee_chg,
            AssetDefinition::native(),
            output_user_pk,
            FreezeFlag::Unfrozen,
        );
        self.fee_chg_ro = fee_change_ro;

        for amount in amounts.iter() {
            let output_user_pk = UserKeyPair::generate(&mut self.rng).pub_key();
            let ro = match self.transfer_asset_def.as_ref() {
                Some(non_native_asset) => RecordOpening::new(
                    &mut self.rng,
                    *amount,
                    non_native_asset.asset_def.clone(),
                    output_user_pk,
                    FreezeFlag::Unfrozen,
                ),
                None => RecordOpening::new(
                    &mut self.rng,
                    *amount,
                    AssetDefinition::native(),
                    output_user_pk,
                    FreezeFlag::Unfrozen,
                ),
            };
            self.output_ros.push(ro);
        }
        self
    }

    /// Set the input credentials
    /// * `cred_expiry` - expiration timestamp the of the credentials
    pub fn set_input_creds(mut self, cred_expiry: u64) -> Self {
        for i in 0..self.num_input {
            let cred = if self.input_ros[i].asset_def.policy.cred_pk == CredIssuerPubKey::default()
            {
                None
            } else {
                let transfer_asset_def = self.transfer_asset_def.as_ref().unwrap();
                Some(
                    ExpirableCredential::create(
                        self.input_upk_at(i).address,
                        IdentityAttribute::random_vector(&mut self.rng),
                        cred_expiry,
                        &transfer_asset_def.minter_keypair,
                    )
                    .unwrap(),
                )
            };
            self.input_creds[i] = cred;
        }
        self
    }

    fn refresh_merkle_root(mut self) -> Self {
        let mut mt = MerkleTree::new(self.tree_depth).unwrap();
        for ro in self.input_ros.iter() {
            mt.push(ro.derive_record_commitment().to_field_element());
        }
        self.update_acc_member_witness(&mt, None);
        self
    }

    /// if `uid` is None, then it's by default assumed to be the first few
    /// leaves in the merkle tree.
    pub(crate) fn update_acc_member_witness(
        &mut self,
        mt: &MerkleTree<C::ScalarField>,
        uids: Option<Vec<u64>>,
    ) {
        let uids = if let Some(uids) = uids {
            assert_eq!(
                uids.len(),
                self.input_ros.len(),
                "wrong number of uid provided"
            );
            uids
        } else {
            (0..self.input_ros.len() as u64).collect()
        };
        // update acc_member_witness of all input records
        for (idx, &uid) in uids.iter().enumerate() {
            self.input_acc_member_witnesses[idx] = AccMemberWitness::lookup_from_tree(mt, uid)
                .expect_ok()
                .unwrap()
                .1; // safe unwrap()
        }

        self.root = mt.commitment().root_value;
    }

    pub(crate) fn update_input_freeze_flag(
        mut self,
        index: usize,
        freeze_flag: FreezeFlag,
    ) -> Self {
        assert!(index < self.input_ros.len());
        self.input_ros[index].freeze_flag = freeze_flag;
        self.refresh_merkle_root()
    }

    pub(crate) fn update_fee_input_asset_def(mut self, asset_def: AssetDefinition<C>) -> Self {
        self.input_ros[0].asset_def = asset_def;
        self.refresh_merkle_root()
    }

    pub(crate) fn update_input_asset_def(
        mut self,
        index: usize,
        asset_def: AssetDefinition<C>,
    ) -> Self {
        assert!(index < self.input_ros.len());
        self.input_ros[index + 1].asset_def = asset_def; // first position is reserved for input fee
        self.refresh_merkle_root()
    }

    pub(crate) fn set_dummy_input_record(mut self, index: usize) -> Self {
        assert!(index < self.input_ros.len());
        self.input_ros[index + 1].asset_def = AssetDefinition::dummy(); // first position is reserved for input fee
        self.input_ros[index + 1].amount = Amount::from(0u64);
        // self.input_ros[index + 1].pub_key.address = Default::default();
        self.refresh_merkle_root()
    }

    pub(crate) fn update_fee_chg_asset_def(mut self, asset_def: AssetDefinition<C>) -> Self {
        self.fee_chg_ro.asset_def = asset_def;
        self
    }

    pub(crate) fn update_output_asset_def(
        mut self,
        index: usize,
        asset_def: AssetDefinition<C>,
    ) -> Self {
        assert!(index < self.output_ros.len());
        self.output_ros[index].asset_def = asset_def;
        self
    }

    pub(crate) fn update_fee_input_amount(mut self, amount: Amount) -> Self {
        self.input_ros[0].amount = amount;
        self.refresh_merkle_root()
    }

    pub(crate) fn update_input_amount(mut self, index: usize, amount: Amount) -> Self {
        assert!(index < self.input_ros.len());
        self.input_ros[index + 1].amount = amount;
        self.refresh_merkle_root()
    }

    /// randomly generate/prepare a parameter builder with 20% chance
    /// transferring native asset type.
    pub(crate) fn rand<R>(
        rng: &mut R,
        num_input: usize,
        num_output: usize,
        tree_depth: Option<u8>,
        user_keypairs: Vec<&'a UserKeyPair<C>>,
        valid_until: u64,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        // question(ZZ): is this gen_range supposed to be inclusive?
        // if so we should use `rng.gen_range(valid_until + 1..=2000)`
        let cred_expiry = rng.gen_range(valid_until + 1..2000);
        // guarantee: fee change < fee, the rest reserve balances
        let (fee_input, input_amounts, fee_chg, output_amounts) = {
            let fee = Amount::from(rng.gen_range(1..20) as u64);
            let fee_change = Amount::from(rng.gen_range(1..=fee.0));
            let transfer_amount = Amount::from(
                rng.gen_range(1..50) * (num_input as u128 - 1) * (num_output as u128 - 1) as u128,
            );
            let input_amounts = vec![transfer_amount / (num_input as u128 - 1); num_input - 1];
            let output_amounts = vec![transfer_amount / (num_output as u128 - 1); num_output - 1];
            (fee, input_amounts, fee_change, output_amounts)
        };

        let builder = if rng.gen_bool(0.2) {
            Self::new_native(num_input, num_output, tree_depth, user_keypairs)
        } else {
            Self::new_non_native(num_input, num_output, tree_depth, user_keypairs)
        }
        .set_input_amounts(fee_input, &input_amounts)
        .set_output_amounts(fee_chg, &output_amounts)
        .set_input_creds(cred_expiry);

        builder
    }

    fn len_check(&self) {
        assert!(
            self.input_ros.len() == self.num_input
                && self.input_acc_member_witnesses.len() == self.num_input
                && self.input_keypairs.len() == self.num_input
                && self.input_creds.len() == self.num_input,
            "Internal error, forget to initialize/update input RO/MemberWitness/KeyPair/Cred"
        );
    }

    pub(crate) fn build_witness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> TransferWitness<C> {
        self.len_check();
        let mut inputs = vec![];
        for i in 0..self.num_input {
            inputs.push(TransferNoteInput {
                ro: self.input_ros[i].clone(),
                acc_member_witness: self.input_acc_member_witnesses[i].clone(),
                owner_keypair: self.input_keypairs[i],
                cred: self.input_creds[i].clone(),
            });
        }

        let mut output_ros = vec![self.fee_chg_ro.clone()];
        output_ros.extend_from_slice(&self.output_ros);
        TransferWitness::new_unchecked(rng, inputs, &output_ros).unwrap()
    }

    /// Build a transfer note
    #[allow(clippy::type_complexity)]
    pub fn build_transfer_note<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        proving_key: &TransferProvingKey<C>,
        valid_until: u64,
        extra_proof_bound_data: Vec<u8>,
    ) -> Result<
        (
            TransferNote<C>,
            Vec<ReceiverMemo>,
            schnorr::Signature<C::EmbeddedCurveParam>,
        ),
        TxnApiError,
    > {
        if self.transfer_asset_def.is_none() {
            self.build_transfer_note_native(rng, proving_key)
        } else {
            self.build_transfer_note_non_native(
                rng,
                proving_key,
                valid_until,
                extra_proof_bound_data,
            )
        }
    }

    #[allow(clippy::type_complexity)]
    fn build_transfer_note_native<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        proving_key: &TransferProvingKey<C>,
    ) -> Result<
        (
            TransferNote<C>,
            Vec<ReceiverMemo>,
            schnorr::Signature<C::EmbeddedCurveParam>,
        ),
        TxnApiError,
    > {
        self.len_check();
        let mut inputs = vec![];
        for i in 0..self.num_input {
            inputs.push(TransferNoteInput {
                ro: self.input_ros[i].clone(),
                acc_member_witness: self.input_acc_member_witnesses[i].clone(),
                owner_keypair: self.input_keypairs[i],
                cred: None,
            });
        }
        // a never expired target
        let valid_until = 2u64.pow(MAX_TIMESTAMP_LEN as u32) - 1;
        let (note, sig_keypair, _) = TransferNote::generate_native(
            rng,
            inputs,
            &self.output_ros,
            self.input_ros[0].amount - self.fee_chg_ro.amount,
            valid_until,
            proving_key,
        )?;
        let recv_memos_res: Result<Vec<_>, _> = self
            .output_ros
            .iter()
            .map(|ro| ReceiverMemo::from_ro(rng, ro, &[]))
            .collect();
        let recv_memos = recv_memos_res?;
        let sig = sign_receiver_memos::<C>(&sig_keypair, &recv_memos)?;
        Ok((note, recv_memos, sig))
    }

    #[allow(clippy::type_complexity)]
    fn build_transfer_note_non_native<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        proving_key: &TransferProvingKey<C>,
        valid_until: u64,
        extra_proof_bound_data: Vec<u8>,
    ) -> Result<
        (
            TransferNote<C>,
            Vec<ReceiverMemo>,
            schnorr::Signature<C::EmbeddedCurveParam>,
        ),
        TxnApiError,
    > {
        self.len_check();
        let fee_input = FeeInput {
            ro: self.input_ros[0].clone(),
            acc_member_witness: self.input_acc_member_witnesses[0].clone(),
            owner_keypair: self.input_keypairs[0],
        };
        let fee_amount = fee_input.ro.amount - self.fee_chg_ro.amount;
        let fee = TxnFeeInfo {
            fee_input,
            fee_amount,
            fee_chg_ro: self.fee_chg_ro.clone(),
        };
        let mut inputs = vec![];
        for i in 1..self.num_input {
            inputs.push(TransferNoteInput {
                ro: self.input_ros[i].clone(),
                acc_member_witness: self.input_acc_member_witnesses[i].clone(),
                owner_keypair: self.input_keypairs[i],
                cred: self.input_creds[i].clone(),
            });
        }

        let (note, sig_keypair) = TransferNote::generate_non_native(
            rng,
            inputs,
            &self.output_ros,
            fee,
            valid_until,
            proving_key,
            extra_proof_bound_data,
        )?;
        let recv_memos_res: Result<Vec<_>, _> = self
            .output_ros
            .iter()
            .map(|ro| ReceiverMemo::from_ro(rng, ro, &[]))
            .collect();
        let recv_memos = recv_memos_res?;
        let sig = sign_receiver_memos::<C>(&sig_keypair, &recv_memos)?;
        Ok((note, recv_memos, sig))
    }
}

// private functions
impl<'a, C: CapConfig> TransferParamsBuilder<'a, C> {
    fn calculate_tree_depth(num_input: usize, num_output: usize, tree_depth: Option<u8>) -> u8 {
        assert_ne!(num_input, 0, "Require at least 1 input");
        assert_ne!(num_output, 0, "Require at least 1 output");
        match tree_depth {
            Some(depth) => {
                assert!(
                    3usize.pow(depth as u32) >= num_input + num_output,
                    "tree depth is not enough!"
                );
                depth
            },
            None => next_power_of_three(num_input + num_output) as u8,
        }
    }

    fn input_upk_at(&self, index: usize) -> UserPubKey<C> {
        assert!(index < self.input_keypairs.len());
        self.input_keypairs[index].pub_key()
    }
}

#[derive(Debug)]
pub(crate) struct NonNativeAssetDefinition<C: CapConfig> {
    pub(crate) asset_def: AssetDefinition<C>,
    pub(crate) viewer_keypair: ViewerKeyPair<C>,
    pub(crate) minter_keypair: CredIssuerKeyPair<C>,
    pub(crate) freezer_keypair: FreezerKeyPair<C>,
}

impl<C: CapConfig> NonNativeAssetDefinition<C> {
    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let viewer_keypair = ViewerKeyPair::generate(rng);
        let minter_keypair = CredIssuerKeyPair::generate(rng);
        let freezer_keypair = FreezerKeyPair::generate(rng);
        let (code, _seed) = AssetCode::random(rng);
        let policy = AssetPolicy::default()
            .set_viewer_pub_key(viewer_keypair.pub_key())
            .set_cred_creator_pub_key(minter_keypair.pub_key())
            .set_freezer_pub_key(freezer_keypair.pub_key());
        let asset_def = AssetDefinition::new(code, policy).unwrap();
        Self {
            asset_def,
            viewer_keypair,
            minter_keypair,
            freezer_keypair,
        }
    }
}

#[derive(Debug, Clone)]
/// Struct containing the parameters needed to build a Mint note
pub struct MintParamsBuilder<'a, C: CapConfig> {
    tree_depth: u8,
    pub(crate) minter_keypair: &'a UserKeyPair<C>,
    pub(crate) fee_ro: RecordOpening<C>,
    pub(crate) fee: Amount,
    pub(crate) mint_ro: RecordOpening<C>,
    pub(crate) ac_seed: AssetCodeSeed<C>,
    pub(crate) ac_description: Vec<u8>,
    pub(crate) asset_def: AssetDefinition<C>,
    pub(crate) viewer_keypair: &'a ViewerKeyPair<C>,
    pub(crate) receiver_keypair: &'a UserKeyPair<C>,
    pub(crate) acc_member_witness: AccMemberWitness<C::ScalarField>,
}

impl<'a, C: CapConfig> MintParamsBuilder<'a, C> {
    /// Generate the parameters for a Mint note
    #[allow(clippy::too_many_arguments)]
    pub fn new<R>(
        rng: &mut R,
        tree_depth: u8,
        input_amount: Amount,
        fee: Amount,
        mint_amount: Amount,
        minter_keypair: &'a UserKeyPair<C>,
        receiver_keypair: &'a UserKeyPair<C>,
        viewer_keypair: &'a ViewerKeyPair<C>,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let fee_ro = RecordOpening::new(
            rng,
            input_amount,
            AssetDefinition::native(),
            minter_keypair.pub_key(),
            FreezeFlag::Unfrozen,
        );

        let ac_seed = AssetCodeSeed::generate(rng);
        let ac_description = b"arbitrary description".to_vec();
        let mint_ac = AssetCode::new_domestic(ac_seed, &ac_description);
        // always use default policy and optionally use `self.policy_reveal()` to
        // selectively reveal
        let mint_policy = AssetPolicy::default();
        let mut mint_asset_def = AssetDefinition::new(mint_ac, mint_policy).unwrap();

        mint_asset_def.policy = mint_asset_def
            .policy
            .set_viewer_pub_key(viewer_keypair.pub_key());

        let mint_ro = RecordOpening::new(
            rng,
            mint_amount,
            mint_asset_def.clone(),
            receiver_keypair.pub_key(),
            FreezeFlag::Unfrozen,
        );

        let mut builder = Self {
            tree_depth,
            minter_keypair,
            fee_ro,
            fee,
            mint_ro,
            ac_seed,
            asset_def: mint_asset_def,
            ac_description,
            receiver_keypair,
            viewer_keypair,
            acc_member_witness: AccMemberWitness::default(),
        };
        builder.refresh_merkle_root();
        builder
    }

    fn refresh_merkle_root(&mut self) {
        let mut mt = MerkleTree::new(self.tree_depth).unwrap();
        mt.push(self.fee_ro.derive_record_commitment().to_field_element());
        self.acc_member_witness = AccMemberWitness::lookup_from_tree(&mt, 0)
            .expect_ok()
            .unwrap()
            .1; // safe unwrap()
    }

    fn update_acc_member_witness(&mut self, mt: &MerkleTree<C::ScalarField>, uid: Option<u64>) {
        let uid = if let Some(uid) = uid { uid } else { 0 };
        self.acc_member_witness = AccMemberWitness::lookup_from_tree(mt, uid)
            .expect_ok()
            .unwrap()
            .1; // safe unwrap()
    }

    pub(crate) fn build_witness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> MintWitness<C> {
        let ac_digest = AssetCodeDigest::from_description(&self.ac_description);
        // avoid integer overflow crash on debug mode, and we don't want to return error
        let fee_chg = if self.fee_ro.amount >= self.fee {
            self.fee_ro.amount - self.fee
        } else {
            Amount::from(u128::MAX) // to cause error later on
        };
        let chg_ro = RecordOpening::new(
            rng,
            fee_chg,
            self.fee_ro.asset_def.clone(),
            self.fee_ro.pub_key.clone(),
            FreezeFlag::Unfrozen,
        );
        MintWitness {
            minter_keypair: self.minter_keypair,
            acc_member_witness: self.acc_member_witness.clone(),
            fee_ro: self.fee_ro.clone(),
            mint_ro: self.mint_ro.clone(),
            chg_ro,
            ac_seed: self.ac_seed,
            ac_digest,
            viewing_memo_enc_rand: C::EmbeddedCurveScalarField::rand(rng),
        }
    }

    pub(crate) fn policy_reveal(mut self, reveal_type: PolicyRevealAttr) -> Self {
        // change transfer_asset_definition
        let mut asset_def = self.asset_def.clone();
        match reveal_type {
            PolicyRevealAttr::UserAddr => {
                asset_def.policy.reveal_map.reveal_user_address();
            },
            PolicyRevealAttr::Amount => {
                asset_def.policy.reveal_map.reveal_amount();
            },
            PolicyRevealAttr::BlindFactor => {
                asset_def.policy.reveal_map.reveal_blinding_factor();
            },
            PolicyRevealAttr::IdAttr(i) => {
                asset_def
                    .policy
                    .reveal_map
                    .reveal_ith_id_attribute(i)
                    .unwrap();
            },
            PolicyRevealAttr::AllIdAttr => {
                asset_def.policy.reveal_map.reveal_all_id_attributes();
            },
        }

        self.asset_def = asset_def.clone();
        self.mint_ro.asset_def = asset_def;

        self
    }

    pub(crate) fn build_witness_and_public_input<R>(
        &self,
        rng: &mut R,
    ) -> Result<(MintWitness<C>, MintPublicInput<C>), TxnApiError>
    where
        R: RngCore + CryptoRng,
    {
        let witness = self.build_witness(rng);
        let public_inputs = MintPublicInput::from_witness(&witness)?;
        Ok((witness, public_inputs))
    }

    /// Build the note given the parameters and a proving key
    #[allow(clippy::type_complexity)]
    pub fn build_mint_note<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        proving_key: &MintProvingKey<C>,
    ) -> Result<
        (
            MintNote<C>,
            schnorr::KeyPair<C::EmbeddedCurveParam>,
            RecordOpening<C>,
        ),
        TxnApiError,
    > {
        let fee_input = FeeInput {
            ro: self.fee_ro.clone(),
            acc_member_witness: self.acc_member_witness.clone(),
            owner_keypair: self.minter_keypair,
        };
        let (txn_fee_info, fee_chg_ro) = TxnFeeInfo::new(rng, fee_input, self.fee)?;
        let (note, key_pair) = MintNote::generate(
            rng,
            self.mint_ro.clone(),
            self.ac_seed,
            &self.ac_description,
            txn_fee_info,
            proving_key,
        )?;
        Ok((note, key_pair, fee_chg_ro))
    }

    /// randomly generate/prepare builder
    pub(crate) fn rand<R>(
        rng: &mut R,
        tree_depth: u8,
        minter_keypair: &'a UserKeyPair<C>,
        receiver_keypair: &'a UserKeyPair<C>,
        viewer_keypair: &'a ViewerKeyPair<C>,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let input_amount = Amount::from(rng.gen_range(1..50) as u64);
        let fee = Amount::from(rng.gen_range(1..=input_amount.0) as u64);
        let mint_amount = Amount::from(rng.gen_range(1..100) as u64);
        Self::new(
            rng,
            tree_depth,
            input_amount,
            fee,
            mint_amount,
            minter_keypair,
            receiver_keypair,
            viewer_keypair,
        )
    }
}

#[derive(Debug, Clone)]
/// Struct containing the parameters needed to build a Freeze note
pub struct FreezeParamsBuilder<'a, C: CapConfig> {
    tree_depth: u8,
    pub(crate) inputs: Vec<FreezeNoteInput<'a, C>>,
    pub(crate) fee_input: FeeInput<'a, C>,
    pub(crate) fee: Amount,
}

impl<'a, C: CapConfig> FreezeParamsBuilder<'a, C> {
    /// Instantiate a new FreezeParamsBuilder
    pub fn new(
        tree_depth: u8,
        input_amounts: &[Amount],
        fee_input_amount: Amount,
        fee: Amount,
        fee_keypair: &'a UserKeyPair<C>,
        freezing_keypairs: Vec<&'a FreezerKeyPair<C>>,
    ) -> Self {
        let rng = &mut ark_std::test_rng();
        assert_eq!(
            input_amounts.len(),
            freezing_keypairs.len(),
            "Should be same number of (non-fee) inputs and freezing keypairs"
        );
        let inputs: Vec<FreezeNoteInput<C>> = input_amounts
            .iter()
            .zip(freezing_keypairs.iter())
            .map(|(amount, keypair)| {
                let mut asset_def = AssetDefinition::rand_for_test(rng);
                asset_def.policy.freezer_pk = keypair.pub_key();
                let user_pk = UserKeyPair::generate(rng).pub_key();
                let ro = RecordOpening::new(rng, *amount, asset_def, user_pk, FreezeFlag::Unfrozen);
                let acc_member_witness = AccMemberWitness::default();
                FreezeNoteInput {
                    ro,
                    acc_member_witness,
                    keypair,
                }
            })
            .collect();
        let fee_input = {
            let fee_ro = RecordOpening::new(
                rng,
                fee_input_amount,
                AssetDefinition::native(),
                fee_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );
            FeeInput {
                ro: fee_ro,
                acc_member_witness: AccMemberWitness::default(),
                owner_keypair: fee_keypair,
            }
        };
        let mut builder = Self {
            tree_depth,
            inputs,
            fee_input,
            fee,
        };
        builder.refresh_merkle_root();
        builder
    }

    fn input_ros(&self) -> Vec<&RecordOpening<C>> {
        self.inputs.iter().map(|input| &input.ro).collect()
    }

    fn fee_ro(&self) -> &RecordOpening<C> {
        &self.fee_input.ro
    }

    /// randomly sample a builder with random amounts, and 50% freeze, 50%
    /// unfreeze
    pub(crate) fn rand<R>(
        rng: &mut R,
        tree_depth: u8,
        fee_keypair: &'a UserKeyPair<C>,
        freezing_keypairs: Vec<&'a FreezerKeyPair<C>>,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let num_input = freezing_keypairs.len();
        assert!(num_input > 0, "require at least one input for freezing");
        let mut input_amounts = vec![];
        for _ in 0..num_input {
            input_amounts.push(Amount::from(rng.gen_range(1..50) as u64));
        }
        let fee_input_amount = Amount::from(rng.gen_range(1..10) as u64);
        let fee = Amount::from(rng.gen_range(1..=fee_input_amount.0) as u64);
        let builder = Self::new(
            tree_depth,
            &input_amounts,
            fee_input_amount,
            fee,
            fee_keypair,
            freezing_keypairs,
        );
        (0..num_input).fold(builder, |builder, idx| {
            if rng.gen_bool(0.5) {
                builder.update_input_freeze_flag(idx, FreezeFlag::Frozen)
            } else {
                builder
            }
        })
    }

    fn refresh_merkle_root(&mut self) {
        let mut mt = MerkleTree::new(self.tree_depth).unwrap();
        for ro in self.input_ros().iter() {
            mt.push(ro.derive_record_commitment().to_field_element());
        }
        mt.push(self.fee_ro().derive_record_commitment().to_field_element());
        self.update_acc_member_witness(&mt, None, None);
    }

    fn update_acc_member_witness(
        &mut self,
        mt: &MerkleTree<C::ScalarField>,
        input_uids: Option<Vec<u64>>,
        fee_uid: Option<u64>,
    ) {
        let input_uids = if let Some(uids) = input_uids {
            assert_eq!(
                uids.len(),
                self.inputs.len(),
                "wrong number of input uid provided"
            );
            uids
        } else {
            // by default inputs are inserted first, before fee input
            (0..self.inputs.len() as u64).collect()
        };
        let fee_uid = if let Some(uid) = fee_uid {
            uid
        } else {
            // by default fee input is inserted after all inputs
            self.inputs.len() as u64
        };

        // update acc_member_witness of all input records
        for (idx, &uid) in input_uids.iter().enumerate() {
            self.inputs[idx].acc_member_witness = AccMemberWitness::lookup_from_tree(mt, uid)
                .expect_ok()
                .unwrap() // safe unwrap()
                .1;
        }
        self.fee_input.acc_member_witness = AccMemberWitness::lookup_from_tree(mt, fee_uid)
            .expect_ok()
            .unwrap() // safe unwrap()
            .1;
    }

    pub(crate) fn update_fee_asset_def(mut self, asset_def: AssetDefinition<C>) -> Self {
        self.fee_input.ro.asset_def = asset_def;
        self.refresh_merkle_root();
        self
    }

    pub(crate) fn update_fee_input_amount(mut self, fee_amount: Amount) -> Self {
        self.fee_input.ro.amount = fee_amount;
        self.refresh_merkle_root();
        self
    }

    pub(crate) fn update_fee_freeze_flag(mut self, flag: FreezeFlag) -> Self {
        self.fee_input.ro.freeze_flag = flag;
        self.refresh_merkle_root();
        self
    }

    pub(crate) fn update_input_freeze_flag(
        mut self,
        index: usize,
        freeze_flag: FreezeFlag,
    ) -> Self {
        assert!(index < self.inputs.len());
        self.inputs[index].ro.freeze_flag = freeze_flag;
        self.refresh_merkle_root();
        self
    }

    pub(crate) fn update_input_policy(mut self, index: usize, policy: AssetPolicy<C>) -> Self {
        assert!(index < self.inputs.len());
        self.inputs[index].ro.asset_def.policy = policy;
        self.refresh_merkle_root();
        self
    }

    // calculate the output ROs
    fn output_ros(&self) -> Vec<RecordOpening<C>> {
        let rng = &mut ark_std::test_rng();
        get_output_ros(rng, &self.inputs)
    }

    /// Build a witness
    pub(crate) fn build_witness(&self) -> FreezeWitness<C> {
        let rng = &mut ark_std::test_rng();
        let (txn_fee_input, _) = TxnFeeInfo::new(rng, self.fee_input.clone(), self.fee).unwrap();
        FreezeWitness::new_unchecked(self.inputs.clone(), &self.output_ros(), txn_fee_input)
    }

    pub(crate) fn build_witness_and_public_input(
        &self,
    ) -> (FreezeWitness<C>, FreezePublicInput<C>) {
        let witness = self.build_witness();
        let pub_input = FreezePublicInput::from_witness(&witness).unwrap();
        (witness, pub_input)
    }

    /// Build the note given the parameters, a proving key and a witness
    /// returns Note, signature key pair, fee_chg record opening, and (un)frozen
    /// outputs record openings
    #[allow(clippy::type_complexity)]
    pub fn build_freeze_note<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        proving_key: &FreezeProvingKey<C>,
    ) -> Result<
        (
            FreezeNote<C>,
            schnorr::KeyPair<C::EmbeddedCurveParam>,
            RecordOpening<C>,
            Vec<RecordOpening<C>>,
        ),
        TxnApiError,
    > {
        let (txn_fee_info, fee_chg_ro) = TxnFeeInfo::new(rng, self.fee_input.clone(), self.fee)?;
        let (note, keypair, outputs) =
            FreezeNote::generate(rng, self.inputs.clone(), txn_fee_info, proving_key)?;
        Ok((note, keypair, fee_chg_ro, outputs))
    }
}

// IMPLEMENT RANDOM FOR COMMON STRUCTURES
impl RevealMap {
    /// Modify current reveal map so that address, amount and blinding factor
    /// are revealed
    pub(crate) fn reveal_record_opening(&mut self) {
        self.reveal_user_address();
        self.reveal_amount();
        self.reveal_blinding_factor();
    }

    /// Modify current reveal map so that address, amount, blinding factor, and
    /// all identity attributes are revealed
    pub(crate) fn reveal_all(&mut self) {
        self.reveal_record_opening();
        self.reveal_all_id_attributes();
    }

    /// Generate a random reveal map
    pub fn rand_for_test<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut reveal_map = [false; VIEWABLE_DATA_LEN];
        for bit in reveal_map.iter_mut().skip(1) {
            *bit = rng.gen_bool(0.5);
        }
        reveal_map[0] = reveal_map[1];
        Self(reveal_map)
    }
}

impl<C: CapConfig> AssetDefinition<C> {
    /// Create a new random asset definition
    pub fn rand_for_test<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let (code, ..) = AssetCode::random(rng);
        AssetDefinition {
            code,
            policy: AssetPolicy::rand_for_test(rng),
        }
    }
}

impl<C: CapConfig> AssetPolicy<C> {
    /// generates a random AssetPolicy
    pub fn rand_for_test<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        AssetPolicy {
            viewer_pk: ViewerKeyPair::generate(rng).pub_key(),
            cred_pk: CredIssuerKeyPair::generate(rng).pub_key(),
            freezer_pk: FreezerKeyPair::generate(rng).pub_key(),
            reveal_map: RevealMap::rand_for_test(rng),
            reveal_threshold: Amount::from(rng.next_u64() as u128),
        }
    }
}

impl<C: CapConfig> RecordOpening<C> {
    /// Create a random record opening. Only used for testing.
    pub fn rand_for_test<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let amount = Amount::from(rng.next_u64() as u128); // In order to avoid possible u128 overflows
        let asset_def = AssetDefinition::rand_for_test(rng);
        let pub_key = UserKeyPair::generate(rng).pub_key();
        let freeze_flag = FreezeFlag::Unfrozen;
        Self::new(rng, amount, asset_def, pub_key, freeze_flag)
    }
}
