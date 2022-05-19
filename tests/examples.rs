// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

#[macro_use]
extern crate anyhow;

use anyhow::Result;
use ark_ec::ProjectiveCurve;
use ark_serialize::*;
use ark_std::{
    collections::{HashMap, HashSet},
    rand::CryptoRng,
    rc::Rc,
};
use jf_cap::{
    calculate_fee,
    constants::{ATTRS_LEN, MAX_TIMESTAMP_LEN},
    errors::TxnApiError,
    freeze::FreezeNote,
    keys::{
        CredIssuerKeyPair, FreezerKeyPair, FreezerPubKey, UserAddress, UserKeyPair, UserPubKey,
        ViewerKeyPair, ViewerPubKey,
    },
    mint::MintNote,
    proof::{
        freeze::FreezeProvingKey,
        mint::MintProvingKey,
        transfer::{preprocess, TransferProvingKey},
        universal_setup, UniversalParam,
    },
    sign_receiver_memos,
    structs::{
        AssetCode, AssetCodeSeed, AssetDefinition, AssetPolicy, BlindFactor, ExpirableCredential,
        FeeInput, FreezeFlag, IdentityAttribute, Nullifier, ReceiverMemo, RecordCommitment,
        RecordOpening, TxnFeeInfo, ViewableData,
    },
    transfer::{TransferNote, TransferNoteInput},
    txn_batch_verify, BaseField, CurveParam, TransactionNote, TransactionVerifyingKey,
};
use jf_primitives::{
    merkle_tree::{AccMemberWitness, MerkleTree, NodeValue},
    signatures::schnorr::Signature,
};
use rand::RngCore;

/// Global constants to be defined in application layer
pub const TREE_DEPTH: u8 = 26;
#[cfg(not(feature = "bls12_377"))]
pub const MAX_DEGREE: usize = 65538; // in practice, please use `crate::utils::compute_universal_param_size()`
#[cfg(feature = "bls12_377")]
pub const MAX_DEGREE: usize = 131074;

/// simulate retrieving global public structured reference string
pub fn mock_retrieve_srs() -> UniversalParam {
    universal_setup(MAX_DEGREE, &mut ark_std::test_rng()).unwrap()
}

/// Naive ledger structure
///  maintains merkle tree of record commitments, nullifier ser and set with
/// historial merkle roots
pub struct LedgerStateMock {
    mt: MerkleTree<BaseField>,
    nullifiers: HashSet<Nullifier>,
    mt_roots: HashSet<NodeValue<BaseField>>,
}

impl LedgerStateMock {
    /// Initiate a new mocked ledger
    pub fn new() -> LedgerStateMock {
        let mut ledger = LedgerStateMock {
            mt: MerkleTree::new(TREE_DEPTH).unwrap(),
            nullifiers: HashSet::new(),
            mt_roots: HashSet::new(),
        };
        ledger.store_current_mt_root();
        ledger
    }

    /// Simulate minting native asset type
    pub fn mock_mint_native_asset<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        owner_pub_key: UserPubKey,
        amount: u64,
    ) -> (RecordOpening, u64) {
        let ro = RecordOpening::new(
            rng,
            amount,
            AssetDefinition::native(),
            owner_pub_key,
            FreezeFlag::Unfrozen,
        );
        let rc = RecordCommitment::from(&ro);
        let uid = self.next_uid();
        self.mt.push(rc.to_field_element());
        self.store_current_mt_root();
        (ro, uid)
    }

    /// Simulate minting non native asset
    pub fn mock_mint_non_native_asset<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        owner_pub_key: UserPubKey,
        amount: u64,
        asset_definition: AssetDefinition,
    ) -> (RecordOpening, u64) {
        let ro = RecordOpening::new(
            rng,
            amount,
            asset_definition,
            owner_pub_key,
            FreezeFlag::Unfrozen,
        );
        let rc = RecordCommitment::from(&ro);
        let uid = self.next_uid();
        self.mt.push(rc.to_field_element());
        self.store_current_mt_root();
        (ro, uid)
    }

    // insert output record commitment in merkle tree
    fn insert_record(&mut self, rc: RecordCommitment) {
        self.mt.push(rc.to_field_element())
    }

    // insert input nullifier in nullifier set
    fn insert_nullifier(&mut self, nullifier: &Nullifier) {
        self.nullifiers.insert(*nullifier);
    }

    // Save current merkle root in set of historial merkle roots
    fn store_current_mt_root(&mut self) {
        self.mt_roots.insert(self.mt.commitment().root_value);
    }

    /// Check that input nullifier is in the nullifier set
    pub fn check_nullifier(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Check that root is in historial merkle root set
    pub fn check_valid_root(&self, merkle_root: &NodeValue<BaseField>) -> bool {
        self.mt_roots.contains(merkle_root)
    }

    // insert input nullifiers and output record commitments
    fn insert_transfer_note(&mut self, xfr_note: &TransferNote, store_new_mt_root: bool) {
        // 1 insert output commitments to merkle tree
        xfr_note
            .output_commitments
            .iter()
            .for_each(|e| self.insert_record(e.clone()));

        // 2 store new root
        if store_new_mt_root {
            self.store_current_mt_root();
        }

        // 3 insert nullifiers
        xfr_note.inputs_nullifiers.iter().for_each(|e| {
            self.insert_nullifier(e);
        });
    }

    // insert input nullifiers and output record commitments
    fn insert_mint_note(&mut self, mint_note: &MintNote, store_new_mt_root: bool) {
        // 1 insert new record commitments: fee change record and new minted record
        self.insert_record(mint_note.chg_comm);
        self.insert_record(mint_note.mint_comm);

        // 2 store new merkle root
        if store_new_mt_root {
            self.store_current_mt_root();
        }

        // 3 insert input record nullifier (that pays fee)
        self.insert_nullifier(&mint_note.input_nullifier);
    }

    // insert input nullifiers and output record commitments
    fn insert_freeze_note(&mut self, freeze_note: &FreezeNote, store_new_mt_root: bool) {
        // 1 insert new record commitments: fee change record and new minted record
        for output in freeze_note.output_commitments.iter() {
            self.insert_record(*output);
        }

        // 2 store new merkle root
        if store_new_mt_root {
            self.store_current_mt_root();
        }

        // 3 insert nullifiers
        freeze_note.input_nullifiers.iter().for_each(|e| {
            self.insert_nullifier(e);
        });
    }

    /// insert input nullifiers and output record commitments
    pub fn insert_block(&mut self, block: &MockBlock) -> Result<()> {
        for txn in block.txns.iter() {
            match txn {
                TransactionNote::Transfer(xfr) => {
                    self.insert_transfer_note(xfr, false);
                },
                TransactionNote::Mint(mint) => {
                    self.insert_mint_note(mint, false);
                },
                TransactionNote::Freeze(freeze) => self.insert_freeze_note(freeze, false),
            }
        }
        let collected_fee_record = block.derive_fee_record_commitment()?;
        self.insert_record(collected_fee_record);
        self.store_current_mt_root();
        Ok(())
    }

    pub fn next_uid(&self) -> u64 {
        self.mt.num_leaves()
    }
}

/// Ledger Transaction Block
#[derive(Clone, CanonicalSerialize)]
pub struct MockBlock {
    txns: Vec<TransactionNote>,
    fee_blind: BlindFactor,
    proposer_pub_key: UserPubKey,
}

impl MockBlock {
    /// scan the block and derive record commitment corresponding to the
    /// collected fee owned by block proposer
    pub fn derive_fee_record_commitment(&self) -> Result<RecordCommitment> {
        let total_fee = calculate_fee(&self.txns)?;
        Ok(RecordCommitment::from(&RecordOpening {
            amount: total_fee,
            asset_def: AssetDefinition::native(),
            pub_key: self.proposer_pub_key.clone(),
            freeze_flag: FreezeFlag::Unfrozen,
            blind: self.fee_blind,
        }))
    }
}

/// Simple Validator that verify transfers against current ledger state
pub struct ValidatorMock<'a> {
    // mapping between transaction type description and corresponding verifying key
    verifying_keys: HashMap<String, Rc<TransactionVerifyingKey>>,
    srs: &'a UniversalParam,
    // for fee collection ownership
    wallet: SimpleUserWalletMock<'a>,
}

impl<'a> ValidatorMock<'a> {
    /// Create a new validator/block proposer containing a user wallet
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R, srs: &'a UniversalParam) -> ValidatorMock<'a> {
        ValidatorMock {
            verifying_keys: HashMap::new(),
            srs,
            wallet: SimpleUserWalletMock::generate(rng, srs),
        }
    }

    /// Validate transfer note
    /// `srs`: Public global structured reference string
    /// `ledger_state`: Current ledger state (nullifier set, merkle tree,
    /// history of merkle roots) `xfr_note`: transfer note to verify
    /// `recv_memos`: receiver memos associated with transfer notes
    /// `recv_memos_sig`: signature over receiver memos
    /// `timestamp`: current timestamp of the system
    ///  1. fetch or create verifying key
    ///  2. check transfer note input nullifiers
    ///    2a. check nullifiers are not in the ledger state
    ///    2b. check nullifiers do not repeat inside the transfer note
    ///  3. verify transfer proof
    ///    3a. check transfer note merkle root in historical merkle root sets
    ///    3b. validate transfer note on current timestamp
    ///  4. verify signatures on receiver memos
    pub fn validate_single_xfr_note(
        &mut self,
        ledger_state: &LedgerStateMock,
        xfr_note: &TransferNote,
        timestamp: u64,
    ) -> Result<()> {
        let n_inputs = xfr_note.inputs_nullifiers.len();
        let n_outputs = xfr_note.output_commitments.len();

        // 0. get verifying key
        let verifying_key = self.get_xfr_verifying_key(n_inputs, n_outputs);

        // 1. check nullifier set
        Self::check_txn_input_nullifiers(
            ledger_state,
            &xfr_note.inputs_nullifiers,
            &mut HashSet::new(),
        )?;

        // 2 verify xfr_note
        // 2.1 check that xfr_note's merkle root is or was a valid merkle root
        let root_value = xfr_note.aux_info.merkle_root;
        if !ledger_state.check_valid_root(&root_value) {
            return Err(anyhow!("Merkle root is invalid"));
        }

        // 2.3 validate xfr_note on given root and timestamp
        match verifying_key.as_ref() {
            TransactionVerifyingKey::Transfer(xfr_verifying_key) => {
                xfr_note.verify(xfr_verifying_key, root_value, timestamp)?
            },
            _ => unreachable!(),
        }
        Ok(())
    }

    /// called by block proposer on a list of transaction to create a block
    /// consisting on the transactions list, collected fee record commitment
    /// blinding factor, and proposer public key
    pub fn collect_fee_and_build_block<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        txns: Vec<TransactionNote>,
    ) -> Result<(RecordOpening, MockBlock, Signature<CurveParam>)> {
        // 1. sample collected fee record
        let total_fee = calculate_fee(&txns)?;
        let record_opening = RecordOpening::new(
            rng,
            total_fee,
            AssetDefinition::native(),
            self.wallet.pub_key(),
            FreezeFlag::Unfrozen,
        );

        // 2. build block
        let block = MockBlock {
            txns,
            proposer_pub_key: self.wallet.pub_key(),
            fee_blind: record_opening.blind,
        };

        // 3. sign block
        let mut bytes = Vec::new();
        block.serialize(&mut bytes).expect("deserialization error");
        let sig = self.wallet.keypair.sign(&bytes);

        Ok((record_opening, block, sig))
    }

    /// validate a block and return collected fee record commitment to be
    /// inserted in the ledger
    pub fn validate_block(
        &mut self,
        ledger_state: &LedgerStateMock,
        block: &MockBlock,
        block_sig: &Signature<CurveParam>,
        timestamp: u64,
        proposer_pub_key: &UserPubKey,
    ) -> Result<()> {
        // 1. check address
        if block.proposer_pub_key != *proposer_pub_key {
            return Err(anyhow!("proposer public key from sortition result from consensus mismatches with that of the block"));
        }

        // 2. check block signature
        let mut block_bytes = Vec::new();
        block
            .serialize(&mut block_bytes)
            .expect("deserialization error");
        proposer_pub_key.verify_sig(&block_bytes, block_sig)?;

        // 3. validate transactions
        self.validate_txns_batch(ledger_state, &block.txns, timestamp)
    }

    /// validate list of transactions in batch
    fn validate_txns_batch(
        &mut self,
        ledger_state: &LedgerStateMock,
        txns: &[TransactionNote],
        timestamp: u64,
    ) -> Result<()> {
        let mut verifying_keys = vec![];
        let mut roots = vec![];
        let mut checked_nullifiers = HashSet::new(); // set of nullifiers in the transaction list
        for note in txns.into_iter() {
            // 1. get corresponding verifying key
            match note {
                TransactionNote::Transfer(xfr_note) => {
                    let n_input = xfr_note.inputs_nullifiers.len();
                    let n_output = xfr_note.output_commitments.len();
                    // 1. get/compute verification key
                    verifying_keys.push(self.get_xfr_verifying_key(n_input, n_output));
                },
                TransactionNote::Mint(_) => {
                    // 1. get/compute verification key
                    verifying_keys.push(self.get_mint_verifying_key());
                },
                TransactionNote::Freeze(freeze_note) => {
                    let n_inputs = freeze_note.input_nullifiers.len();
                    verifying_keys.push(self.get_freeze_verifying_key(n_inputs));
                },
            }
            // 2. check transfer nullifiers are not in the ledger state and that they do not
            // repeat within transfer or other transaction in the batch
            Self::check_txn_input_nullifiers(
                ledger_state,
                &note.nullifiers(),
                &mut checked_nullifiers,
            )?;

            // 3. get merkle root value for transaction and check its validity
            let root_value = note.merkle_root();
            if !ledger_state.check_valid_root(&root_value) {
                return Err(anyhow!("merkle root is not part of the history"));
            }
            roots.push(root_value);
        }

        let verifying_keys_refs: Vec<_> = verifying_keys.iter().map(|rc| rc.as_ref()).collect();

        Ok(txn_batch_verify(
            txns,
            &roots,
            timestamp,
            &verifying_keys_refs,
        )?)
    }

    fn get_mint_verifying_key(&mut self) -> Rc<TransactionVerifyingKey> {
        let description = String::from("Mint");
        if !self.verifying_keys.contains_key(&description) {
            let (_, verifying_key, _) =
                jf_cap::proof::mint::preprocess(&self.srs, TREE_DEPTH).unwrap();
            self.verifying_keys.insert(
                description.clone(),
                Rc::new(TransactionVerifyingKey::Mint(verifying_key)),
            );
        }
        self.verifying_keys.get(&description).unwrap().clone()
    }

    fn get_xfr_verifying_key(
        &mut self,
        n_inputs: usize,
        n_outputs: usize,
    ) -> Rc<TransactionVerifyingKey> {
        let description = format!("Xfr_{}_{}", n_inputs, n_outputs);
        if !self.verifying_keys.contains_key(&description) {
            let (_, verifying_key, _) =
                preprocess(&self.srs, n_inputs, n_outputs, TREE_DEPTH).unwrap();
            self.verifying_keys.insert(
                description.clone(),
                Rc::new(TransactionVerifyingKey::Transfer(verifying_key)),
            );
        }
        self.verifying_keys.get(&description).unwrap().clone()
    }

    fn get_freeze_verifying_key(&mut self, n_inputs: usize) -> Rc<TransactionVerifyingKey> {
        let description = format!("Freeze_{}", n_inputs);
        if !self.verifying_keys.contains_key(&description) {
            let (_, verifying_key, _) =
                jf_cap::proof::freeze::preprocess(&self.srs, n_inputs, TREE_DEPTH).unwrap();
            self.verifying_keys.insert(
                description.clone(),
                Rc::new(TransactionVerifyingKey::Freeze(verifying_key)),
            );
        }
        self.verifying_keys.get(&description).unwrap().clone()
    }

    // verify nullifiers in a transaction are not in the ledger state nor in a set
    // of nullifiers already checked (in a block)
    fn check_txn_input_nullifiers(
        ledger_state: &LedgerStateMock,
        nullifiers: &[Nullifier],
        checked_nullifiers: &mut HashSet<Nullifier>,
    ) -> Result<()> {
        // 1. check nullifiers against ledger state
        if nullifiers
            .iter()
            .any(|nullifier| ledger_state.check_nullifier(nullifier))
        {
            return Err(anyhow!("Some txn input nullifier already in ledger"));
        }

        // 2. check nullifiers within transfer note are all different
        if !nullifiers
            .iter()
            .all(|nullifier| checked_nullifiers.insert(*nullifier))
        {
            return Err(anyhow!("Repeated nullifiers within the transansaction"));
        }
        Ok(())
    }
}

/// Simple Viewer that scan Transfer note and attempt to decrypt ViewableMemos
pub struct ViewerMock {
    keypair: ViewerKeyPair,
    asset_def: AssetDefinition,
}

impl ViewerMock {
    /// Create a new viewer
    pub fn new(keypair: ViewerKeyPair, asset_def: AssetDefinition) -> ViewerMock {
        ViewerMock { keypair, asset_def }
    }

    pub fn pub_key(&self) -> ViewerPubKey {
        self.keypair.pub_key()
    }
    /// Scan transfer note viewing memos and attempt to open them
    /// Return Error if asset policy does not math of error in decryption
    pub fn scan_xfr(
        &self,
        xfr_note: &TransferNote,
        uid_offset: u64,
    ) -> Result<(Vec<ViewableData>, Vec<(ViewableData, u64)>)> {
        let n_inputs = xfr_note.inputs_nullifiers.len() - 1;
        let n_outputs = xfr_note.output_commitments.len() - 1;
        let (input_visible_data, output_visible_data) = self
            .keypair
            .open_transfer_viewing_memo(&self.asset_def, &xfr_note)?;

        if input_visible_data.len() > 0 && input_visible_data.len() > n_inputs {
            // input can be dummy and contain noviewing data, so we allow
            // input_visible_data.len() < n_inputs
            return Err(anyhow!("bug: unexpectedviewing data len"));
        }

        if output_visible_data.len() > 0 && output_visible_data.len() != n_outputs {
            return Err(anyhow!("bug: unexpectedviewing data len"));
        }

        let mut uid = uid_offset + 1; // skip fee change
        let mut output_visible_data_uids = vec![];
        for output_record_visible_data in output_visible_data.into_iter() {
            output_visible_data_uids.push((output_record_visible_data, uid));
            uid += 1;
        }
        Ok((input_visible_data, output_visible_data_uids))
    }

    pub fn scan_mint(&self, mint_note: &MintNote, uid_offset: u64) -> Result<(ViewableData, u64)> {
        let visible_data = self.keypair.open_mint_viewing_memo(mint_note)?;
        Ok((visible_data, uid_offset + 1)) // skip fee change record
    }
}

/// Simple freezer who is also an viewer that views record openings (but for
/// simplicity does not view identity attributes)
pub struct FreezerMock<'a> {
    // Viewer: freezer needsviewing data and hence we assume that a freezer is also an viewer.
    // Alternatively, freezer and viewer can be independent entities and communicate via RPC
    viewer: ViewerMock,
    keypair: FreezerKeyPair,
    srs: &'a UniversalParam,
    proving_keys: HashMap<String, FreezeProvingKey<'a>>,
    // wallet: wallet used to pay fees
    wallet: SimpleUserWalletMock<'a>,
    freezable_records: HashMap<UserAddress, HashSet<(RecordOpening, u64)>>, // record + uid
    releasable_records: HashMap<UserAddress, HashSet<(RecordOpening, u64)>>, // record + uid
    // unconfirmed_frozen_records:Frozen records where freeze transaction has been produced, but
    // has not been confirmed by network It store the user address (original record and uid)
    // and frozen record opening Once the nullifier is detected in a validated freeze
    // transaction, the user address is used to indexing freezable_records and remove
    // (original_record opening and its uid). The frozen record opening is added to
    // releasable_records.
    unconfirmed_frozen_records:
        HashMap<Nullifier, (UserAddress, (RecordOpening, u64), RecordOpening)>, /* address, (original record, uid), frozen opening */
    // unconfirmed_released_records: Released records where unfreeze transaction has been produced,
    // but has not been confirmed by network It store the user address (frozen record and uid)
    // and released record opening Once the nullifier is detected in a validated unfreeze
    // transaction, the user address is used to indexing releasable_records and remove
    // (frozen_record opening and its uid). The released record opening is added to
    // freezaable_records.
    unconfirmed_released_records:
        HashMap<Nullifier, (UserAddress, (RecordOpening, u64), RecordOpening)>, /* address, (frozen record, uid), released record opening */
    // user_keys_orable: The user address is detected via viewing memo, but we assume freezer can
    // find out the entirety of user's public key (including the encryption key for ReceiverMemo)
    // either via direct channel with the user, or via public bulletin board.
    user_keys_oracle: HashMap<UserAddress, UserPubKey>,
}

impl<'a> FreezerMock<'a> {
    /// Create a new freezer
    pub fn generate<R: CryptoRng + RngCore>(
        rng: &mut R,
        srs: &'a UniversalParam,
        asset_code: AssetCode,
    ) -> FreezerMock<'a> {
        let freezer_keypair = FreezerKeyPair::generate(rng);
        let viewer_keypair = ViewerKeyPair::generate(rng);
        let asset_policy = AssetPolicy::default()
            .set_viewer_pub_key(viewer_keypair.pub_key())
            .set_freezer_pub_key(freezer_keypair.pub_key())
            .reveal_record_opening()
            .unwrap();
        let asset_definition = AssetDefinition::new(asset_code, asset_policy).unwrap();
        let viewer = ViewerMock::new(viewer_keypair, asset_definition);
        let wallet = SimpleUserWalletMock::generate(rng, srs);

        FreezerMock {
            keypair: freezer_keypair,
            viewer,
            srs,
            proving_keys: HashMap::new(),
            freezable_records: HashMap::new(),
            unconfirmed_frozen_records: HashMap::new(),
            unconfirmed_released_records: HashMap::new(),
            releasable_records: HashMap::new(),
            wallet,
            user_keys_oracle: HashMap::new(),
        }
    }

    pub fn asset_def(&self) -> AssetDefinition {
        self.viewer.asset_def.clone()
    }

    pub fn pub_key(&self) -> FreezerPubKey {
        self.keypair.pub_key()
    }

    pub fn add_user_key(&mut self, key: UserPubKey) {
        self.user_keys_oracle.insert(key.address(), key);
    }

    fn get_proving_key(&self, n_inputs: usize) -> Option<&FreezeProvingKey<'a>> {
        let description = format!("Freeze_{}", n_inputs);
        self.proving_keys.get(&description)
    }

    fn compute_proving_key(&self, n_inputs: usize) -> FreezeProvingKey<'a> {
        let (proving_key, ..) =
            jf_cap::proof::freeze::preprocess(&self.srs, n_inputs, TREE_DEPTH).unwrap();
        proving_key
    }

    fn insert_proving_key(&mut self, n_inputs: usize, proving_key: FreezeProvingKey<'a>) {
        let description = format!("Freeze_{}", n_inputs);
        self.proving_keys.insert(description, proving_key);
    }

    /// scan a block looking for freezable records in transfers, mints,
    /// and update freezable/releasable status for freeze notes
    pub fn scan_block(
        &mut self,
        block: &MockBlock,
        receiver_memos: &[&[ReceiverMemo]],
        uid_offset: u64,
    ) -> Result<()> {
        if block.txns.len() != receiver_memos.len() {
            return Err(anyhow!(
                "txn len:{}, receiver_memos len:{}",
                block.txns.len(),
                receiver_memos.len()
            ));
        }
        let mut uid = uid_offset;
        for (txn, txn_receiver_memos) in block.txns.iter().zip(receiver_memos.iter()) {
            let n_outputs = txn.output_commitments().len() as u64;
            self.scan_txn(txn, txn_receiver_memos, uid)?;
            uid += n_outputs;
        }
        Ok(())
    }

    /// scan a transaction looking for freezable records in transfers, mints,
    /// and update freezable/releasable status for freeze notes
    pub fn scan_txn(
        &mut self,
        txn: &TransactionNote,
        receiver_memos: &[ReceiverMemo],
        uid_offset: u64,
    ) -> Result<()> {
        self.wallet.scan_txn(txn, receiver_memos, uid_offset);
        match txn {
            TransactionNote::Transfer(xfr) => self.scan_xfr(xfr, uid_offset),
            TransactionNote::Freeze(freeze) => self.scan_freeze(freeze, uid_offset),
            TransactionNote::Mint(mint) => self.scan_mint(mint, uid_offset),
        }
    }

    // check if created record is freezable
    // Store record opening of freezable minted record
    fn scan_mint(&mut self, mint_note: &MintNote, uid_offset: u64) -> Result<()> {
        let (visible_data, uid) = self.viewer.scan_mint(mint_note, uid_offset)?;
        let user_address = visible_data.user_address.as_ref().unwrap();
        let ro = RecordOpening {
            amount: visible_data.amount.unwrap(),
            asset_def: self.viewer.asset_def.clone(),
            pub_key: self.user_keys_oracle.get(user_address).unwrap().clone(),
            freeze_flag: FreezeFlag::Unfrozen,
            blind: visible_data.blinding_factor.unwrap(),
        };
        match self
            .freezable_records
            .get_mut(visible_data.user_address.as_ref().unwrap())
        {
            Some(set) => {
                set.insert((ro, uid));
            },
            None => {
                let mut hash_set = HashSet::new();
                hash_set.insert((ro, uid));
                self.freezable_records
                    .insert(visible_data.user_address.clone().unwrap(), hash_set);
            },
        }
        Ok(())
    }

    // scan a transfer looking for freezable records and store their openings
    fn scan_xfr(&mut self, xfr_note: &TransferNote, uid_offset: u64) -> Result<()> {
        let (_input_records, output_records_and_uids) =
            self.viewer.scan_xfr(xfr_note, uid_offset)?;
        // take only outputs
        for (transfer_visible_data, uid) in output_records_and_uids.iter() {
            let user_address = transfer_visible_data.user_address.as_ref().unwrap();
            let ro = RecordOpening {
                amount: transfer_visible_data.amount.unwrap(),
                asset_def: self.viewer.asset_def.clone(),
                pub_key: self.user_keys_oracle.get(user_address).unwrap().clone(),
                freeze_flag: FreezeFlag::Unfrozen,
                blind: transfer_visible_data.blinding_factor.unwrap(),
            };
            match self
                .freezable_records
                .get_mut(transfer_visible_data.user_address.as_ref().unwrap())
            {
                Some(set) => {
                    set.insert((ro, *uid));
                },
                None => {
                    let mut hash_set = HashSet::new();
                    hash_set.insert((ro, *uid));
                    self.freezable_records.insert(
                        transfer_visible_data.user_address.clone().unwrap(),
                        hash_set,
                    );
                },
            }
        }
        Ok(())
    }

    // scan a freeze note updating state on unconfirmed freezable and frozen records
    fn scan_freeze(&mut self, freeze_note: &FreezeNote, uid_offset: u64) -> Result<()> {
        let uid_offset = uid_offset + 1;
        for (position, nullifier) in freeze_note.input_nullifiers.iter().skip(1).enumerate() {
            match self.unconfirmed_frozen_records.get(nullifier) {
                None => {},
                Some((addr, original_record_and_uid, releasable_record)) => {
                    self.freezable_records
                        .get_mut(addr)
                        .unwrap()
                        .remove(&original_record_and_uid);
                    match self.releasable_records.get_mut(addr) {
                        None => {
                            let mut set = HashSet::new();
                            set.insert((releasable_record.clone(), uid_offset + position as u64));
                            self.releasable_records.insert(addr.clone(), set);
                        },
                        Some(set) => {
                            set.insert((releasable_record.clone(), uid_offset + position as u64));
                        },
                    }
                    self.unconfirmed_frozen_records.remove(nullifier);
                },
            }
            match self.unconfirmed_released_records.get(nullifier) {
                None => {},
                Some((addr, frozen_record_uid, released_record)) => {
                    self.releasable_records
                        .get_mut(addr)
                        .unwrap()
                        .remove(&frozen_record_uid);
                    self.freezable_records
                        .get_mut(addr)
                        .unwrap()
                        .insert((released_record.clone(), uid_offset + position as u64));
                    self.unconfirmed_released_records.remove(nullifier);
                },
            }
        }
        Ok(())
    }

    /// unfreeze user
    pub fn unfreeze_user<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        user: &UserAddress,
        fee: u64,
        merkle_tree_oracle: &MerkleTree<BaseField>,
    ) -> Result<(FreezeNote, Vec<ReceiverMemo>, Signature<CurveParam>)> {
        self.freeze_user_internal(rng, user, fee, merkle_tree_oracle, false)
    }

    /// unfreeze user
    pub fn freeze_user<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        user: &UserAddress,
        fee: u64,
        merkle_tree_oracle: &MerkleTree<BaseField>,
    ) -> Result<(FreezeNote, Vec<ReceiverMemo>, Signature<CurveParam>)> {
        self.freeze_user_internal(rng, user, fee, merkle_tree_oracle, true)
    }

    /// freeze user
    fn freeze_user_internal<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        user: &UserAddress,
        fee: u64,
        merkle_tree_oracle: &MerkleTree<BaseField>,
        freeze: bool, // true: freeze, false: unfreeze
    ) -> Result<(FreezeNote, Vec<ReceiverMemo>, Signature<CurveParam>)> {
        // 1. get records for user
        let records_and_uids = if freeze {
            self.freezable_records
                .get(user)
                .ok_or(anyhow!(
                    "No records to freeze for user {}",
                    user.internal().into_affine()
                ))?
                .clone()
        } else {
            self.releasable_records
                .get(user)
                .ok_or(anyhow!(
                    "No records to unfreeze for user {}",
                    user.internal().into_affine()
                ))?
                .clone()
        };
        // 2. build inputs
        // 2.1 fee inputs
        let (fee_record, uid) = self.wallet.find_record_for_fee(fee)?;
        let witness = AccMemberWitness::lookup_from_tree(merkle_tree_oracle, uid)
            .expect_ok()
            .unwrap()
            .1;

        let nullifier = self.wallet.keypair.nullify(
            &Default::default(),
            uid,
            &RecordCommitment::from(&fee_record),
        );
        self.wallet
            .mark_unconfirmed_spent(nullifier, fee_record.clone(), uid);

        let fee_input = FeeInput {
            ro: fee_record,
            acc_member_witness: witness,
            owner_keypair: &self.wallet.keypair,
        };
        let (txn_fee_info, fee_chg_ro) = TxnFeeInfo::new(rng, fee_input, fee).unwrap();
        // set input with a dummy record
        let dummy_freezer_keypair = FreezerKeyPair::default();
        let freeze_flag = if freeze {
            FreezeFlag::Unfrozen
        } else {
            FreezeFlag::Frozen
        };
        let (dummy_ro, _dummy_key) = RecordOpening::dummy(rng, freeze_flag);
        let mut inputs = vec![jf_cap::freeze::FreezeNoteInput {
            ro: dummy_ro,
            acc_member_witness: AccMemberWitness::dummy(TREE_DEPTH),
            keypair: &dummy_freezer_keypair,
        }];
        // 2.2 build each input to freeze
        for (record, uid) in records_and_uids.iter() {
            let witness = AccMemberWitness::lookup_from_tree(merkle_tree_oracle, *uid)
                .expect_ok()
                .unwrap()
                .1;
            inputs.push(jf_cap::freeze::FreezeNoteInput {
                ro: record.clone(),
                acc_member_witness: witness,
                keypair: &self.keypair,
            });
        }
        // push a dummy input at the end just as an example
        let (dummy_ro, _dummy_key) = RecordOpening::dummy(rng, freeze_flag);
        inputs.push(jf_cap::freeze::FreezeNoteInput {
            ro: dummy_ro,
            acc_member_witness: AccMemberWitness::dummy(TREE_DEPTH),
            keypair: &dummy_freezer_keypair,
        });

        let input_len = inputs.len();
        let proving_key = self.get_proving_key(input_len + 1);
        let (freeze_note, sig_key, freeze_note_outputs_record_openings) = match proving_key {
            Some(key) => FreezeNote::generate(rng, inputs, txn_fee_info, key).unwrap(),
            None => {
                let proving_key = self.compute_proving_key(input_len + 1);
                let r = FreezeNote::generate(rng, inputs, txn_fee_info, &proving_key).unwrap();
                self.insert_proving_key(input_len + 1, proving_key);
                r
            },
        };

        // wallet option: compute receiver memos and sign them with a key bound to the
        // transaction
        let recv_memos: Vec<_> = freeze_note_outputs_record_openings
            .iter()
            .map(|ro| ReceiverMemo::from_ro(rng, ro, &[]).unwrap())
            .collect();
        let sig = sign_receiver_memos(&sig_key, &recv_memos)?;

        // records_and_uids doesn't contain any dummy record,
        // hence I cannot zip with freeze_note_outputs_record_openings (may contain
        // dummy records)
        let mut records_uids_iter = records_and_uids.into_iter();
        for new_record in freeze_note_outputs_record_openings.iter() {
            if new_record.is_dummy() {
                continue;
            }
            let (original_record, uid) = records_uids_iter.next().unwrap();
            let owner_public_key = &original_record.pub_key;
            let nullifier = self.keypair.nullify(
                &owner_public_key.address(),
                uid,
                &RecordCommitment::from(&original_record),
            );
            if freeze {
                self.unconfirmed_frozen_records.insert(
                    nullifier,
                    (
                        owner_public_key.address(),
                        (original_record, uid),
                        new_record.clone(),
                    ),
                );
            } else {
                self.unconfirmed_released_records.insert(
                    nullifier,
                    (
                        owner_public_key.address(),
                        (original_record, uid),
                        new_record.clone(),
                    ),
                );
            }
        }

        self.wallet.unconfirmed_fee_chg_records.insert(fee_chg_ro);
        Ok((freeze_note, recv_memos, sig))
    }
}

// a never expired target
const UNEXPIRED_VALID_UNTIL: u64 = 2u64.pow(MAX_TIMESTAMP_LEN as u32) - 1;

/// Simple naive wallet for users
/// it stores spending keypair, all owned records by the key, and the credential
/// linked to the user
pub struct SimpleUserWalletMock<'a> {
    // spending, decrypting, signing keys
    keypair: UserKeyPair,
    // user credentials
    credential: Option<ExpirableCredential>,
    // reference to SRS
    srs: &'a UniversalParam,
    // map from description string to corresponding verifying key
    proving_keys: HashMap<String, TransferProvingKey<'a>>,
    // submitted record for spending, not confirmed by network yet
    // store mapping from nullifier to record opening and uid of the record (position in the merkle
    // tree)
    unconfirmed_spent_records: HashMap<Nullifier, (RecordOpening, u64)>,
    // owned records not spent yet, maps asset code to (record_opening, uid)
    unspent_records: HashMap<AssetCode, HashSet<(RecordOpening, u64)>>,
    // record openings produces as fee change, waiting confirmation to add to unspent_records
    unconfirmed_fee_chg_records: HashSet<RecordOpening>,
}

impl<'a> SimpleUserWalletMock<'a> {
    /// sample keypair and initiate empty record opening set
    pub fn generate<R: CryptoRng + RngCore>(
        rng: &mut R,
        srs: &'a UniversalParam,
    ) -> SimpleUserWalletMock<'a> {
        SimpleUserWalletMock {
            keypair: UserKeyPair::generate(rng),
            credential: None,
            srs,
            proving_keys: HashMap::new(),
            unspent_records: HashMap::new(),
            unconfirmed_spent_records: HashMap::new(),
            unconfirmed_fee_chg_records: HashSet::new(),
        }
    }

    /// computes spendable funds for given asset code
    pub fn available_funds(&self, asset_code: &AssetCode) -> u64 {
        match self.unspent_records.get(asset_code) {
            Some(records) => records.iter().map(|(record, _uid)| record.amount).sum(),
            None => 0u64,
        }
    }

    // retrieve public key
    fn pub_key(&self) -> UserPubKey {
        self.keypair.pub_key()
    }

    // Add record opening to list of owned records
    fn add_record_opening(&mut self, record_opening: RecordOpening, uid: u64) {
        let code = record_opening.asset_def.code;
        self.unspent_records
            .entry(code)
            .or_insert(HashSet::new())
            .insert((record_opening, uid));
    }

    // Set user credential
    fn set_credential(&mut self, credential: ExpirableCredential) {
        self.credential = Some(credential)
    }

    /// Scan a transaction and matching receiver memos looking for owner record
    /// in the transaction and it updates unconfirmed spent records by
    /// looking at the input nullifiers `uid_offset`:  number of ledger
    /// records before this transaction is added to the ledger
    pub fn scan_txn(
        &mut self,
        txn_note: &TransactionNote,
        receiver_memos: &[ReceiverMemo],
        uid_offset: u64,
    ) -> Vec<RecordOpening> {
        // process output
        let mut recv_record_openings: Vec<_> = vec![];
        let output_commitments = match txn_note {
            TransactionNote::Transfer(xfr) => xfr.output_commitments.clone(),
            TransactionNote::Mint(mint) => {
                vec![mint.chg_comm, mint.mint_comm]
            },
            TransactionNote::Freeze(freeze) => freeze.output_commitments.clone(),
        };

        assert_eq!(output_commitments.len() - 1, receiver_memos.len());
        let mut delete = None;
        for unconfirmed_fee_chg_ro in self.unconfirmed_fee_chg_records.iter() {
            let commitment = RecordCommitment::from(unconfirmed_fee_chg_ro);
            if commitment == output_commitments[0] {
                delete = Some(unconfirmed_fee_chg_ro.clone());
                break;
            }
        }
        delete.map(|ro| {
            self.unconfirmed_fee_chg_records.remove(&ro);
            self.add_record_opening(ro, uid_offset);
        });
        assert_eq!(output_commitments.len() - 1, receiver_memos.len());
        for (position, (record_commitment, memo)) in output_commitments
            .iter()
            .skip(1)
            .zip(receiver_memos.iter())
            .enumerate()
        {
            match memo.decrypt(&self.keypair, record_commitment, &[]) {
                Ok(record_opening) => {
                    recv_record_openings.push(record_opening.clone());
                    match record_opening.freeze_flag {
                        FreezeFlag::Unfrozen => {
                            self.add_record_opening(
                                record_opening,
                                uid_offset + 1 + position as u64,
                            );
                        },
                        FreezeFlag::Frozen => {},
                    }
                },
                Err(_) => {},
            }
        }

        // process input
        for nullifier in txn_note.nullifiers().iter() {
            self.mark_spent_if_owned(nullifier);
        }

        recv_record_openings
    }

    /// Scan transactions in a block searching for owned record commitment and
    /// updating unconfirmed spent records
    /// This method do not scan collected fee record
    /// `uid_offset`: number of ledger records before this block is added to the
    /// ledger
    pub fn scan_block(
        &mut self,
        block: &MockBlock,
        recv_memos: &[&[ReceiverMemo]],
        uid_offset: u64,
    ) -> Vec<RecordOpening> {
        assert_eq!(block.txns.len(), recv_memos.len());
        let mut uid_offset = uid_offset;
        let mut owned_records_openings = vec![];
        // scan each transaction in the block
        for (txn, recv_memos) in block.txns.iter().zip(recv_memos.iter()) {
            let mut txn_owned_record_openings = self.scan_txn(txn, recv_memos, uid_offset);
            owned_records_openings.append(&mut txn_owned_record_openings);
            uid_offset += txn.output_len() as u64;
        }
        owned_records_openings
    }

    fn get_proving_key(
        &self,
        n_inputs: usize,
        n_outputs: usize,
    ) -> Option<&TransferProvingKey<'a>> {
        let description = format!("Xfr_{}_{}", n_inputs, n_outputs);
        self.proving_keys.get(&description)
    }

    fn compute_proving_key(&self, n_inputs: usize, n_outputs: usize) -> TransferProvingKey<'a> {
        let (proving_key, ..) = preprocess(&self.srs, n_inputs, n_outputs, TREE_DEPTH).unwrap();
        proving_key
    }

    fn insert_proving_key(
        &mut self,
        n_inputs: usize,
        n_outputs: usize,
        proving_key: TransferProvingKey<'a>,
    ) {
        let description = format!("Xfr_{}_{}", n_inputs, n_outputs);
        self.proving_keys.insert(description, proving_key);
    }

    /// find a record and corresponding uid on the native asset type with enough
    /// funds to pay transaction fee
    fn find_record_for_fee(&self, fee: u64) -> Result<(RecordOpening, u64)> {
        let unspent_native_assets = self
            .unspent_records
            .get(&AssetDefinition::native().code)
            .ok_or(anyhow!("No balance in native asset"))?;
        let ro = unspent_native_assets
            .iter()
            .find(|record| record.0.amount >= fee)
            .ok_or(anyhow!(
                "No single native asset record has sufficient amount for intended fee"
            ))?
            .clone();
        Ok(ro)
    }

    /// find a set of record and corresponding uids on a given asset type that
    /// adds up enough funds to transfer.
    /// Returns the list of (record opening, uid), and the change (difference)
    /// between its total value minus the requested `amount`.
    fn find_records(
        &self,
        asset_code: &AssetCode,
        amount: u64,
    ) -> Result<(Vec<(RecordOpening, u64)>, u64)> {
        let mut result = vec![];
        let mut current_amount = 0u64;
        let unspent_records = self
            .unspent_records
            .get(asset_code)
            .ok_or(anyhow!("No balance in native asset"))?;

        for unspent_record in unspent_records {
            current_amount += unspent_record.0.amount;
            result.push(unspent_record.clone());
            if current_amount >= amount {
                return Ok((result, current_amount - amount));
            }
        }
        Err(anyhow!(
            "Not enough balance, requested: {}, only got: {}",
            amount,
            current_amount
        ))
    }

    /// create transfer note that spend owned native assets
    /// `output_keys_and_amounts`: list of receiver keys and amounts
    /// `merkle_tree`: merkle tree containing input record commitments to spend
    pub fn spend_native<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        output_addresses_and_amounts: &[(UserPubKey, u64)],
        fee: u64,
        merkle_tree_oracle: &MerkleTree<BaseField>,
    ) -> Result<(TransferNote, Vec<ReceiverMemo>, Signature<CurveParam>)> {
        let total_output_amount: u64 = output_addresses_and_amounts
            .iter()
            .fold(0, |acc, (_, amount)| acc + amount)
            + fee;

        // find input records of the asset type to spent
        let (mut input_records, _change) =
            self.find_records(&AssetCode::native(), total_output_amount)?;

        // add dummy record as an example
        let (ro_dummy, dummy_keypair) = RecordOpening::dummy(rng, FreezeFlag::Unfrozen);
        input_records.push((ro_dummy, 0));

        // prepare inputs
        let mut inputs = vec![];
        for (ro, uid) in input_records {
            if ro.is_dummy() {
                let acc_member_witness = AccMemberWitness::dummy(TREE_DEPTH);
                inputs.push(TransferNoteInput {
                    ro,
                    acc_member_witness,
                    owner_keypair: &dummy_keypair,
                    cred: None,
                });
                continue;
            }
            let nullifier = self.keypair.nullify(
                ro.asset_def.policy_ref().freezer_pub_key(),
                uid,
                &RecordCommitment::from(&ro),
            );
            self.unconfirmed_spent_records
                .insert(nullifier, (ro.clone(), uid));

            let acc_member_witness = AccMemberWitness::lookup_from_tree(merkle_tree_oracle, uid)
                .expect_ok()
                .unwrap()
                .1;

            inputs.push(TransferNoteInput {
                ro,
                acc_member_witness,
                owner_keypair: &self.keypair,
                cred: None,
            });
        }

        // prepare output, potentially include a fee change
        let mut outputs = vec![];
        for (pub_key, amount) in output_addresses_and_amounts {
            outputs.push(RecordOpening::new(
                rng,
                *amount,
                AssetDefinition::native(),
                pub_key.clone(),
                FreezeFlag::Unfrozen,
            ));
        }

        // retrieve or compute proving key and generate transfer note
        let num_inputs = inputs.len();
        let num_outputs = outputs.len() + 1; // add fee change output
        let proving_key = self.get_proving_key(num_inputs, num_outputs);
        let (note, keypair, fee_change_ro) = match proving_key {
            Some(key) => TransferNote::generate_native(
                rng,
                inputs,
                &outputs,
                fee,
                UNEXPIRED_VALID_UNTIL,
                key,
            )?,
            None => {
                let proving_key = self.compute_proving_key(num_inputs, num_outputs);
                let r = TransferNote::generate_native(
                    rng,
                    inputs,
                    &outputs,
                    fee,
                    UNEXPIRED_VALID_UNTIL,
                    &proving_key,
                )?;
                self.insert_proving_key(num_inputs, num_outputs, proving_key);
                r
            },
        };
        let recv_memos: Result<Vec<_>, TxnApiError> = outputs
            .iter()
            .map(|ro| ReceiverMemo::from_ro(rng, ro, &[]))
            .collect();
        let recv_memos = recv_memos?;
        let sig = sign_receiver_memos(&keypair, &recv_memos)?;
        self.unconfirmed_fee_chg_records.insert(fee_change_ro);
        Ok((note, recv_memos, sig))
    }

    /// create transfer note that spend owned non-native assets
    /// `asset_def`: the asset definition of the asset being transferred
    /// `output_keys_and_amounts`: list of receiver keys and amounts
    /// `merkle_tree`: merkle tree containing input record commitments to spend
    pub fn spend_non_native<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        asset_def: &AssetDefinition,
        output_addresses_and_amounts: &[(UserPubKey, u64)],
        fee: u64,
        merkle_tree_oracle: &MerkleTree<BaseField>,
    ) -> Result<(TransferNote, Vec<ReceiverMemo>, Signature<CurveParam>)> {
        assert_ne!(
            *asset_def,
            AssetDefinition::native(),
            "call `spend_native()` instead"
        );
        let total_output_amount: u64 = output_addresses_and_amounts
            .iter()
            .fold(0, |acc, (_, amount)| acc + amount);

        let (fee_ro, fee_uid) = self.find_record_for_fee(fee)?;
        {
            // update wallet about deduction of native asset for fee
            let nullifier = self.keypair.nullify(
                fee_ro.asset_def.policy_ref().freezer_pub_key(),
                fee_uid,
                &RecordCommitment::from(&fee_ro),
            );
            self.unconfirmed_spent_records
                .insert(nullifier, (fee_ro.clone(), fee_uid));
        }
        let fee_input = FeeInput {
            ro: fee_ro,
            acc_member_witness: AccMemberWitness::lookup_from_tree(merkle_tree_oracle, fee_uid)
                .expect_ok()
                .unwrap()
                .1,
            owner_keypair: &self.keypair,
        };

        let (txn_fee_info, fee_chg_ro) = TxnFeeInfo::new(rng, fee_input, fee).unwrap();
        // find input records of the asset type to spent
        let (mut input_records, change) =
            self.find_records(&asset_def.code, total_output_amount)?;

        // add dummy record as an example
        let (dummy_ro, dummy_keypair) = RecordOpening::dummy(rng, FreezeFlag::Unfrozen);
        input_records.push((dummy_ro, 0));

        let mut inputs = vec![];
        let mut to_spend_records = vec![];
        for (ro, uid) in input_records.into_iter() {
            if ro.is_dummy() {
                let witness = AccMemberWitness::dummy(TREE_DEPTH);
                inputs.push(TransferNoteInput {
                    ro,
                    acc_member_witness: witness,
                    owner_keypair: &dummy_keypair,
                    cred: None,
                });
                continue;
            }
            let witness = AccMemberWitness::lookup_from_tree(merkle_tree_oracle, uid)
                .expect_ok()
                .unwrap()
                .1;
            let nullifier = self.keypair.nullify(
                ro.asset_def.policy_ref().freezer_pub_key(),
                uid,
                &RecordCommitment::from(&ro),
            );
            to_spend_records.push((nullifier, ro.clone(), uid));

            inputs.push(TransferNoteInput {
                ro,
                acc_member_witness: witness,
                owner_keypair: &self.keypair,
                cred: self.credential.clone(),
            });
        }

        let mut outputs = vec![];
        for (pub_key, amount) in output_addresses_and_amounts {
            outputs.push(RecordOpening::new(
                rng,
                *amount,
                asset_def.clone(),
                pub_key.clone(),
                FreezeFlag::Unfrozen,
            ));
        }
        // change in the asset type being transfered (not fee change)
        if change > 0 {
            let change_ro = RecordOpening::new(
                rng,
                change,
                asset_def.clone(),
                self.pub_key(),
                FreezeFlag::Unfrozen,
            );
            outputs.push(change_ro);
        }
        // retrieve or compute proving key and generate transfer note
        let num_inputs = inputs.len() + 1; // inputs didn't count fee
        let num_outputs = outputs.len() + 1; // outputs didn't count fee change
        let valid_until = match &self.credential {
            None => UNEXPIRED_VALID_UNTIL,
            Some(cred) => cred.expiry(),
        };
        let proving_key = self.get_proving_key(num_inputs, num_outputs);
        let (note, sig_keypair) = match proving_key {
            Some(key) => TransferNote::generate_non_native(
                rng,
                inputs,
                &outputs,
                txn_fee_info,
                valid_until,
                key,
                vec![],
            )?,
            None => {
                let proving_key = self.compute_proving_key(num_inputs, num_outputs);
                let r = TransferNote::generate_non_native(
                    rng,
                    inputs,
                    &outputs,
                    txn_fee_info,
                    valid_until,
                    &proving_key,
                    vec![],
                )?;
                self.insert_proving_key(num_inputs, num_outputs, proving_key);
                r
            },
        };

        let recv_memos: Result<Vec<_>, TxnApiError> = outputs
            .iter()
            .map(|ro| ReceiverMemo::from_ro(rng, ro, &[]))
            .collect();
        let recv_memos = recv_memos?;
        let sig = sign_receiver_memos(&sig_keypair, &recv_memos)?;

        // mark unconfirmed spent
        for (nullifier, ro, uid) in to_spend_records {
            self.mark_unconfirmed_spent(nullifier, ro, uid);
        }
        self.unconfirmed_fee_chg_records.insert(fee_chg_ro);
        Ok((note, recv_memos, sig))
    }

    /// change state of record to unconfirmed spent
    pub fn mark_unconfirmed_spent(&mut self, nullifier: Nullifier, ro: RecordOpening, uid: u64) {
        self.unconfirmed_spent_records.insert(nullifier, (ro, uid));
    }

    /// change state of record to spent
    #[inline]
    pub fn mark_spent_if_owned(&mut self, nullifier: &Nullifier) {
        // check unconfirmed_spent
        match self.unconfirmed_spent_records.get(nullifier) {
            Some(record) => {
                self.unspent_records
                    .get_mut(&record.0.asset_def.code)
                    .unwrap()
                    .remove(record);
                self.unconfirmed_spent_records.remove(nullifier);
            },
            None => {},
        }
        // check if frozen
        for records in self.unspent_records.values_mut() {
            let mut record_to_remove = None;
            for record_uid in records.iter() {
                let freezer_key = record_uid.0.asset_def.policy_ref().freezer_pub_key();
                if self.keypair.nullify(
                    &freezer_key,
                    record_uid.1,
                    &RecordCommitment::from(&record_uid.0),
                ) == *nullifier
                {
                    record_to_remove = Some(record_uid.clone());
                }
            }
            match record_to_remove.as_ref() {
                None => {},
                Some(record_uid) => {
                    records.remove(record_uid);
                    return;
                },
            }
        }
    }
}

pub struct AssetIssuerMock<'a> {
    wallet: SimpleUserWalletMock<'a>,
    // proving key for generating mint transaction
    proving_key: MintProvingKey<'a>,
    // maps defined asset code to asset definition, seed and description of the asset
    defined_assets: HashMap<AssetCode, (AssetDefinition, AssetCodeSeed, Vec<u8>)>,
}

impl<'a> AssetIssuerMock<'a> {
    /// AssetIssuerMock struct constructor: Generate a user wallet and initiate
    /// set of defined assets
    pub fn new<R: CryptoRng + RngCore>(
        rng: &mut R,
        srs: &'a UniversalParam,
    ) -> AssetIssuerMock<'a> {
        let wallet = SimpleUserWalletMock::generate(rng, srs);
        let (proving_key, ..) = jf_cap::proof::mint::preprocess(&wallet.srs, TREE_DEPTH).unwrap();

        AssetIssuerMock {
            wallet,
            proving_key,
            defined_assets: HashMap::new(),
        }
    }

    /// define a new asset and store secret info for minting
    pub fn new_asset_definition<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        description: &[u8],
        policy: AssetPolicy,
    ) -> AssetCode {
        let seed = AssetCodeSeed::generate(rng);
        let code = AssetCode::new_domestic(seed, description);
        let asset_definition = AssetDefinition::new(code, policy).unwrap();
        self.defined_assets
            .insert(code, (asset_definition, seed, description.to_vec()));
        code
    }

    /// Retrieve asset definition
    pub fn asset_defintion(&self, code: &AssetCode) -> Option<AssetDefinition> {
        self.defined_assets.get(code).map(|(def, ..)| def.clone())
    }

    /// create a mint note that assign asset to an owner
    pub fn mint<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        fee: u64,
        asset_code: &AssetCode,
        amount: u64,
        owner: UserPubKey,
        merkle_tree_oracle: &MerkleTree<BaseField>,
    ) -> Result<(MintNote, Signature<CurveParam>, ReceiverMemo)> {
        let (fee_ro, uid) = self.wallet.find_record_for_fee(fee)?;
        let fee_record_nullifier =
            self.wallet
                .keypair
                .nullify(&Default::default(), uid, &RecordCommitment::from(&fee_ro));
        self.wallet
            .mark_unconfirmed_spent(fee_record_nullifier, fee_ro.clone(), uid);
        let acc_member_witness = AccMemberWitness::lookup_from_tree(merkle_tree_oracle, uid)
            .expect_ok()
            .unwrap()
            .1;
        let (asset_def, seed, asset_description) = self
            .defined_assets
            .get(asset_code)
            .ok_or(anyhow!("No balance under the asset code"))?;
        let mint_record = RecordOpening {
            amount,
            asset_def: asset_def.clone(),
            pub_key: owner,
            freeze_flag: FreezeFlag::Unfrozen,
            blind: BlindFactor::rand(rng),
        };
        let mint_recv_memo = [ReceiverMemo::from_ro(rng, &mint_record, &[])?];
        let fee_input = FeeInput {
            ro: fee_ro,
            acc_member_witness,
            owner_keypair: &self.wallet.keypair,
        };
        let (txn_fee_info, fee_chg_ro) = TxnFeeInfo::new(rng, fee_input, fee).unwrap();
        let (min_note, sig_key) = jf_cap::mint::MintNote::generate(
            rng,
            mint_record,
            *seed,
            asset_description.as_slice(),
            txn_fee_info,
            &self.proving_key,
        )?;
        self.wallet.unconfirmed_fee_chg_records.insert(fee_chg_ro);
        let sig = sign_receiver_memos(&sig_key, &mint_recv_memo)?;
        Ok((min_note, sig, mint_recv_memo[0].clone()))
    }

    /// scan transaction to mark spent fee record
    pub fn scan_txn(
        &mut self,
        txn: &TransactionNote,
        receiver_memos: &[ReceiverMemo],
        uid_offset: u64,
    ) {
        self.wallet.scan_txn(txn, receiver_memos, uid_offset);
    }
}
/// This tests shows how to generate and verify transfer notes transferring the
/// native asset. It also lays out how receiver can open and spend received
/// records for his key. Specifically this test does:
///  1. simulate ledger state with single unspent record on the native asset
///  2. create a transfer note that spends this record
///  3. simulate verifier node validating the transfer note
///    3.1: check note input nullifier is not in the ledger state
///    3.2: verify transfer note
///    3.3: verify receiver memos signature
///    3.4: update state with transfer note output commitments
///    3.5: update state with input nullifiers
///  4. receiver decrypts receiver memos into new record
///  5. receiver spends received record
///  6. simulate verifier node again on new transfer note
#[test]
pub fn example_native_asset_transfer() {
    let rng = &mut ark_std::test_rng();
    // 0. setting up params
    let mut ledger_state = LedgerStateMock::new();
    let srs = mock_retrieve_srs();

    // 1. setting up state, one input owned by a single user
    let mut sender_wallet = SimpleUserWalletMock::generate(rng, &srs);
    let sender_pub_key = sender_wallet.pub_key();

    let mut receiver_wallet = SimpleUserWalletMock::generate(rng, &srs);
    let receiver_pub_key = receiver_wallet.pub_key();

    let mint_amount = 10;
    let (record_opening_in, uid) =
        ledger_state.mock_mint_native_asset(rng, sender_pub_key.clone(), mint_amount);
    sender_wallet.add_record_opening(record_opening_in, uid);
    assert_eq!(
        sender_wallet.available_funds(&AssetCode::native()),
        mint_amount
    );

    let fee = 1;
    let change_back = 2;
    let (xfr_note, recv_memos, recv_memos_sig) = sender_wallet
        .spend_native(
            rng,
            &[(receiver_pub_key.clone(), mint_amount - fee - change_back)],
            fee,
            &ledger_state.mt,
        )
        .unwrap();

    // validator
    let uid_offset = ledger_state.next_uid();
    let mut validator = ValidatorMock::new(rng, &srs);
    let mock_timestamp = 10; // simulate current timestamp
    validator
        .validate_single_xfr_note(&ledger_state, &xfr_note, mock_timestamp)
        .and_then(|_| Ok(ledger_state.insert_transfer_note(&xfr_note, true)))
        .unwrap();

    // Bulletin board or users verify receiver memos
    let txn: TransactionNote = xfr_note.into();
    txn.verify_receiver_memos_signature(&recv_memos, &recv_memos_sig)
        .unwrap();
    // 4. receivers: 1 intended receiver, 2 change to sender
    let recv_record_openings = receiver_wallet.scan_txn(&txn, &recv_memos, uid_offset);
    assert_eq!(
        receiver_wallet.available_funds(&AssetCode::native()),
        mint_amount - fee - change_back
    );
    assert_eq!(recv_record_openings.len(), 1);
    let record_opening_recv = &recv_record_openings[0];
    assert_eq!(record_opening_recv.amount, mint_amount - fee - change_back);
    assert_eq!(record_opening_recv.freeze_flag, FreezeFlag::Unfrozen);
    assert_eq!(record_opening_recv.asset_def, AssetDefinition::native());
    assert_eq!(record_opening_recv.pub_key, receiver_pub_key);

    assert!(!sender_wallet.unconfirmed_fee_chg_records.is_empty());
    sender_wallet.scan_txn(&txn, &recv_memos, uid_offset);
    assert_eq!(
        sender_wallet.available_funds(&AssetCode::native()),
        change_back
    );
    assert!(sender_wallet.unconfirmed_fee_chg_records.is_empty());

    // 5. receiver spends record by sending back 8 units to user0
    let (xfr_note2, recv_memos2, _recv_memos_sig2) = receiver_wallet
        .spend_native(
            rng,
            &[(sender_pub_key, mint_amount - 2 * fee - change_back)],
            fee,
            &ledger_state.mt,
        )
        .unwrap();
    // validator
    let mock_timestamp = 11; // simulate current timestamp
    validator
        .validate_single_xfr_note(&ledger_state, &xfr_note2, mock_timestamp)
        .and_then(|_| Ok(ledger_state.insert_transfer_note(&xfr_note2, true)))
        .unwrap();

    let uid_offset = ledger_state.next_uid();
    let txn2 = xfr_note2.into();
    sender_wallet.scan_txn(&txn2, &recv_memos2, uid_offset);
    assert_eq!(
        sender_wallet.available_funds(&AssetCode::native()),
        mint_amount - 2 * fee
    );
    receiver_wallet.scan_txn(&txn2, &recv_memos2, uid_offset);
    assert_eq!(receiver_wallet.available_funds(&AssetCode::native()), 0);
}

/// This tests shows how to generate and verify transfer notes transferring non
/// native asset.  1. simulate ledger state with two unspent records, one with a
/// native asset used to pay fees     and one with another asset with no
/// associated policy.  2. create a transfer note that spends the records by
/// transferring the second record and     paying fee with native asset record.
///  3. simulate verifier node validating the transfer note
///    3.1: check note input nullifier is not in the ledger state
///    3.2: verify transfer note
///    3.3: verify receiver memos signature
///    3.4: update state with transfer note output commitments
///    3.5: update state with input nullifiers
///  4. receiver decrypts receiver memos into new record
#[test]
pub fn example_non_native_asset_transfer() {
    let rng = &mut ark_std::test_rng();
    // 0. setting up params
    let mut ledger_state = LedgerStateMock::new();
    let srs = mock_retrieve_srs();

    // 1. setting up state, two inputs owned by a single user
    let mut sender_wallet = SimpleUserWalletMock::generate(rng, &srs);
    let mut receiver_wallet = SimpleUserWalletMock::generate(rng, &srs);
    let recv_pub_key = receiver_wallet.pub_key();
    assert_ne!(recv_pub_key, sender_wallet.pub_key());
    let native_amount = 10;
    let non_native_amount = 15;

    let (asset_code, ..) = AssetCode::random(rng);
    let policy = AssetPolicy::default();
    let asset_definition = AssetDefinition::new(asset_code, policy).unwrap();

    let (record_opening_in_fee, uid) =
        ledger_state.mock_mint_native_asset(rng, sender_wallet.pub_key(), native_amount);
    sender_wallet.add_record_opening(record_opening_in_fee, uid);

    let (record_opening_in, uid) = ledger_state.mock_mint_non_native_asset(
        rng,
        sender_wallet.pub_key(),
        non_native_amount,
        asset_definition.clone(),
    );
    sender_wallet.add_record_opening(record_opening_in, uid);

    let fee = 2;
    let (xfr_note, recv_memos, recv_memos_sig) = sender_wallet
        .spend_non_native(
            rng,
            &asset_definition,
            &[(recv_pub_key.clone(), non_native_amount)],
            fee,
            &ledger_state.mt,
        )
        .unwrap();

    let uid_offset = ledger_state.next_uid();

    // xfr note validation
    let mut validator = ValidatorMock::new(rng, &srs);
    let mock_timestamp = 10; // simulate current timestamp
    validator
        .validate_single_xfr_note(&ledger_state, &xfr_note, mock_timestamp)
        .and_then(|_| Ok(ledger_state.insert_transfer_note(&xfr_note, true)))
        .unwrap();

    // Bulleting board or users verify receiver memos
    let txn_note: TransactionNote = xfr_note.into();
    txn_note
        .verify_receiver_memos_signature(&recv_memos, &recv_memos_sig)
        .unwrap();

    sender_wallet.scan_txn(&txn_note, &recv_memos, uid_offset);
    assert_eq!(
        sender_wallet.available_funds(&AssetCode::native()),
        native_amount - fee
    );
    // receiver retrieve record opening
    assert_eq!(
        receiver_wallet
            .scan_txn(&txn_note, &recv_memos, uid_offset)
            .len(),
        1
    );
    assert_eq!(
        receiver_wallet.available_funds(&asset_definition.code),
        non_native_amount
    );
}

/// This tests shows how to generate and verify transfer notes transferring non
/// native asset with an viewer policy on records' opening.
///  1. simulate ledger state with two unspent records, one with a
///     native asset used to pay fees
///     and one with another asset with associated policy viewing policy.
///  2. create a transfer note that spends the records by transferring the
/// second record and     paying fee with native asset record.
///  3. simulate verifier node validating the transfer note
///    3.1: check note input nullifier is not in the ledger state
///    3.2: verify transfer note
///    3.3: verify receiver memos signature
///    3.4: update state with transfer note output commitments
///    3.5: update state with input nullifiers
///  4. Viewer decrypts viewing memos
#[test]
pub fn example_test_viewed_asset_transfer() {
    let rng = &mut ark_std::test_rng();
    // 0. setting up params
    let mut ledger_state = LedgerStateMock::new();
    let srs = mock_retrieve_srs();

    // 1. setting up state, two inputs owned by a single user
    let mut sender_wallet = SimpleUserWalletMock::generate(rng, &srs);
    let mut receiver_wallet = SimpleUserWalletMock::generate(rng, &srs);
    let recv_pub_key = receiver_wallet.pub_key();
    let native_amount = 10;
    let non_native_amount = 15;

    let viewer_keypair = ViewerKeyPair::generate(rng);
    let policy = AssetPolicy::default()
        .set_viewer_pub_key(viewer_keypair.pub_key())
        .reveal_record_opening()
        .unwrap();
    let (code, ..) = AssetCode::random(rng);
    let asset_def = AssetDefinition::new(code, policy.clone()).unwrap();
    let viewer = ViewerMock::new(viewer_keypair, asset_def.clone());

    let (record_opening_in_fee, uid) =
        ledger_state.mock_mint_native_asset(rng, sender_wallet.pub_key(), native_amount);
    sender_wallet.add_record_opening(record_opening_in_fee, uid);

    let (record_opening_in, uid) = ledger_state.mock_mint_non_native_asset(
        rng,
        sender_wallet.pub_key(),
        non_native_amount,
        asset_def.clone(),
    );
    sender_wallet.add_record_opening(record_opening_in.clone(), uid);

    let fee = 2;
    let (xfr_note, recv_memos, recv_memos_sig) = sender_wallet
        .spend_non_native(
            rng,
            &asset_def,
            &[(recv_pub_key.clone(), non_native_amount)],
            fee,
            &ledger_state.mt,
        )
        .unwrap();

    let mt_size_prev = ledger_state.next_uid();

    // xfr note validation
    let mut validator = ValidatorMock::new(rng, &srs);
    let mock_timestamp = 10; // simulate current timestamp
    validator
        .validate_single_xfr_note(&ledger_state, &xfr_note, mock_timestamp)
        .and_then(|_| Ok(ledger_state.insert_transfer_note(&xfr_note, true)))
        .unwrap();

    // viewer
    let (input_visible_data, output_visible_data) =
        viewer.scan_xfr(&xfr_note, mt_size_prev).unwrap();
    assert_eq!(input_visible_data.len(), 1);
    assert_eq!(output_visible_data.len(), 1);

    // Bulleting board or users verify receiver memos
    let txn: TransactionNote = xfr_note.into();
    txn.verify_receiver_memos_signature(&recv_memos, &recv_memos_sig)
        .unwrap();

    check_transfer_visible_data(
        &input_visible_data[0],
        viewer.asset_def.code,
        Some(sender_wallet.pub_key().address()),
        Some(non_native_amount),
        Some(record_opening_in.blind),
        vec![None; ATTRS_LEN],
    );

    let record_opening_recv = &receiver_wallet.scan_txn(&txn, &recv_memos, mt_size_prev)[0];

    check_transfer_visible_data(
        &output_visible_data[0].0,
        viewer.asset_def.code,
        Some(recv_pub_key.address()),
        Some(non_native_amount),
        Some(record_opening_recv.blind),
        vec![None; ATTRS_LEN],
    );

    // check balances
    assert_eq!(
        receiver_wallet.available_funds(&asset_def.code),
        non_native_amount
    );
    sender_wallet.scan_txn(&txn, &recv_memos, mt_size_prev);
    assert_eq!(
        sender_wallet.available_funds(&AssetCode::native()),
        native_amount - fee
    );
}

/// This tests shows how to generate and verify transfer notes transferring non
/// native asset with an viewer policy viewing credential attributes.
///  1. simulate ledger state with two unspent records, one with a
///     native asset used to pay fees
///     and one with another asset with associated policy
///     viewing credential attributed.
///  2. create a transfer note that spends the records by transferring the
/// second record and     paying fee with native asset record.
///  3. simulate verifier node validating the transfer note
///    3.1: check note input nullifier is not in the ledger state
///    3.2: verify transfer note
///    3.3: verify receiver memos signature
///    3.4: update state with transfer note output commitments
///    3.5: update state with input nullifiers
///  4. Viewer decrypts viewing memos
#[test]
pub fn example_viewed_non_native_asset_with_credentials() {
    let rng = &mut ark_std::test_rng();
    // 0. setting up params
    let mut ledger_state = LedgerStateMock::new();
    let srs = mock_retrieve_srs();

    // 1. setting up state, two inputs owned by a single user
    let mut sender_wallet = SimpleUserWalletMock::generate(rng, &srs);
    let mut receiver_wallet = SimpleUserWalletMock::generate(rng, &srs);
    let recv_pub_key = receiver_wallet.pub_key();
    let native_amount = 10;
    let non_native_amount = 15;

    let viewer_keypair = ViewerKeyPair::generate(rng);
    let cred_minter_keypair = CredIssuerKeyPair::generate(rng);
    let expiry = 10;
    let mut attributes = vec![];
    attributes.push(IdentityAttribute::new(b"attr0").unwrap());
    attributes.push(IdentityAttribute::new(b"attr1").unwrap());
    attributes.push(IdentityAttribute::new(b"attr2").unwrap());
    attributes.push(IdentityAttribute::new(b"attr3").unwrap());
    attributes.push(IdentityAttribute::new(b"attr4").unwrap());
    attributes.push(IdentityAttribute::new(b"attr5").unwrap());
    attributes.push(IdentityAttribute::new(b"attr6").unwrap());
    attributes.push(IdentityAttribute::new(b"attr7").unwrap());
    sender_wallet.set_credential(
        ExpirableCredential::create(
            sender_wallet.pub_key().address(),
            attributes,
            expiry,
            &cred_minter_keypair,
        )
        .unwrap(),
    );
    let policy = AssetPolicy::default()
        .set_viewer_pub_key(viewer_keypair.pub_key())
        .set_cred_creator_pub_key(cred_minter_keypair.pub_key())
        .reveal_record_opening()
        .unwrap()
        .reveal_ith_attribute(0)
        .unwrap()
        .reveal_ith_attribute(4)
        .unwrap();
    let (code, ..) = AssetCode::random(rng);
    let asset_def = AssetDefinition::new(code, policy.clone()).unwrap();
    let viewer = ViewerMock::new(viewer_keypair, asset_def.clone());

    let (record_opening_in_fee, uid) =
        ledger_state.mock_mint_native_asset(rng, sender_wallet.pub_key(), native_amount);
    sender_wallet.add_record_opening(record_opening_in_fee, uid);

    let (record_opening_in, uid) = ledger_state.mock_mint_non_native_asset(
        rng,
        sender_wallet.pub_key(),
        non_native_amount,
        asset_def.clone(),
    );
    sender_wallet.add_record_opening(record_opening_in.clone(), uid);

    let fee = 2;
    let (xfr_note, recv_memos, recv_memos_sig) = sender_wallet
        .spend_non_native(
            rng,
            &asset_def,
            &[(recv_pub_key.clone(), non_native_amount)],
            fee,
            &ledger_state.mt,
        )
        .unwrap();

    let mt_size_prev = ledger_state.next_uid();

    // xfr note validation
    let mut validator = ValidatorMock::new(rng, &srs);
    let mock_timestamp = expiry; // simulate current timestamp
    validator
        .validate_single_xfr_note(&ledger_state, &xfr_note, mock_timestamp)
        .and_then(|_| Ok(ledger_state.insert_transfer_note(&xfr_note, true)))
        .unwrap();

    // current timestamp greater then credential expiration time
    let mock_timestamp = expiry + 1;
    assert!(validator
        .validate_single_xfr_note(&ledger_state, &xfr_note, mock_timestamp)
        .is_err());

    // viewer
    let (input_visible_data, output_visible_data) =
        viewer.scan_xfr(&xfr_note, mt_size_prev).unwrap();
    assert_eq!(input_visible_data.len(), 1);
    assert_eq!(output_visible_data.len(), 1);

    // Bulleting board or users verify receiver memos
    let txn: TransactionNote = xfr_note.into();
    txn.verify_receiver_memos_signature(&recv_memos, &recv_memos_sig)
        .unwrap();

    let record_opening_recv = &receiver_wallet.scan_txn(&txn, &recv_memos, mt_size_prev)[0];

    let mut expected_attributes = vec![None; ATTRS_LEN];
    expected_attributes[0] = Some(IdentityAttribute::new(b"attr0").unwrap());
    expected_attributes[4] = Some(IdentityAttribute::new(b"attr4").unwrap());
    check_transfer_visible_data(
        &input_visible_data[0],
        viewer.asset_def.code,
        Some(sender_wallet.pub_key().address()),
        Some(non_native_amount),
        Some(record_opening_in.blind),
        expected_attributes,
    );
    check_transfer_visible_data(
        &output_visible_data[0].0,
        viewer.asset_def.code,
        Some(receiver_wallet.pub_key().address()),
        Some(non_native_amount),
        Some(record_opening_recv.blind),
        vec![None; ATTRS_LEN],
    );
}

// Only use for testing
fn check_transfer_visible_data(
    data: &ViewableData,
    expected_code: AssetCode,
    expected_user_address: Option<UserAddress>,
    expected_amount: Option<u64>,
    expected_blind_factor: Option<BlindFactor>,
    expected_attributes: Vec<Option<IdentityAttribute>>,
) {
    assert_eq!(data.asset_code, expected_code);
    assert_eq!(data.user_address, expected_user_address);
    assert_eq!(data.amount, expected_amount);
    assert_eq!(data.blinding_factor, expected_blind_factor);
    assert_eq!(data.attributes, expected_attributes);
}

#[test]
fn example_fee_collection_and_batch_verification() {
    let rng = &mut ark_std::test_rng();
    // 0. setting up params
    let mut ledger_state = LedgerStateMock::new();
    let srs = mock_retrieve_srs();

    // setting up wallets
    let mut senders_wallets = vec![];
    let amounts = [10u64, 20, 30, 40];
    for _ in amounts.iter() {
        let user_wallet = SimpleUserWalletMock::generate(rng, &srs);
        senders_wallets.push(user_wallet);
    }
    let receiver_pub_key = SimpleUserWalletMock::generate(rng, &srs).pub_key();

    // mocking ledger state and add assets to wallets
    for (amount, wallet) in amounts.iter().zip(senders_wallets.iter_mut()) {
        let (record_opening, uid) =
            ledger_state.mock_mint_native_asset(rng, wallet.pub_key(), *amount);
        wallet.add_record_opening(record_opening, uid);
    }

    // generate set of xfr_notes
    let mut xfr_notes = vec![];
    let fee = 1;
    for (wallet, amount) in senders_wallets.iter_mut().zip(amounts.iter()) {
        let (xfr_note, _recv_memos, _recv_memos_sig) = wallet
            .spend_native(
                rng,
                &[(receiver_pub_key.clone(), *amount - fee)],
                fee,
                &ledger_state.mt,
            )
            .unwrap();
        xfr_notes.push(xfr_note)
    }

    // batch validate xfr_notes
    let txns: Vec<_> = xfr_notes.into_iter().map(|x| x.into()).collect();
    let mut validator = ValidatorMock::new(rng, &srs);
    let mock_timestamp = 11;
    assert!(validator
        .validate_txns_batch(&ledger_state, &txns, mock_timestamp)
        .is_ok());

    // fee collection and block creation
    let ledger_len = ledger_state.next_uid();
    let mut block_proposer = ValidatorMock::new(rng, &srs);
    let (fee_record_opening, block, block_sig) = block_proposer
        .collect_fee_and_build_block(rng, txns)
        .unwrap();

    // network validates block and ledger is updated
    let now = 11;
    assert!(validator
        .validate_block(
            &ledger_state,
            &block,
            &block_sig,
            now,
            &block_proposer.wallet.pub_key()
        )
        .is_ok());
    ledger_state.insert_block(&block).unwrap();

    // block proposer inserts collected fee record
    block_proposer.wallet.add_record_opening(
        fee_record_opening,
        ledger_len + (block.txns.len() as u64) - 1,
    );
    assert_eq!(
        block_proposer.wallet.available_funds(&AssetCode::native()),
        fee * (amounts.len() as u64)
    );
}

#[test]
fn example_mint() {
    let rng = &mut ark_std::test_rng();
    // 0. setting up params
    let mut ledger_state = LedgerStateMock::new();
    let srs = mock_retrieve_srs();

    // setting up wallets
    let mut asset_creator = AssetIssuerMock::new(rng, &srs);
    let mut owner_wallet = SimpleUserWalletMock::generate(rng, &srs);
    let owner_pub_key = owner_wallet.pub_key();
    // initialize the wallet with some native asset to be used to pay txn fee
    {
        let amount = 10;
        let (init_balance_ro, uid) =
            ledger_state.mock_mint_native_asset(rng, asset_creator.wallet.pub_key(), amount);
        asset_creator
            .wallet
            .add_record_opening(init_balance_ro, uid);
    }

    // create/mint a new asset
    let mint_amount: u64 = 1000000;
    let asset_code = asset_creator.new_asset_definition(rng, b"BankX USD", AssetPolicy::default());
    let fee = 1;
    let (mint_note, _sig, fee_chg_recv_memo) = asset_creator
        .mint(
            rng,
            fee,
            &asset_code,
            mint_amount,
            owner_pub_key,
            &ledger_state.mt,
        )
        .unwrap();

    let recv_memos = [fee_chg_recv_memo];
    // block proposer validator
    let mut block_proposer = ValidatorMock::new(rng, &srs);
    let txns = vec![mint_note.into()];
    let now = 5;
    let uid_offset = ledger_state.next_uid();
    assert!(block_proposer
        .validate_txns_batch(&mut ledger_state, &txns, now)
        .is_ok());
    let (collected_fee_ro, block, block_sig) = block_proposer
        .collect_fee_and_build_block(rng, txns)
        .unwrap();

    // validators
    let mut network_validator = ValidatorMock::new(rng, &srs);
    assert!(network_validator
        .validate_block(
            &mut ledger_state,
            &block,
            &block_sig,
            now,
            &block_proposer.wallet.pub_key()
        )
        .is_ok());
    ledger_state.insert_block(&block).unwrap();

    // users update wallets
    block_proposer
        .wallet
        .add_record_opening(collected_fee_ro, uid_offset + (block.txns.len() as u64) - 1);
    assert_eq!(
        owner_wallet
            .scan_block(&block, &[&recv_memos], uid_offset)
            .len(),
        1
    );
    assert_eq!(owner_wallet.available_funds(&asset_code), mint_amount);
}

#[test]
fn example_freeze() {
    let rng = &mut ark_std::test_rng();
    // 0. setting up params
    let mut ledger_state = LedgerStateMock::new();
    let srs = mock_retrieve_srs();

    // setting up wallets
    let mut user1 = SimpleUserWalletMock::generate(rng, &srs); // sender
    let mut user2 = SimpleUserWalletMock::generate(rng, &srs); // receiver
    let native_amount = 10;
    let non_native_amount = 5;

    // set up freezer
    let (asset_code, _) = AssetCode::random(rng);
    let mut freezer = FreezerMock::generate(rng, &srs, asset_code);
    let asset_definition = freezer.asset_def();

    // mock mint native assets to user1 and freezer
    let (record_opening, uid) =
        ledger_state.mock_mint_native_asset(rng, user1.pub_key(), native_amount);
    user1.add_record_opening(record_opening, uid);
    let (record_opening, uid) =
        ledger_state.mock_mint_native_asset(rng, freezer.wallet.pub_key(), native_amount);
    freezer.wallet.add_record_opening(record_opening, uid);

    // mock mint non_native_asset to user 1
    let (record_opening, uid) = ledger_state.mock_mint_non_native_asset(
        rng,
        user1.pub_key(),
        non_native_amount,
        asset_definition.clone(),
    );
    user1.add_record_opening(record_opening, uid);

    // simulate freezer obtaining users public keys
    freezer.add_user_key(user1.pub_key());
    freezer.add_user_key(user2.pub_key());

    // check empty freezer status: no records to freeze
    check_freezer_status(&freezer, native_amount, &user2, 0, 0, 0, 0);

    let mut prev_uid_offset;
    let mut uid_offset = ledger_state.next_uid();

    // user1  transfer freezable asset to user2
    let fee = 1;
    let (xfr, recv_memos, _sig) = user1
        .spend_non_native(
            rng,
            &asset_definition,
            &[(user2.pub_key(), non_native_amount)],
            fee,
            &ledger_state.mt,
        )
        .unwrap();
    let timestamp = 1; // arbitrary: eg block height

    // network validates transfer
    let mut validator = ValidatorMock::new(rng, &srs);
    let block = {
        // block proposal, validation and ledger insertion
        let block_proposer = ValidatorMock::new(rng, &srs);
        let (_collected_fee_opening, block, block_sig) = block_proposer
            .collect_fee_and_build_block(rng, vec![xfr.into()])
            .unwrap();
        validator
            .validate_block(
                &ledger_state,
                &block,
                &block_sig,
                timestamp + 1,
                &block_proposer.wallet.pub_key(),
            )
            .unwrap();
        ledger_state.insert_block(&block).unwrap();
        prev_uid_offset = uid_offset;
        uid_offset = ledger_state.next_uid();
        block
    };

    // freezer scan transaction detecting freezable records
    freezer
        .scan_block(&block, &[&recv_memos], prev_uid_offset)
        .unwrap();
    check_freezer_status(&freezer, native_amount, &user2, 1, 0, 0, 0);
    // user2's funds available after scanning block
    assert_eq!(user2.available_funds(&asset_code), 0);
    user2.scan_block(&block, &[&recv_memos], prev_uid_offset);
    assert_eq!(user2.available_funds(&asset_code), non_native_amount);

    // freezer freezes user2 freezable records
    let (freeze_note, recv_memos, _sig) = freezer
        .freeze_user(rng, &user2.pub_key().address(), fee, &ledger_state.mt)
        .unwrap();

    check_freezer_status(&freezer, native_amount, &user2, 1, 0, 1, 0);

    let block = {
        // block proposal, validation and ledger insertion
        let block_proposer = ValidatorMock::new(rng, &srs);
        let (_collected_fee_opening, block, block_sig) = block_proposer
            .collect_fee_and_build_block(rng, vec![freeze_note.into()])
            .unwrap();
        validator
            .validate_block(
                &ledger_state,
                &block,
                &block_sig,
                timestamp + 1,
                &block_proposer.wallet.pub_key(),
            )
            .unwrap();
        ledger_state.insert_block(&block).unwrap();
        prev_uid_offset = uid_offset;
        uid_offset = ledger_state.next_uid();
        block
    };

    freezer
        .scan_block(&block, &[&recv_memos], prev_uid_offset)
        .unwrap();

    check_freezer_status(&freezer, native_amount - fee, &user2, 0, 1, 0, 0);

    // user2's funds unavailable after scanning block
    user2.scan_block(&block, &[&recv_memos], prev_uid_offset);
    assert_eq!(user2.available_funds(&asset_code), 0);

    let (unfreeze_note, freeze_recv_memos, _sig) = freezer
        .unfreeze_user(rng, &user2.pub_key().address(), 1, &ledger_state.mt)
        .unwrap();

    check_freezer_status(&freezer, native_amount - fee, &user2, 0, 1, 0, 1);

    // add a minting note with another freezable record
    let mut creator = AssetIssuerMock::new(rng, &srs);
    let new_asset_policy = AssetPolicy::default()
        .set_viewer_pub_key(freezer.viewer.pub_key())
        .reveal_record_opening()
        .unwrap()
        .set_freezer_pub_key(freezer.pub_key());
    let new_asset_code = creator.new_asset_definition(rng, b"freezable asset", new_asset_policy);
    let (record, uid) =
        ledger_state.mock_mint_native_asset(rng, creator.wallet.pub_key(), native_amount);
    creator.wallet.add_record_opening(record, uid);
    let new_asset_amount = 20u64;
    let (mint_note, _sig, fee_ch_recv_memo) = creator
        .mint(
            rng,
            fee,
            &new_asset_code,
            new_asset_amount,
            user1.pub_key(),
            &ledger_state.mt,
        )
        .unwrap();

    let mint_recv_memos = [fee_ch_recv_memo];

    let block = {
        // block proposal, validation and ledger insertion
        let block_proposer = ValidatorMock::new(rng, &srs);
        let (_collected_fee_opening, block, block_sig) = block_proposer
            .collect_fee_and_build_block(rng, vec![unfreeze_note.into(), mint_note.into()])
            .unwrap();
        validator
            .validate_block(
                &ledger_state,
                &block,
                &block_sig,
                timestamp + 1,
                &block_proposer.wallet.pub_key(),
            )
            .unwrap();
        ledger_state.insert_block(&block).unwrap();
        prev_uid_offset = uid_offset;
        block
    };

    freezer
        .scan_block(
            &block,
            &[&freeze_recv_memos, &mint_recv_memos],
            prev_uid_offset,
        )
        .unwrap();

    check_freezer_status(&freezer, native_amount - 2 * fee, &user2, 1, 0, 0, 0);
    check_freezer_status(&freezer, native_amount - 2 * fee, &user1, 1, 0, 0, 0);
    // check user 2 funds available again
    user2.scan_block(
        &block,
        &[&freeze_recv_memos, &mint_recv_memos],
        prev_uid_offset,
    );
    assert_eq!(user2.available_funds(&asset_code), non_native_amount);

    assert_eq!(user1.available_funds(&new_asset_code), 0);
    user1.scan_block(
        &block,
        &[&freeze_recv_memos, &mint_recv_memos],
        prev_uid_offset,
    );
    assert_eq!(user1.available_funds(&new_asset_code), new_asset_amount);
}

fn check_freezer_status(
    freezer: &FreezerMock,
    available_native_funds: u64,
    user: &SimpleUserWalletMock,
    user_freezable_records: usize,
    user_releasable_records: usize,
    unconfirmed_frozen: usize,
    unconfirmed_released: usize,
) {
    // check freezer state after scanning freezing note
    assert_eq!(
        freezer.wallet.available_funds(&AssetCode::native()),
        available_native_funds,
        "avilable funds for user, expected: {}, got: {}",
        available_native_funds,
        freezer.wallet.available_funds(&AssetCode::native()),
    );
    let n_freezable = match freezer.freezable_records.get(&user.pub_key().address()) {
        None => 0,
        Some(x) => x.len(),
    };
    assert_eq!(
        n_freezable, user_freezable_records,
        "total freezable records, expected: {}, got: {}",
        user_freezable_records, n_freezable,
    );
    let n_releasable = match freezer.releasable_records.get(&user.pub_key().address()) {
        None => 0,
        Some(x) => x.len(),
    };
    assert_eq!(
        n_releasable, user_releasable_records,
        "total releasable records, expected: {}, got: {}",
        user_releasable_records, n_releasable,
    );
    assert_eq!(
        freezer.unconfirmed_frozen_records.len(),
        unconfirmed_frozen,
        "total unconfirmed frozen records, expected: {}, got: {}",
        unconfirmed_frozen,
        freezer.unconfirmed_frozen_records.len(),
    );
    assert_eq!(
        freezer.unconfirmed_released_records.len(),
        unconfirmed_released,
        "total unconfirmed released records, expected: {}, got: {}",
        unconfirmed_released,
        freezer.unconfirmed_released_records.len(),
    );
}
