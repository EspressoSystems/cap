// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! API library for the _configurable asset policy_ system which allows for
//! issuance, transfers and (un)freezing of arbitrary asset that are fully
//! private, yet publicly verifiable and auditable. It is strongly recommended
//! to refer to at least the first two chapters of [Spec] for an introduction to
//! core concepts, data structures and main workflows.
//!
//! # Entities and Their Keys
//! As explained in Chapter 1.2 of [Spec], there are 5 main roles and all their
//! public/private key related materials can be found under the [keys] module.
//! Common actions involving a key can usually be found as associated methods
//! of the key struct -- e.g. for an auditor/tracer to decrypt memos for
//! him/her, use [`keys::AuditorKeyPair::open_transfer_audit_memo()`].
//!
//! # 3 Types of Transaction and Their Workflows
//! As explained in Chapter 2.1 of [Spec], we support 3 types of transaction
//! (txn) -- **transfer**, **mint** and **freeze**.
//!
//! While an actual transaction may contain extra information such as metadata
//! (timestamp), consensus related data etc., our APIs center around the core
//! body of a transaction which we call a [`TransactionNote`]. To generate or
//! verify a transaction note of a certain type, go to respective module under
//! the same type name -- e.g. [`transfer::TransferNote::generate_native()`] or
//! [`freeze::FreezeNote::verify()`].
//!
//! ## General Workflow
//! The "privacy-preserving" property of our payment system is largely
//! the result of how each transaction demonstrates its validity and how
//! validators/miners verify them.
//! Namely, in contrast to transaction on Ethereum, which put all necessary info
//! of a txn (amount, sender, receiver etc.) in the open to maintain public
//! verifiability, we utilize cryptographic proofs that can mathematically
//! attest to the "truth of any statement" -- statement such as "This txn
//! preserves the balance of total amount of inputs and outputs, plus all
//! senders are legitimate owners of their asset records ...".
//!
//! To generate such a proof, one would need to first settle the exact statement
//! and deterministically derive one _proving key_ and one _verifying key_ from
//! the statement, the former for the prover of the statement (i.e. the txn
//! creator) whereas the latter for the verifier of the statement (i.e. the
//! validators) -- this is called _preprocessing_, and for the validity
//! statement for each txn type, their APIs can be found under [proof] module.
//!
//! One more complication steming from the proof system we use is: before
//! preprocess any concrete statement, we need to retrieve a so-called
//! _universal parameter_ which will be needed during subsequent preprocessings.
//! Reason why it's called "universal" is because this parameter is independent
//! of the concrete statement of a bounded size.
//!
//! Therefore, the generic workflow or life cycle of a txn note is as follows:
//! 1. (during system setup) validators and users fetch the universal
//! parameter[^srs].
//! 2. sender of a txn runs the preprocessing function to get the proving key of
//! the correct txn type, providing the universal parameter.
//! 3. sender decides fee, then assembles all other necessary secret witnesses
//! necessary to generate the txn note, a list of _receiver memos_ (one for each
//! output) [^receiver memos] and a signature signed over the memos.
//! 4. upon receiving txn note, validators verify it.
//! 5. for public bulletin board maintainers, verify the signature against the
//! list of memos and the note, and only publish the list of memos if
//! verification passed.
//! 6. receivers scan the bulletin board to try to decrypt newly added memos to
//! find record openings designated to him which enables him to spend them
//! further.
//!
//! ## Proving Keys & Verifying Keys
//! Ideally, users and validators should have a copy of the proving and
//! verifying keys locally as binary files, and load to memory on demand --
//! utility functions to help with this can be found under [parameters] module.
//!
//! However, currently, deserializing these parameter files takes longer than
//! reproducing them, thus we recommend only loading the universal parameter via
//! [`parameters::load_universal_parameter()`] and then **generate proving keys
//! and verifying keys on demand**. For example, for transfer txn, invoke
//! [`proof::transfer::preprocess()`] inputting the universal parameter you just
//! loaded to memory [^de problem].
//!
//! Additional note: there's potentially different proving/verifying keys for
//! the same txn type but with different number of inputs, outputs and depth of
//! the Merkle Tree accumulating record commitments. Thus, you have to be
//! careful to use the correct ones, or else you will get an Error.
//!
//! ## Transaction Note Generation: Fee and Fee Change
//! Each transaction could decide to include a non-negative fee in _native asset
//! type_.
//! This is achieved by providing a [`structs::FeeInput`] and specify the
//! actual amount of `fee: u64` to pay whenever you generate a note.
//! Be careful: the value of `FeeInput` has to be no smaller than `fee`, and the
//! difference is _fee change_ which would be included in the output with the
//! same owner as the fee payer.
//!
//! ## Transaction Note Generation: Assembling All Necessary Witnesses
//! There are a dozen of secret witness data required to feed into the txn note
//! generation as inputs, all necessary data structures can be found under
//! [structs] module, and the best place to learn about how to assemble those
//! input parameters is through our integration test examples.
//!
//! Let us strongly recommend again: **please read example workflows in
//! [integration test]!**
//!
//! ## Transaction Note Verification: Batch Verification
//! In addition to verification on a single txn note, we also offers batch
//! verification which has lower amortized cost -- this is offered at
//! [`txn_batch_verify()`].
//!
//! # Transaction Fee Collection for Validators
//! At the ledger level, when a validator proposes a block containing a list of
//! transactions, the validator is entitled to claim all the txn fee specified
//! within the block. We have deviced two APIs regarding txn fee collection:
//! - for block proposer: [`prepare_txns_fee_record()`]
//! - for the rest of validators who upon validating the block, try to credit
//!   the txn fee record to rightful block proposer:
//!   [`derive_txns_fee_record()`]
//!
//! Again, we recommend readers take a look at the [integration test] to get an
//! idea of this workflow in actual mock code.
//!
//! [integration test]: https://github.com/EspressoSystems/cap/blob/main/src/transfer.rs
//!
//! [^srs]: in production, this would be a file downloaded from authority
//! source, but in test and for demo, we can generate them via
//! [proof::universal_setup()]
//!
//! [^de problem]: But do expect the slow deserialization problem to be resolved
//! in the future by which time those preprocessings are one-time procedule, and
//! normally you only need to load those proving/verifying keys from files using
//! APIs in [parameters].
//!
//! [^receiver memos]: Publishing the list of receiver memos to a public
//! bulletin board is optional, as long as the receivers have an authenticated
//! way of receiving the record openings of the output record.

#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate std;

pub mod bench_utils;
pub(crate) mod circuit;
pub mod constants;
pub mod errors;
pub mod freeze;
pub mod keys;
pub mod mint;
pub mod parameters;
pub mod proof;
pub mod structs;
pub mod transfer;
mod types;
pub mod utils;

#[cfg(feature = "test_apis")]
pub mod testing_apis;

#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;
use crate::{
    keys::UserPubKey,
    proof::transfer::TransferVerifyingKey,
    structs::{
        AssetDefinition, BlindFactor, FreezeFlag, Nullifier, ReceiverMemo, RecordCommitment,
        RecordOpening,
    },
    utils::txn_helpers::get_receiver_memos_digest,
};
use ark_serialize::*;
use ark_std::{
    boxed::Box,
    format,
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use errors::TxnApiError;
use freeze::FreezeNote;
use jf_plonk::{proof_system::structs::Proof, transcript::SolidityTranscript};
use jf_utils::tagged_blob;
use mint::MintNote;
use proof::{freeze::FreezeVerifyingKey, mint::MintVerifyingKey};
use serde::{Deserialize, Serialize};
use transfer::TransferNote;

// Re-export the types with associated parameters
pub use types::*;

/// A transaction note contains a note of possibly various transaction types,
/// including transfer, mint and freeze.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionNote {
    /// a transfer note
    Transfer(Box<TransferNote>),
    /// a mint (asset issuance) note
    Mint(Box<MintNote>),
    /// a freeze/unfreeze note
    Freeze(Box<FreezeNote>),
}

impl CanonicalSerialize for TransactionNote {
    fn serialize<W>(&self, mut w: W) -> Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
    {
        match self {
            Self::Transfer(transfer_note) => {
                let flag = 0;
                w.write_all(&[flag])?;
                <TransferNote as CanonicalSerialize>::serialize(transfer_note, &mut w)
            },
            Self::Mint(mint_note) => {
                let flag = 1;
                w.write_all(&[flag])?;
                <MintNote as CanonicalSerialize>::serialize(mint_note, &mut w)
            },
            Self::Freeze(freeze_note) => {
                let flag = 2;
                w.write_all(&[flag])?;
                <FreezeNote as CanonicalSerialize>::serialize(freeze_note, &mut w)
            },
        }
    }
    fn serialized_size(&self) -> usize {
        match self {
            Self::Transfer(transfer_note) => transfer_note.serialized_size() + 1,
            Self::Mint(mint_note) => mint_note.serialized_size() + 1,
            Self::Freeze(freeze_note) => freeze_note.serialized_size() + 1,
        }
    }
}

impl CanonicalDeserialize for TransactionNote {
    fn deserialize<R>(mut r: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let mut flag = [0u8; 1];
        r.read_exact(&mut flag)?;
        match flag[0] {
            0 => Ok(Self::Transfer(Box::new(
                <TransferNote as CanonicalDeserialize>::deserialize(&mut r)?,
            ))),
            1 => Ok(Self::Mint(Box::new(
                <MintNote as CanonicalDeserialize>::deserialize(&mut r)?,
            ))),
            2 => Ok(Self::Freeze(Box::new(
                <FreezeNote as CanonicalDeserialize>::deserialize(&mut r)?,
            ))),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl commit::Committable for TransactionNote {
    fn commit(&self) -> commit::Commitment<Self> {
        let mut bytes = vec![];
        CanonicalSerialize::serialize(self, &mut bytes).unwrap();
        commit::RawCommitmentBuilder::new("Txn Comm")
            .var_size_bytes(&bytes)
            .finalize()
    }
}

impl TransactionNote {
    /// Retrieve transaction input nullifiers
    pub fn nullifiers(&self) -> Vec<Nullifier> {
        match self {
            TransactionNote::Transfer(note) => note.inputs_nullifiers.clone(),
            TransactionNote::Mint(note) => vec![note.input_nullifier],
            TransactionNote::Freeze(note) => note.input_nullifiers.clone(),
        }
    }
    /// Retrieve transaction output record commitments
    pub fn output_commitments(&self) -> Vec<RecordCommitment> {
        match self {
            TransactionNote::Transfer(note) => note.output_commitments.clone(),
            TransactionNote::Mint(note) => vec![note.chg_comm, note.mint_comm],
            TransactionNote::Freeze(note) => note.output_commitments.clone(),
        }
    }
    /// Retrieve number of transaction outputs in the note
    pub fn output_len(&self) -> usize {
        match self {
            TransactionNote::Transfer(note) => note.output_commitments.len(),
            TransactionNote::Mint(_note) => 2,
            TransactionNote::Freeze(note) => note.output_commitments.len(),
        }
    }

    /// Retrieve merkle root
    pub fn merkle_root(&self) -> NodeValue {
        match self {
            TransactionNote::Transfer(note) => note.aux_info.merkle_root,
            TransactionNote::Mint(note) => note.aux_info.merkle_root,
            TransactionNote::Freeze(note) => note.aux_info.merkle_root,
        }
    }

    /// Verify signature of Receiver Memos associated with the transaction
    pub fn verify_receiver_memos_signature(
        &self,
        recv_memos: &[ReceiverMemo],
        sig: &Signature,
    ) -> Result<(), TxnApiError> {
        let digest = get_receiver_memos_digest(recv_memos)?;
        self.txn_memo_ver_key()
            .verify(&[digest], sig)
            .map_err(TxnApiError::FailedReceiverMemoSignature)
    }

    /// Retrieve validity proof
    pub fn validity_proof(&self) -> Proof<PairingEngine> {
        match self {
            TransactionNote::Transfer(note) => note.proof.clone(),
            TransactionNote::Mint(note) => note.proof.clone(),
            TransactionNote::Freeze(note) => note.proof.clone(),
        }
    }
}

// Private methods
impl TransactionNote {
    /// Retrieve reference to verification key used by user to sign messages
    /// bound to the note E.g. to verify receiver memos associated with the
    /// transaction outputs on the note
    fn txn_memo_ver_key(&self) -> &VerKey {
        match self {
            TransactionNote::Transfer(note) => &note.aux_info.txn_memo_ver_key,
            TransactionNote::Mint(note) => &note.aux_info.txn_memo_ver_key,
            TransactionNote::Freeze(note) => &note.aux_info.txn_memo_ver_key,
        }
    }
}

impl From<TransferNote> for TransactionNote {
    fn from(xfr_note: TransferNote) -> Self {
        TransactionNote::Transfer(Box::new(xfr_note))
    }
}

impl From<MintNote> for TransactionNote {
    fn from(mint_note: MintNote) -> Self {
        TransactionNote::Mint(Box::new(mint_note))
    }
}

impl From<FreezeNote> for TransactionNote {
    fn from(freeze_note: FreezeNote) -> Self {
        TransactionNote::Freeze(Box::new(freeze_note))
    }
}

/// A transaction verifying key contains a proof verification key of possibly
/// various transaction types, including transfer, mint and freeze.
#[tagged_blob("TXVERKEY")]
#[derive(Debug, Clone)]
pub enum TransactionVerifyingKey {
    /// verification key for validity proof in transfer note
    Transfer(TransferVerifyingKey),
    /// verification key for validity proof in mint note
    Mint(MintVerifyingKey),
    /// verification key for validity proof in freeze note
    Freeze(FreezeVerifyingKey),
}

impl CanonicalSerialize for TransactionVerifyingKey {
    fn serialize<W>(&self, mut w: W) -> Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
    {
        match self {
            Self::Transfer(transfer_key) => {
                let flag = 0;
                w.write_all(&[flag])?;
                <TransferVerifyingKey as CanonicalSerialize>::serialize(transfer_key, &mut w)
            },
            Self::Mint(mint_key) => {
                let flag = 1;
                w.write_all(&[flag])?;
                <MintVerifyingKey as CanonicalSerialize>::serialize(mint_key, &mut w)
            },

            Self::Freeze(freeze_key) => {
                let flag = 2;
                w.write_all(&[flag])?;
                <FreezeVerifyingKey as CanonicalSerialize>::serialize(freeze_key, &mut w)
            },
        }
    }

    fn serialized_size(&self) -> usize {
        match self {
            Self::Transfer(transfer_key) => transfer_key.serialized_size() + 1,
            Self::Mint(mint_key) => mint_key.serialized_size() + 1,
            Self::Freeze(freeze_key) => freeze_key.serialized_size() + 1,
        }
    }
}

impl CanonicalDeserialize for TransactionVerifyingKey {
    fn deserialize<R>(mut r: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let mut flag = [0u8; 1];
        r.read_exact(&mut flag)?;
        match flag[0] {
            0 => Ok(Self::Transfer(
                <TransferVerifyingKey as CanonicalDeserialize>::deserialize(&mut r)?,
            )),
            1 => Ok(Self::Mint(
                <MintVerifyingKey as CanonicalDeserialize>::deserialize(&mut r)?,
            )),
            2 => Ok(Self::Freeze(
                <FreezeVerifyingKey as CanonicalDeserialize>::deserialize(&mut r)?,
            )),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl TransactionVerifyingKey {
    pub(crate) fn get_key_ref(&self) -> &VerifyingKey {
        match self {
            TransactionVerifyingKey::Transfer(key) => &key.verifying_key,
            TransactionVerifyingKey::Mint(key) => &key.verifying_key,
            TransactionVerifyingKey::Freeze(key) => &key.verifying_key,
        }
    }
}

/// Batch verification for transaction
/// * `txns`: list of transaction notes to be verified
/// * `txns_roots`: root values for each transaction
/// * `verify_keys`: verification keys for each transaction instance
pub fn txn_batch_verify(
    txns: &[TransactionNote],
    txns_roots: &[NodeValue],
    timestamp: u64,
    verify_keys: &[&TransactionVerifyingKey],
) -> Result<(), TxnApiError> {
    // check parameters
    if txns.len() != verify_keys.len() || txns.len() != txns_roots.len() {
        return Err(TxnApiError::InvalidParameter(
            "Mismatched number of input parameters for batch verification".to_string(),
        ));
    }
    let public_inputs = txns
        .iter()
        .zip(txns_roots.iter())
        .map(|(txn, merkle_root)| match txn {
            TransactionNote::Transfer(note) => {
                let pi =
                    note.check_instance_and_get_public_input_internal(*merkle_root, timestamp)?;
                Ok(pi.to_scalars())
            },
            TransactionNote::Mint(note) => {
                let pi = note.check_instance_and_get_public_input(*merkle_root)?;
                Ok(pi.to_scalars())
            },
            TransactionNote::Freeze(note) => {
                let pi = note.check_instance_and_get_public_input(*merkle_root)?;
                Ok(pi.to_scalars())
            },
        })
        .collect::<Result<Vec<_>, TxnApiError>>()?;
    let public_inputs_as_slice: Vec<&[BaseField]> =
        public_inputs.iter().map(|x| x.as_slice()).collect();

    let proofs: Vec<_> = txns
        .iter()
        .map(|txn| match txn {
            TransactionNote::Transfer(note) => &note.proof,
            TransactionNote::Mint(note) => &note.proof,
            TransactionNote::Freeze(note) => &note.proof,
        })
        .collect();

    let keys = txns
        .iter()
        .map(|txn| match txn {
            TransactionNote::Transfer(note) => note.aux_info.txn_memo_ver_key.clone(),
            TransactionNote::Mint(note) => note.aux_info.txn_memo_ver_key.clone(),
            TransactionNote::Freeze(note) => note.aux_info.txn_memo_ver_key.clone(),
        })
        .collect::<Vec<VerKey>>();
    let mut extra_msgs = Vec::new();
    for (key, txn) in keys.iter().zip(txns.iter()) {
        let mut buf = Vec::new();
        CanonicalSerialize::serialize(key, &mut buf)?;
        if let TransactionNote::Transfer(note) = txn {
            buf.extend_from_slice(&note.aux_info.extra_proof_bound_data);
        }
        extra_msgs.push(Some(buf))
    }

    let keys: Vec<_> = verify_keys.iter().map(|key| key.get_key_ref()).collect();
    jf_plonk::proof_system::PlonkKzgSnark::batch_verify::<SolidityTranscript>(
        &keys,
        &public_inputs_as_slice,
        &proofs,
        &extra_msgs,
    )
    .map_err(|e| {
        TxnApiError::FailedSnark(format!(
            "Failed batch txn validity proof verification: {}",
            e
        ))
    })
}

/// Prepare the record opening corresponding to collected fee from a list of
/// transaction notes (within a block). The result is a record opening whose
/// blinding factor should be directly appended to the same block before being
/// disseminated to other nodes. This function is intended to be called by nodes
/// proposing blocks.
///
/// * `txns` - List of verified transaction notes within a block
/// * `owner_pk` - Public key of the owner of the collected fee, usually the
///   block proposer's public key
pub fn prepare_txns_fee_record<R>(
    rng: &mut R,
    txns: &[TransactionNote],
    owner_pk: UserPubKey,
) -> Result<RecordOpening, TxnApiError>
where
    R: RngCore + CryptoRng,
{
    if txns.is_empty() {
        return Err(TxnApiError::InvalidParameter(
            "Require at least 1 transaction to collect fee".to_string(),
        ));
    }
    let total_fee = calculate_fee(txns)?;
    let ro = RecordOpening::new(
        rng,
        total_fee,
        AssetDefinition::native(),
        owner_pk,
        FreezeFlag::Unfrozen,
    );
    Ok(ro)
}

/// Derive the record commitment corresponding to collected fee from a list of
/// transaction notes (within a block). The result is a record commitment to be
/// inserted in the ledger. This function is intended to be called by nodes
/// validating blocks.
///
/// * `txns` - List of verified transaction notes within a block
/// * `owner_pk` - Public key of the owner of the collected fee, usually the
///   block proposer's public key
/// * `blind` - blinding factor of the record commitment
pub fn derive_txns_fee_record(
    txns: &[TransactionNote],
    owner_pk: UserPubKey,
    blind: BlindFactor,
) -> Result<RecordCommitment, TxnApiError> {
    if txns.is_empty() {
        return Err(TxnApiError::InvalidParameter(
            "Require at least 1 transaction to collect fee".to_string(),
        ));
    }
    let total_fee = calculate_fee(txns)?;
    let ro = RecordOpening {
        amount: total_fee,
        asset_def: AssetDefinition::native(),
        pub_key: owner_pk,
        freeze_flag: FreezeFlag::Unfrozen,
        blind,
    };

    Ok(RecordCommitment::from(&ro))
}

/// Compute signature over a list of receiver memos
pub fn sign_receiver_memos(
    keypair: &KeyPair,
    recv_memos: &[ReceiverMemo],
) -> Result<Signature, TxnApiError> {
    let digest = get_receiver_memos_digest(recv_memos)?;
    Ok(keypair.sign(&[digest]))
}

// Compute amount of claimable transaction fee
pub(crate) fn calculate_fee(txns: &[TransactionNote]) -> Result<u64, TxnApiError> {
    let fee_amounts: Vec<u64> = txns
        .iter()
        .map(|txn| match txn {
            TransactionNote::Transfer(note) => note.aux_info.fee,
            TransactionNote::Mint(note) => note.aux_info.fee,
            TransactionNote::Freeze(note) => note.aux_info.fee,
        })
        .collect();
    utils::safe_sum_u64(&fee_amounts)
        .ok_or_else(|| TxnApiError::IncorrectFee("Overflow in total fee".to_string()))
}

#[cfg(test)]
mod test {
    use crate::{
        calculate_fee, derive_txns_fee_record,
        errors::TxnApiError,
        keys::{UserKeyPair, UserPubKey},
        prepare_txns_fee_record,
        structs::{AssetDefinition, BlindFactor, FreezeFlag},
        txn_batch_verify,
        utils::params_builder::TxnsParams,
        KeyPair, TransactionNote,
    };
    use ark_std::{vec, vec::Vec};

    #[test]
    fn test_transaction_note() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let num_transfer_txn = 1;
        let num_mint_txn = 2;
        let num_freeze_txn = 3;
        let tree_depth = 10;
        let params = TxnsParams::generate_txns(
            rng,
            num_transfer_txn,
            num_mint_txn,
            num_freeze_txn,
            tree_depth,
        );
        for t in &params.txns {
            assert_eq!(t.merkle_root(), params.merkle_root);

            match t.clone() {
                TransactionNote::Transfer(v) => {
                    let new_note = TransactionNote::from(*v.clone());
                    assert_eq!(t.clone().nullifiers(), v.inputs_nullifiers);
                    assert_eq!(t.clone().output_commitments(), v.output_commitments);
                    assert_eq!(t.clone().output_len(), v.output_commitments.len());
                    assert_eq!(new_note, t.clone());
                },
                TransactionNote::Mint(v) => {
                    let new_note = TransactionNote::from(*v.clone());
                    assert_eq!(t.clone().nullifiers(), vec![v.input_nullifier]);
                    assert_eq!(
                        t.clone().output_commitments(),
                        vec![v.chg_comm, v.mint_comm]
                    );
                    assert_eq!(t.clone().output_len(), 2);
                    assert_eq!(new_note, t.clone());
                },
                TransactionNote::Freeze(v) => {
                    let new_note = TransactionNote::from(*v.clone());
                    assert_eq!(t.clone().nullifiers(), v.input_nullifiers);
                    assert_eq!(t.clone().output_commitments(), v.output_commitments);
                    assert_eq!(t.clone().output_len(), v.output_commitments.len());
                    assert_eq!(new_note, t.clone());
                },
            }
        }

        // Test calculate fee
        // todo: check this fee is correct
        let fee = calculate_fee(&params.txns).unwrap();
        assert_eq!(fee, 5_u64);

        // Overflow
        let txn = params.txns[0].clone();
        let v = match txn {
            TransactionNote::Transfer(v) => Some(v),
            _ => None,
        };

        let mut v = v.unwrap();
        v.aux_info.fee = u64::MAX;
        let mut txns = params.txns.clone();
        txns.push(TransactionNote::Transfer(v));

        assert!(calculate_fee(&txns).is_err());

        // test fee collection
        let validator_keypair = UserKeyPair::generate(rng);
        let fee_ro = prepare_txns_fee_record(rng, &params.txns, validator_keypair.pub_key())?;

        // Cannot compute fees for an empty list of transactions
        assert!(prepare_txns_fee_record(rng, &[], validator_keypair.pub_key()).is_err());

        assert_eq!(fee_ro.asset_def, AssetDefinition::native());
        assert_eq!(fee_ro.pub_key, validator_keypair.pub_key());
        assert_eq!(fee_ro.freeze_flag, FreezeFlag::Unfrozen);
        assert_eq!(fee_ro.amount, calculate_fee(&params.txns)?);

        // test derive_txns_fee_record()
        let rng = &mut ark_std::test_rng();
        let params = TxnsParams::generate_txns(rng, 2, 3, 4, tree_depth);
        assert!(derive_txns_fee_record(
            &params.txns,
            UserPubKey::default(),
            BlindFactor::rand(rng)
        )
        .is_ok());
        assert!(
            derive_txns_fee_record(&[], UserPubKey::default(), BlindFactor::rand(rng)).is_err()
        );

        Ok(())
    }

    #[test]
    fn test_batch_verify() -> Result<(), TxnApiError> {
        let rng = &mut ark_std::test_rng();
        let num_transfer_txn = 5;
        let num_mint_txn = 2;
        let num_freeze_txn = 3;
        let tree_depth = 10;
        let params = TxnsParams::generate_txns(
            rng,
            num_transfer_txn,
            num_mint_txn,
            num_freeze_txn,
            tree_depth,
        );

        let keys = params.get_verifying_keys();
        let verifying_keys: Vec<_> = keys.iter().map(|rc| rc.as_ref()).collect();
        let mut roots = params.get_merkle_roots();

        // batch verify all transactions
        assert!(txn_batch_verify(
            &params.txns,
            &roots,
            params.valid_until - 1,
            &verifying_keys
        )
        .is_ok());

        // bad params
        let old_root_0 = roots[0];
        roots[0] = Default::default();
        assert!(txn_batch_verify(
            &params.txns,
            &roots,
            params.valid_until - 1,
            &verifying_keys
        )
        .is_err());
        roots[0] = old_root_0;
        assert!(txn_batch_verify(
            &params.txns,
            &roots,
            params.valid_until + 1,
            &verifying_keys
        )
        .is_err());
        // wrong recv_memo_ver_key should fail
        let wrong_param = params
            .clone()
            .update_recv_memos_ver_key(0, KeyPair::generate(rng).ver_key());
        assert!(txn_batch_verify(
            &wrong_param.txns,
            &roots,
            wrong_param.valid_until - 1,
            &verifying_keys
        )
        .is_err());

        // Less txs than roots / verifying keys
        assert!(txn_batch_verify(
            &params.txns[0..8],
            &roots,
            params.valid_until,
            &verifying_keys
        )
        .is_err());

        // Less roots than txs / verifying keys
        assert!(txn_batch_verify(
            &params.txns,
            &roots[0..5],
            params.valid_until,
            &verifying_keys
        )
        .is_err());

        // Less verifying keys than roots / txs
        assert!(txn_batch_verify(
            &params.txns,
            &roots,
            params.valid_until,
            &verifying_keys[0..4]
        )
        .is_err());

        Ok(())
    }
}
