// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Cryptographic key related data structures
//!
//! | Role | Data Structures |
//! | ---- | --------------- |
//! | User (incl Asset Issuer, Validators) | [UserKeyPair], [UserPubKey] |
//! | Credential Issuer | [CredIssuerKeyPair], [CredIssuerPubKey] |
//! | Viewer | [ViewerKeyPair], [ViewerPubKey] |
//! | Freezer | [FreezerKeyPair], [FreezerPubKey] |
use crate::{
    constants::VIEWABLE_DATA_LEN,
    errors::TxnApiError,
    mint::MintNote,
    structs::{
        AssetCode, AssetDefinition, Credential, InOrOut, Nullifier, RecordCommitment, ViewableData,
        ViewableMemo,
    },
    transfer::TransferNote,
    BaseField, CurveParam, ScalarField,
};
use ark_ec::{group::Group, twisted_edwards_extended::GroupProjective, ProjectiveCurve};
use ark_serialize::*;
use ark_std::{
    format,
    hash::{Hash, Hasher},
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
    UniformRand,
};
use derive_more::{Deref, From, Into};
use jf_primitives::{
    aead, elgamal,
    elgamal::EncKey,
    prf::{PrfKey, PRF},
    signatures::{
        schnorr,
        schnorr::{SchnorrSignatureScheme, Signature},
        SignatureScheme,
    },
};
use jf_rescue::Permutation as RescuePermutation;
use jf_utils::{hash_to_field, tagged_blob};

/// Public address for a user to send assets to/from.
#[tagged_blob("ADDR")]
#[derive(
    Clone,
    Default,
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Deref,
    From,
    Into,
)]
pub struct UserAddress(schnorr::VerKey<CurveParam>);

impl From<&UserAddress> for (BaseField, BaseField) {
    fn from(addr: &UserAddress) -> Self {
        (&**addr).into()
    }
}

/// The public key of a `UserKeyPair`
#[tagged_blob("USERPUBKEY")]
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct UserPubKey {
    pub(crate) address: UserAddress,
    enc_key: aead::EncKey,
}

impl UserPubKey {
    /// Encrypt a message with authenticated label using AEAD.
    pub fn encrypt<R>(
        &self,
        rng: &mut R,
        message: &[u8],
        label: &[u8],
    ) -> Result<aead::Ciphertext, TxnApiError>
    where
        R: RngCore + CryptoRng,
    {
        let ciphertext = self
            .enc_key
            .encrypt(rng, message, label)
            .map_err(|e| TxnApiError::FailedPrimitives(format!("AEAD encryption failed: {}", e)))?;
        Ok(ciphertext)
    }

    /// Get public key address field
    pub fn address(&self) -> UserAddress {
        self.address.clone()
    }

    /// Constructor
    pub fn new(address: UserAddress, enc_key: aead::EncKey) -> Self {
        Self { address, enc_key }
    }

    /// Clone the Encryption key.
    /// Enc key does not impl Copy so we have to clone here.
    /// The caller is responsible for clearing the memory.
    pub fn enc_key(&self) -> aead::EncKey {
        self.enc_key.clone()
    }

    /// Verify a signature
    pub fn verify_sig(&self, msg: &[u8], sig: &Signature<CurveParam>) -> Result<(), TxnApiError> {
        let bls_scalars = hash_to_field::<_, BaseField>(msg);
        self.address
            .verify(
                &[bls_scalars],
                sig,
                SchnorrSignatureScheme::<CurveParam>::CS_ID,
            )
            .map_err(|_| {
                TxnApiError::FailedPrimitives(
                    "UserPubKey: Failed signature verification".to_string(),
                )
            })
    }
}

// private or internal functions
impl UserPubKey {
    pub(crate) fn address_internal(&self) -> &GroupProjective<CurveParam> {
        self.address.internal()
    }
}

/// A key pair for the user who owns and can consume records (spend asset)
#[tagged_blob("USERKEY")]
#[derive(Debug, Default, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct UserKeyPair {
    pub(crate) addr_keypair: schnorr::KeyPair<CurveParam>,
    pub(crate) enc_keypair: aead::KeyPair,
}

impl UserKeyPair {
    /// Generate a new user key pair
    pub fn generate<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Self {
            addr_keypair: schnorr::KeyPair::generate(rng),
            enc_keypair: aead::KeyPair::generate(rng),
        }
    }

    /// Getter for the user public key
    pub fn pub_key(&self) -> UserPubKey {
        UserPubKey {
            address: self.address(),
            enc_key: self.enc_keypair.enc_key(),
        }
    }

    /// Getter for public address
    pub fn address(&self) -> UserAddress {
        self.addr_keypair.ver_key().into()
    }

    /// Getter for the reference to the address secret key
    pub(crate) fn address_secret_ref(&self) -> &ScalarField {
        self.addr_keypair.sign_key_internal()
    }

    /// Nullify an Asset Record Commitment (RC)
    ///
    /// * `fpk` - Freezer public key associated with the asset record's policy;
    ///   `FreezerPubKey::default()` if the asset policy contains no/empty
    ///   freezer
    /// * `uid` - the unique id for the position of RC in the accumulator
    /// * `rc` - the asset record commitment from `RecordCommitment`
    pub fn nullify(&self, fpk: &FreezerPubKey, uid: u64, rc: &RecordCommitment) -> Nullifier {
        self.derive_nullifier_key(fpk).nullify(uid, rc)
    }

    /// Sign an arbitrary message using the address spending key
    pub fn sign(&self, msg: &[u8]) -> Signature<CurveParam> {
        let scalars = hash_to_field::<_, BaseField>(msg);
        self.addr_keypair
            .sign(&[scalars], SchnorrSignatureScheme::<CurveParam>::CS_ID)
    }

    // Derive nullifying secret key.
    // Return user address secret key if freezer public key is neutral,
    // otherwise return the hash of the Diffie-Hellman shared key
    pub(crate) fn derive_nullifier_key(&self, fpk: &FreezerPubKey) -> NullifierKey {
        if fpk.0 == GroupProjective::<CurveParam>::default() {
            NullifierKey::from(self.address_secret_ref())
        } else {
            compute_nullifier_key(&fpk.0, self.address_secret_ref())
        }
    }
}

/// Public key for the credential creator
#[tagged_blob("CREDPUBKEY")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default, CanonicalDeserialize, CanonicalSerialize)]
pub struct CredIssuerPubKey(pub(crate) schnorr::VerKey<CurveParam>);

impl CredIssuerPubKey {
    /// Verify a credential only for its signature correctness.
    pub(crate) fn verify(&self, msg: &[BaseField], cred: &Credential) -> Result<(), TxnApiError> {
        self.0
            .verify(msg, &cred.0, SchnorrSignatureScheme::<CurveParam>::CS_ID)
            .map_err(|_| {
                TxnApiError::FailedCredentialVerification(
                    "wrong signature in credential".to_string(),
                )
            })
    }

    /// Transform to a pair of scalars
    pub(crate) fn to_scalars(&self) -> Vec<BaseField> {
        let (x, y) = (&self.0).into();
        vec![x, y]
    }
}

/// Key pair for the credential creator
#[tagged_blob("CREDKEY")]
#[derive(Debug, Clone, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredIssuerKeyPair(pub(crate) schnorr::KeyPair<CurveParam>);

impl CredIssuerKeyPair {
    /// Generate a new key pair
    pub fn generate<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Self(schnorr::KeyPair::generate(rng))
    }

    /// Getter for the public key
    pub fn pub_key(&self) -> CredIssuerPubKey {
        CredIssuerPubKey(self.0.ver_key())
    }

    /// Sign a message and create a credential.
    pub(crate) fn sign(&self, msg: &[BaseField]) -> Credential {
        Credential(
            self.0
                .sign(msg, SchnorrSignatureScheme::<CurveParam>::CS_ID),
        )
    }
}

/// Public key for the viewer
#[tagged_blob("AUDPUBKEY")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default, CanonicalDeserialize, CanonicalSerialize)]
pub struct ViewerPubKey(pub(crate) elgamal::EncKey<CurveParam>);

impl ViewerPubKey {
    /// Generate a random viewer public key with unknown associated secret key
    pub(crate) fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        ViewerPubKey(EncKey::<CurveParam>::rand(rng))
    }

    /// Encrypt messages including information about a transaction that an
    /// viewer should know.
    pub(crate) fn encrypt(
        &self,
        randomizer: ScalarField,
        message: &[BaseField],
    ) -> elgamal::Ciphertext<CurveParam> {
        self.0.deterministic_encrypt(randomizer, message)
    }

    /// Transform to a pair of scalars
    pub(crate) fn to_scalars(&self) -> Vec<BaseField> {
        let (x, y) = (&self.0).into();
        vec![x, y]
    }
}
/// Key pair for the viewer
#[tagged_blob("AUDKEY")]
#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ViewerKeyPair(pub(crate) elgamal::KeyPair<CurveParam>);

impl ViewerKeyPair {
    /// Generate a new key pair
    pub fn generate<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Self(elgamal::KeyPair::generate(rng))
    }

    /// Getter for the public key
    pub fn pub_key(&self) -> ViewerPubKey {
        ViewerPubKey(self.0.enc_key())
    }

    /// Decrypts ViewerMemo
    pub(crate) fn decrypt(&self, memo: &ViewableMemo) -> Vec<BaseField> {
        self.0.decrypt(&memo.0)
    }

    /// Open ViewableMemo into input and output vectors ofViewableData struct
    pub fn open_transfer_viewing_memo(
        &self,
        asset_definition: &AssetDefinition,
        transfer_note: &TransferNote,
    ) -> Result<(Vec<ViewableData>, Vec<ViewableData>), TxnApiError> {
        if self.pub_key() != asset_definition.policy.viewer_pk {
            return Err(TxnApiError::InvalidParameter(
                "Viewer decrypt key do not match policy viewer public key".to_string(),
            ));
        }
        let n_inputs = transfer_note.inputs_nullifiers.len() - 1; // fee record has no viewing memo
        let n_outputs = transfer_note.output_commitments.len() - 1; // fee chg record has no viewing memo

        let plaintext = self.decrypt(&transfer_note.viewing_memo);
        let expected_len = 1 + n_inputs * VIEWABLE_DATA_LEN + n_outputs * 4;
        if plaintext.len() != expected_len {
            return Err(TxnApiError::FailedViewableMemoDecryption(format!(
                "decrypted memo length:{}, expected:{}",
                plaintext.len(),
                expected_len
            )));
        }
        let asset_code = AssetCode(plaintext[0]);

        if asset_definition.code != asset_code {
            return Err(TxnApiError::FailedViewableMemoDecryption(
                "Decrypted asset code does not match expected policy".to_string(),
            ));
        }
        let mut off_set = 1;
        let input_len = VIEWABLE_DATA_LEN;
        let mut visible_data_input = vec![];
        for _ in 0..n_inputs {
            let chunk = &plaintext[off_set..off_set + input_len];
            let visible_data =
                ViewableData::from_xfr_data_and_asset(asset_definition, chunk, InOrOut::In)?;
            if visible_data.user_address.is_none()
                || visible_data.user_address.as_ref().unwrap() != &UserAddress::default()
            {
                visible_data_input.push(visible_data);
            }
            off_set += input_len;
        }
        let output_len = 4;
        let mut visible_data_output = vec![];
        for _ in 0..n_outputs {
            let chunk = &plaintext[off_set..off_set + output_len];
            visible_data_output.push(ViewableData::from_xfr_data_and_asset(
                asset_definition,
                chunk,
                InOrOut::Out,
            )?);
            off_set += output_len;
        }
        Ok((visible_data_input, visible_data_output))
    }

    /// Open MintNote ViewableMemo intoViewableData for new minted record
    pub fn open_mint_viewing_memo(
        &self,
        mint_note: &MintNote,
    ) -> Result<ViewableData, TxnApiError> {
        let plaintext = self.decrypt(&mint_note.viewing_memo);
        let expected_len = 3; // (x,y) owner address and blinding factor
        if plaintext.len() != expected_len {
            return Err(TxnApiError::FailedViewableMemoDecryption(format!(
                "decrypted memo length:{}, expected:{}",
                plaintext.len(),
                expected_len
            )));
        }
        ViewableData::from_mint_note(&plaintext, mint_note)
    }
}

/// Public key for the freezer
#[tagged_blob("FREEZEPUBKEY")]
#[derive(Clone, Debug, Eq, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct FreezerPubKey(pub(crate) GroupProjective<CurveParam>);

impl FreezerPubKey {
    /// Transform to a pair of scalars
    pub(crate) fn to_scalars(&self) -> Vec<BaseField> {
        let affine_p = self.0.into_affine();
        vec![affine_p.x, affine_p.y]
    }
}

impl Hash for FreezerPubKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.0.into_affine(), state)
    }
}

impl PartialEq for FreezerPubKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.into_affine().eq(&other.0.into_affine())
    }
}

/// Key pair for the freezer
#[tagged_blob("FREEZEKEY")]
#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct FreezerKeyPair {
    pub(crate) sec_key: ScalarField,
    pub(crate) pub_key: GroupProjective<CurveParam>,
}

impl FreezerKeyPair {
    /// Generate a new key pair
    pub fn generate<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let sec_key = ScalarField::rand(rng);
        let pub_key = Group::mul(
            &GroupProjective::<CurveParam>::prime_subgroup_generator(),
            &sec_key,
        );
        Self { sec_key, pub_key }
    }

    /// Getter for the public key
    pub fn pub_key(&self) -> FreezerPubKey {
        FreezerPubKey(self.pub_key)
    }

    /// Nullify an Asset Record Commitment (RC)
    ///
    /// * `address` - User address, the owner of the asset record
    /// * `uid` - the unique id for the position of RC in the accumulator
    /// * `rc` - the asset record commitment from `RecordCommitment`
    pub fn nullify(&self, address: &UserAddress, uid: u64, rc: &RecordCommitment) -> Nullifier {
        self.derive_nullifier_key(address).nullify(uid, rc)
    }

    // Derive nullifying secret key.
    // Return the hash of the Diffie-Hellman shared key
    //
    // Note: `address` is guaranteed to be in a large group and not an identity
    // group element, since this public key is being retreived from existing
    // asset record and sanity check had been done during asset issuance to
    // avoid malformed user public key.
    pub(crate) fn derive_nullifier_key(&self, address: &UserAddress) -> NullifierKey {
        compute_nullifier_key(address.internal(), &self.sec_key)
    }
}

impl Hash for FreezerKeyPair {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.sec_key, state);
        Hash::hash(&self.pub_key.into_affine(), state);
    }
}

impl PartialEq for FreezerKeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.sec_key == other.sec_key && self.pub_key.into_affine() == other.pub_key.into_affine()
    }
}

// Use DH to derive a shared key, then hash to get the nullifier key
fn compute_nullifier_key(
    pub_key_alice: &GroupProjective<CurveParam>,
    sec_key_bob: &ScalarField,
) -> NullifierKey {
    let shared_key_affine = Group::mul(pub_key_alice, sec_key_bob).into_affine();
    let nk = RescuePermutation::default().hash_3_to_1(&[
        shared_key_affine.x,
        shared_key_affine.y,
        BaseField::from(0u32),
    ]);
    NullifierKey(nk)
}

/// Secret key used to nullify records, can only be derived by either the record
/// owner (`UserKeyPair`) or the correct freezer (`FreezerKeyPair`)
#[tagged_blob("NULKEY")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct NullifierKey(pub(crate) BaseField);

impl NullifierKey {
    // Nullify an asset record commitment (with its unique id in the
    // accumulator for security purposes)
    // nl := PRF(nk; uid || com) where uid is leaf index, com is the coin/ar
    // commitment
    pub(crate) fn nullify(&self, uid: u64, com: &RecordCommitment) -> Nullifier {
        let prf_key = PrfKey::from(self.0);
        Nullifier(
            PRF::new(2, 1)
                .eval(&prf_key, &[BaseField::from(uid), com.0])
                .unwrap()[0],
        )
    }
}

impl From<&ScalarField> for NullifierKey {
    fn from(s: &ScalarField) -> Self {
        NullifierKey(jf_utils::fr_to_fq::<_, CurveParam>(s))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_user_keypair() {
        let mut rng = ark_std::test_rng();
        let user_keypair = UserKeyPair::generate(&mut rng);
        let user_pubkey = user_keypair.pub_key();

        let msg = "message".as_bytes();
        let sig = user_keypair.sign(&msg);
        assert!(user_pubkey.verify_sig(&msg, &sig).is_ok());

        let wrong_msg = "wrong_message".as_bytes();
        assert!(user_pubkey.verify_sig(&wrong_msg, &sig).is_err());

        let other_sig = user_keypair.sign(&wrong_msg);
        assert!(user_pubkey.verify_sig(&msg, &other_sig).is_err());

        let other_pubkey = UserKeyPair::generate(&mut rng).pub_key();
        assert!(other_pubkey.verify_sig(&msg, &sig).is_err());
    }

    #[test]
    fn test_derive_nullifier_key() {
        let mut rng = ark_std::test_rng();
        let user_keypair = UserKeyPair::generate(&mut rng);
        let freezer_keypair = FreezerKeyPair::generate(&mut rng);
        let nk1 = user_keypair.derive_nullifier_key(&freezer_keypair.pub_key());
        let nk2 = freezer_keypair.derive_nullifier_key(&user_keypair.address());
        assert_eq!(nk1, nk2);

        let expected_shared_key = Group::mul(
            user_keypair.pub_key().address_internal(),
            &freezer_keypair.sec_key,
        )
        .into_affine();
        let expected_nk = RescuePermutation::default().hash_3_to_1(&[
            expected_shared_key.x,
            expected_shared_key.y,
            BaseField::from(0u32),
        ]);
        assert_eq!(nk1.0, expected_nk);

        // nk is user secret key when the freezer public key is neutral
        let empty_fzk = FreezerPubKey::default();
        let nk3 = user_keypair.derive_nullifier_key(&empty_fzk);
        assert_eq!(
            nk3.0,
            jf_utils::fr_to_fq::<_, CurveParam>(user_keypair.address_secret_ref())
        );
    }

    #[test]
    fn test_serde() {
        let mut rng = ark_std::test_rng();
        let user_keypair = UserKeyPair::generate(&mut rng);
        let minter_keypair = CredIssuerKeyPair::generate(&mut rng);
        let viewer_keypair = ViewerKeyPair::generate(&mut rng);
        let freezer_keypair = FreezerKeyPair::generate(&mut rng);
        let nullifier_key = user_keypair.derive_nullifier_key(&freezer_keypair.pub_key());

        let ser_bytes = bincode::serialize(&user_keypair).unwrap();
        let de: UserKeyPair = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de.enc_keypair.enc_key(), user_keypair.enc_keypair.enc_key());
        assert_eq!(
            de.addr_keypair.ver_key(),
            user_keypair.addr_keypair.ver_key()
        );

        let ser_bytes = bincode::serialize(&minter_keypair).unwrap();
        let de: CredIssuerKeyPair = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de.0.ver_key(), minter_keypair.0.ver_key());
        let ser_bytes = bincode::serialize(&viewer_keypair).unwrap();
        let de: ViewerKeyPair = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de.0.enc_key(), viewer_keypair.0.enc_key());
        let ser_bytes = bincode::serialize(&freezer_keypair).unwrap();
        let de: FreezerKeyPair = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de, freezer_keypair);
        let ser_bytes = bincode::serialize(&nullifier_key).unwrap();
        let de: NullifierKey = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de, nullifier_key);
    }
}
