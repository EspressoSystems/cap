// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! record-related data structures in transactions

use crate::{
    config::CapConfig,
    constants::*,
    errors::{DeserializationError, TxnApiError},
    keys::*,
    mint::MintNote,
    utils::*,
};
use ark_ec::models::twisted_edwards::Affine;
use ark_ff::{BigInteger, Field, PrimeField, UniformRand, Zero};
use ark_serialize::*;
use ark_std::{
    borrow::ToOwned,
    convert::TryFrom,
    format,
    rand::{CryptoRng, RngCore, SeedableRng},
    string::ToString,
    vec,
    vec::Vec,
};
use jf_primitives::{
    aead,
    commitment::{CommitmentScheme, FixedLengthRescueCommitment},
    elgamal,
    merkle_tree::prelude::{MerkleTreeScheme, RescueMerkleTree},
    prf::{RescuePRF, PRF},
    rescue::Permutation,
    signatures::schnorr::{self, Signature},
};
use jf_utils::hash_to_field;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha3::{Digest, Keccak256};
use tagged_base64::tagged;

/// Alias for `NodeValue` type in merkle tree.
pub type NodeValue<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::NodeValue;
/// Alias for `MembershipProof` type in merkle tree.
pub type AccMemberWitness<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::MembershipProof;

#[derive(Debug, Clone, Copy)]
/// Enum for each type of note
pub enum NoteType {
    /// Transfer note
    Transfer,
    /// Mint note
    Mint,
    /// Freeze note
    Freeze,
}

/// The random seed used in AssetCode derivation
#[tagged("ASSET_SEED")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Copy(bound = "C: CapConfig"),
    Default(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig")
)]
pub struct AssetCodeSeed<C: CapConfig>(pub(crate) C::ScalarField);

impl<C: CapConfig> AssetCodeSeed<C> {
    /// sample a new seed for asset code generation
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        AssetCodeSeed(C::ScalarField::rand(rng))
    }
}

/// The digest of asset description
#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Copy(bound = "C: CapConfig"),
    Default(bound = "C: CapConfig")
)]
pub(crate) struct AssetCodeDigest<C: CapConfig>(pub(crate) C::ScalarField);

impl<C: CapConfig> AssetCodeDigest<C> {
    pub(crate) fn from_description(description: &[u8]) -> Self {
        let scalars = hash_to_field::<_, C::ScalarField>(description);
        let digest = Permutation::default().sponge_with_padding(&[scalars], 1)[0];
        AssetCodeDigest(digest)
    }
}

/// A unique identifier/code for an asset type
#[tagged("INTERNAL_ASSET_CODE")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Copy(bound = "C: CapConfig"),
    Default(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
pub struct InternalAssetCode<C: CapConfig>(pub(crate) C::ScalarField);

impl<C: CapConfig> InternalAssetCode<C> {
    /// Derive an Asset code from its seed and digest
    /// `seed`:  only known by the asset creator.
    /// `description`: asset code description
    pub fn new(seed: AssetCodeSeed<C>, description: &[u8]) -> Self {
        let digest = AssetCodeDigest::from_description(description);
        Self::new_internal(seed, digest)
    }

    // internal logic of deriving an asset code from seed and digest, both as scalar
    pub(crate) fn new_internal(seed: AssetCodeSeed<C>, digest: AssetCodeDigest<C>) -> Self {
        Self(RescuePRF::<C::ScalarField, 1, 1>::evaluate(&[seed.0], &[digest.0]).unwrap()[0])
    }
}

/// Record Amount type
/// # How to convert between unsigned int types
/// ```ignore
/// let a = Amount::from(10u64);
/// let b : Amount = 8u32.into();
/// let c : u128 = a.into();
/// ```
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Default,
    Hash,
    Eq,
    From,
    Into,
    Add,
    AddAssign,
    Sub,
    SubAssign,
    Mul,
    MulAssign,
    Div,
    DivAssign,
    Rem,
    RemAssign,
    PartialOrd,
    Ord,
    Sum,
    Deserialize,
    Serialize,
    Display,
    FromStr,
    LowerHex,
)]
#[serde(from = "u128", into = "u128")]
#[from(types(u64, u32, u8))]
pub struct Amount(pub(crate) u128);

impl Amount {
    /// Generate a vector of Amount from a u128 vector
    pub fn from_vec(vals: &[u128]) -> Vec<Self> {
        vals.iter().map(|x| Amount(*x)).collect()
    }
}

impl From<Amount> for primitive_types::U256 {
    fn from(amt: Amount) -> Self {
        u128::from(amt).into()
    }
}

impl TryFrom<primitive_types::U256> for Amount {
    type Error = TxnApiError;

    fn try_from(value: primitive_types::U256) -> Result<Self, Self::Error> {
        if value <= primitive_types::U256::from(u128::MAX) {
            let mut bytes_u256 = [0u8; 32];
            value.to_little_endian(&mut bytes_u256);
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&bytes_u256[..16]);

            Ok(Self::from(u128::from_le_bytes(bytes)))
        } else {
            Err(TxnApiError::InvalidParameter(
                "input U256 value larger than Amount's bound".to_string(),
            ))
        }
    }
}

/// Asset code structure
#[tagged("ASSET_CODE")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Copy(bound = "C: CapConfig"),
    Default(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    PartialOrd(bound = "C: CapConfig"),
    Ord(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
pub struct AssetCode<C: CapConfig>(pub(crate) C::ScalarField);

impl<C: CapConfig> AssetCode<C> {
    /// Return the AssetCode assigned for the native asset
    pub fn native() -> Self {
        C::native_asset_code()
    }

    /// Return the AssetCode assigned for a dummy record
    pub fn dummy() -> Self {
        C::dummy_asset_code()
    }

    /// Generate a random asset code
    /// Returns the asset code together with the randomly sampled seed and
    /// digest used to derive it
    pub fn random<R>(rng: &mut R) -> (Self, AssetCodeSeed<C>)
    where
        R: RngCore + CryptoRng,
    {
        let seed = AssetCodeSeed::generate(rng);
        (Self::new_domestic(seed, &[]), seed)
    }

    /// Derive a domestic cap Asset code from its seed and digest
    /// `seed`:  only known by the asset creator.
    /// `description`: asset code description
    pub fn new_domestic(seed: AssetCodeSeed<C>, description: &[u8]) -> Self {
        let internal = InternalAssetCode::new(seed, description);
        Self::new_domestic_from_internal(&internal)
    }

    /// Derive a domestic cap Asset code from its seed and digest
    /// `seed`:  only known by the asset creator.
    /// `description`: asset code description
    pub(crate) fn new_domestic_from_digest(
        seed: AssetCodeSeed<C>,
        digest: AssetCodeDigest<C>,
    ) -> Self {
        let internal = InternalAssetCode::new_internal(seed, digest);
        Self::new_domestic_from_internal(&internal)
    }

    /// Derive a domestic cap asset code from its internal asset code value
    pub(crate) fn new_domestic_from_internal(internal: &InternalAssetCode<C>) -> Self {
        let bytes_internal = internal.0.into_repr().to_bytes_le();
        let bytes = [DOM_SEP_DOMESTIC_ASSET.to_vec(), bytes_internal].concat();
        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        let hash_value = hasher.finalize();
        AssetCode(C::ScalarField::from_le_bytes_mod_order(&hash_value))
    }

    /// Derive asset code from a foreign tokens (e.g. an Ethereum
    /// wrapped token)
    pub fn new_foreign(description: &[u8]) -> Self {
        let bytes = [DOM_SEP_FOREIGN_ASSET.to_vec(), description.to_vec()].concat();
        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        let hash_value = hasher.finalize();
        AssetCode(C::ScalarField::from_le_bytes_mod_order(&hash_value))
    }

    /// Verify that asset code is an app domestic asset that was derived from
    /// `internal` asset code
    pub(crate) fn verify_domestic(
        &self,
        internal: &InternalAssetCode<C>,
    ) -> Result<(), TxnApiError> {
        let derived = Self::new_domestic_from_internal(internal);
        if derived == *self {
            return Ok(());
        }
        Err(TxnApiError::FailedAssetCodeVerification("Derived asset code from does not match expected asset code in minted asset code verification".to_string()))
    }

    /// Verify that asset code is a foreign derived from a non cap asset
    /// description or identifier
    pub fn verify_foreign(&self, description: &[u8]) -> Result<(), TxnApiError> {
        let derived = Self::new_foreign(description);
        if derived == *self {
            return Ok(());
        }
        Err(TxnApiError::FailedAssetCodeVerification("Derived asset code from does not match expected asset code in minted asset code verification".to_string()))
    }
}

/// A bitmap indicating which of the following fields are to be revealed:
/// (upk_x, upk_y, v, blind, attrs) where reveal bits for upk_x and upk_y are
/// the same. Also note that asset code code is compulsorily revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct RevealMap(pub(crate) [bool; VIEWABLE_DATA_LEN]);

impl RevealMap {
    /// Create a `RevealMap` with internal representation.
    /// **USE WITH CAUTION**: it is strongly recommended to not directly use
    /// this unless necessary, and create `RevealMap` via
    /// `AssetPolicy.reveal_xxx()` API.
    /// This API may be useful when deserialize into a `RevealMap` given its
    /// internal representation.
    pub fn new(internal_repr: [bool; VIEWABLE_DATA_LEN]) -> Self {
        Self(internal_repr)
    }
    /// Get the internal reveal map representation
    pub fn internal(&self) -> [bool; VIEWABLE_DATA_LEN] {
        self.0
    }

    /// Modify current reveal map so that address is revealed
    pub(crate) fn reveal_user_address(&mut self) {
        self.0[0] = true;
        self.0[1] = true;
    }

    /// Check if map is set to reveal user address
    pub(crate) fn is_user_address_revealed(&self) -> bool {
        self.0[0]
    }

    /// Modify current reveal map so that amount is revealed
    pub(crate) fn reveal_amount(&mut self) {
        self.0[2] = true;
    }

    /// Check if map is set to reveal amount
    pub(crate) fn is_amount_revealed(&self) -> bool {
        self.0[2]
    }

    /// Modify current reveal map so that commitment blinding factor is revealed
    pub(crate) fn reveal_blinding_factor(&mut self) {
        self.0[3] = true;
    }

    /// Check if map is set to reveal blinding factor
    pub(crate) fn is_blinding_factor_revealed(&self) -> bool {
        self.0[3]
    }

    /// Modify current reveal map so that ith identity attribute is revealed
    /// `i`: index (in range [0..ATTR_LEN - 1]) of identity attribute to reveal
    /// Return error is index `i` > ATTR_LEN - 1
    pub(crate) fn reveal_ith_id_attribute(&mut self, i: usize) -> Result<(), TxnApiError> {
        if i >= ATTRS_LEN {
            Err(TxnApiError::InvalidParameter(
                "index out of bounds to setting reveal map identity attribute".to_string(),
            ))
        } else {
            self.0[ASSET_TRACING_MAP_LEN + i] = true;
            Ok(())
        }
    }

    /// Check if map is set to reveal i-th identity attribute
    /// `i`: index (in range [0..ATTR_LEN - 1]) of identity attribute to reveal
    pub(crate) fn is_ith_attribute_revealed(&self, i: usize) -> Result<bool, TxnApiError> {
        if i >= ATTRS_LEN {
            return Err(TxnApiError::InvalidParameter(format!(
                "index {} must be smaller than ATTRS_LEN {}",
                i, ATTRS_LEN
            )));
        }
        Ok(self.0[ASSET_TRACING_MAP_LEN + i])
    }

    /// Modify current reveal map so that ith identity attribute is revealed
    pub(crate) fn reveal_all_id_attributes(&mut self) {
        for i in 0..ATTRS_LEN {
            self.0[ASSET_TRACING_MAP_LEN + i] = true;
        }
    }

    /// Convert to a scalar representation
    pub fn to_scalar<C: CapConfig>(&self) -> C::ScalarField {
        C::ScalarField::from(
            self.0
                .iter()
                .fold(0u64, |acc, &x| if x { acc * 2 + 1 } else { acc * 2 }),
        )
    }
}

// private or internal functions
impl RevealMap {
    /// compute the hadamard product/entry-wise product of the (reveal_map *
    /// vals).
    /// Noted that the 1st bit in reveal map on `upk` would require
    /// two Scalars: `(upk_x, upk_y)` thus vals.len() == REVEAL_MAP_LEN + 1
    pub(crate) fn hadamard_product<C: CapConfig>(
        &self,
        vals: &[C::ScalarField],
    ) -> Vec<C::ScalarField> {
        assert!(
            vals.len() <= VIEWABLE_DATA_LEN,
            "Internal Error: number of attributes larger than expected"
        );
        self.0
            .iter()
            .zip(vals.iter())
            .map(|(&bit, &val)| if bit { val } else { C::ScalarField::zero() })
            .collect()
    }
}

/// Policies related to asset record
/// * `viewer_pk` - viewer public key
/// * `cred_pk` - credential public key
/// * `freezer_pk` - freezer public key
/// * `reveal_map` - a binary vector indicating the subset of asset record info
///   and identity attributes to be revealed to the viewer
#[derive(CanonicalDeserialize, CanonicalSerialize, Serialize, Deserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Default(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
pub struct AssetPolicy<C: CapConfig> {
    pub(crate) viewer_pk: ViewerPubKey<C>,
    pub(crate) cred_pk: CredIssuerPubKey<C>,
    pub(crate) freezer_pk: FreezerPubKey<C>,
    pub(crate) reveal_map: RevealMap,
    // the asset viewing is applied only when the transfer amount exceeds `reveal_threshold`.
    pub(crate) reveal_threshold: Amount,
}

impl<C: CapConfig> AssetPolicy<C> {
    /// Reference to viewer public key
    pub fn viewer_pub_key(&self) -> &ViewerPubKey<C> {
        &self.viewer_pk
    }

    /// Reference to credential creator public key
    pub fn cred_creator_pub_key(&self) -> &CredIssuerPubKey<C> {
        &self.cred_pk
    }

    /// Reference to freezer public key
    pub fn freezer_pub_key(&self) -> &FreezerPubKey<C> {
        &self.freezer_pk
    }

    /// Getter for the reveal map
    /// **USE WITH CAUTION**: in most cases, you wouldn't need to use
    /// `reveal_map` directly, try `is_reveal_xxx_set()` APIs first.
    pub fn reveal_map(&self) -> RevealMap {
        self.reveal_map
    }

    /// Referecne to revealing threshold
    pub fn reveal_threshold(&self) -> Amount {
        self.reveal_threshold
    }

    /// Set the reveal map directly!
    /// **USE WITH CAUTION!**: since you might have an invalid reveal map, it is
    /// strongly recommended to construct reveal map via step-wise
    /// `reveal_xxx()` API.
    pub fn set_reveal_map_for_test(mut self, reveal_map: RevealMap) -> Self {
        self.reveal_map = reveal_map;
        self
    }

    /// Set revealing threshold policy
    pub fn set_reveal_threshold(mut self, reveal_threshold: Amount) -> Self {
        self.reveal_threshold = reveal_threshold;
        self
    }

    /// True if `reveal_threshold` is not the default value, false otherwise
    pub fn is_reveal_threshold_set(&self) -> bool {
        self.reveal_threshold != Amount::from(0u64)
    }

    /// Set the viewer public key
    pub fn set_viewer_pub_key(mut self, viewer_pub_key: ViewerPubKey<C>) -> Self {
        self.viewer_pk = viewer_pub_key;
        self
    }

    /// True if viewer public key is not the default key, false otherwise
    pub fn is_viewer_pub_key_set(&self) -> bool {
        self.viewer_pk != ViewerPubKey::default()
    }

    /// Set the credential creator public key
    pub fn set_cred_creator_pub_key(mut self, cred_creator_pub_key: CredIssuerPubKey<C>) -> Self {
        self.cred_pk = cred_creator_pub_key;
        self
    }

    /// True if credential creator public key is not dummy, false otherwise
    pub fn is_cred_creator_pub_key_set(&self) -> bool {
        self.cred_pk != CredIssuerPubKey::default()
    }

    /// Set the freezer public key
    pub fn set_freezer_pub_key(mut self, freezer_pub_key: FreezerPubKey<C>) -> Self {
        self.freezer_pk = freezer_pub_key;
        self
    }

    /// True if freezer public key is not dummy, false otherwise
    pub fn is_freezer_pub_key_set(&self) -> bool {
        self.freezer_pk != FreezerPubKey::default()
    }

    /// Set policy to reveal user address to viewer
    /// Return TxnApiError::InvalidParameter if viewer public key has not been
    /// specified yet
    pub fn reveal_user_address(mut self) -> Result<Self, TxnApiError> {
        if !self.is_viewer_pub_key_set() {
            return Err(TxnApiError::InvalidParameter(
                "Cannot reveal user address to dummy ViewerPublicKey".to_string(),
            )); // TODO crate InvalidStructure error type
        }
        self.reveal_map.reveal_user_address();
        Ok(self)
    }

    /// Check if the policy is set to reveal user address
    pub fn is_user_address_revealed(&self) -> bool {
        self.reveal_map.is_user_address_revealed()
    }

    /// Set policy to reveal amount to viewer
    /// Return TxnApiError::InvalidParameter if viewer public key has not been
    /// specified yet
    pub fn reveal_amount(mut self) -> Result<Self, TxnApiError> {
        // we cannot call directly self.reveal_map.reveal_amount() because there is no
        // checking the viewer pub key is present in the policy
        if !self.is_viewer_pub_key_set() {
            return Err(TxnApiError::InvalidParameter(
                "Cannot reveal amount to dummy ViewerPublicKey".to_string(),
            )); // TODO crate InvalidStructure error type
        }
        self.reveal_map.reveal_amount();
        Ok(self)
    }

    /// Check if the policy is set to reveal amount
    pub fn is_amount_revealed(&self) -> bool {
        self.reveal_map.is_amount_revealed()
    }

    /// Set policy to reveal record commitment blinding factor to viewer
    /// Return TxnApiError::InvalidParameter if viewer public key has not been
    /// specified yet
    pub fn reveal_blinding_factor(mut self) -> Result<Self, TxnApiError> {
        // we cannot call directly self.reveal_map.reveal_amount() because there is no
        // checking the viewer pub key is present in the policy
        if !self.is_viewer_pub_key_set() {
            return Err(TxnApiError::InvalidParameter(
                "Cannot reveal blinding factor to dummy ViewerPublicKey".to_string(),
            )); // TODO crate InvalidStructure error type
        }
        self.reveal_map.reveal_blinding_factor();
        Ok(self)
    }

    /// Check if the policy is set to reveal blinding factor
    pub fn is_blinding_factor_revealed(&self) -> bool {
        self.reveal_map.is_blinding_factor_revealed()
    }

    /// Set policy to reveal ith identity attribute to viewer
    /// Return TxnApiError::InvalidParameter if viewer or credential creator
    /// public key have not been specified yet or it `i` greater or equal to
    /// ATTRS_LEN
    pub fn reveal_ith_attribute(mut self, i: usize) -> Result<Self, TxnApiError> {
        if !self.is_viewer_pub_key_set() {
            return Err(TxnApiError::InvalidParameter(
                "Cannot reveal credential attribute to dummy ViewerPublicKey".to_string(),
            )); // TODO crate InvalidStructure error type
        }
        if !self.is_cred_creator_pub_key_set() {
            return Err(TxnApiError::InvalidParameter("Cannot reveal credential attribute when no credential creator pub key has been defined".to_string()));
            // TODO crate InvalidStructure error type
        }
        self.reveal_map.reveal_ith_id_attribute(i)?;
        Ok(self)
    }

    /// Set policy to reveal all identity attributes to viewer
    /// Return TxnApiError::InvalidParameter if viewer or credential creator
    /// public keys have not been specified yet
    pub fn reveal_all_attributes(mut self) -> Result<Self, TxnApiError> {
        if !self.is_viewer_pub_key_set() {
            return Err(TxnApiError::InvalidParameter(
                "Cannot reveal credential attribute to dummy ViewerPublicKey".to_string(),
            )); // TODO crate InvalidStructure error type
        }
        if !self.is_cred_creator_pub_key_set() {
            return Err(TxnApiError::InvalidParameter("Cannot reveal credential attribute when no credential creator pub key has been defined".to_string()));
            // TODO crate InvalidStructure error type
        }
        self.reveal_map.reveal_all_id_attributes();
        Ok(self)
    }

    /// Set policy to reveal user address, amount and record commitment blinding
    /// factor to viewer Return TxnApiError::InvalidParameter if viewer
    /// public key have not been specified yet
    pub fn reveal_record_opening(mut self) -> Result<Self, TxnApiError> {
        // we cannot call directly self.reveal_map.reveal_record_opening() because there
        // is no checking the viewer pub key is present in the policy
        self = self.reveal_user_address()?;
        self = self.reveal_amount()?;
        self = self.reveal_blinding_factor()?;
        Ok(self)
    }

    /// Set policy to reveal user address, amount, record commitment blinding
    /// factor and all identity attributes to viewer Return TxnApiError::
    /// InvalidParameter if viewer or credential creator public keys have not
    /// been specified yet
    pub fn reveal_all(mut self) -> Result<Self, TxnApiError> {
        // we cannot call directly self.reveal_map.reveal_all() because there is no
        // checking the viewer pub key or credential creator pub key are present in the
        // policy
        self = self.reveal_record_opening()?;
        self.reveal_all_attributes()
    }

    /// Transform to a list of scalars
    /// The order: (reveal_map, viewer_pk, cred_pk, freezer_pk)
    pub(crate) fn to_scalars(&self) -> Vec<C::ScalarField> {
        let mut result = vec![self.reveal_map.to_scalar::<C>()];
        result.extend_from_slice(&self.viewer_pk.to_scalars());
        result.extend_from_slice(&self.cred_pk.to_scalars());
        result.extend_from_slice(&self.freezer_pk.to_scalars());
        result.push(C::ScalarField::from(self.reveal_threshold.0));
        result
    }
}

/// Asset Definition
/// * `code` -- asset code as unique id code
/// * `policy` -- asset policy attached
#[tagged("ASSET_DEF")]
#[derive(CanonicalDeserialize, CanonicalSerialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Default(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
pub struct AssetDefinition<C: CapConfig> {
    /// asset code as unique id code
    pub code: AssetCode<C>,
    /// asset policy attached
    pub(crate) policy: AssetPolicy<C>,
}

impl<C: CapConfig> AssetDefinition<C> {
    /// Create a new `AssetDefinition` with specified asset code and asset
    /// policy
    /// Return Error is code AssetCode::native()
    pub fn new(code: AssetCode<C>, policy: AssetPolicy<C>) -> Result<Self, TxnApiError> {
        if code == AssetCode::native() || code == AssetCode::dummy() {
            return Err(TxnApiError::InvalidParameter(
                "Neither native or Dummy asset code can be used to create custom asset definition"
                    .to_string(),
            ));
        }
        Ok(AssetDefinition { code, policy })
    }

    /// Return native asset definition: code is 1, and policy is empty
    pub fn native() -> Self {
        AssetDefinition {
            code: AssetCode::native(),
            policy: AssetPolicy::default(),
        }
    }

    /// Return the dummy record asset definition: code is 2, and policy is empty
    pub fn dummy() -> Self {
        AssetDefinition {
            code: AssetCode::dummy(),
            policy: AssetPolicy::default(),
        }
    }

    /// returns true if it is a native asset, false otherwise
    pub fn is_native(&self) -> bool {
        self == &Self::native()
    }

    /// returns true if it is a dummy asset, false otherwise
    pub fn is_dummy(&self) -> bool {
        self == &Self::dummy()
    }

    /// Get reference to policy
    pub fn policy_ref(&self) -> &AssetPolicy<C> {
        &self.policy
    }
}

/// The blind factor used to produce a hiding commitment
#[tagged("BLIND")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Copy(bound = "C: CapConfig"),
    Default(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
pub struct BlindFactor<C: CapConfig>(pub(crate) C::ScalarField);

impl<C: CapConfig> BlindFactor<C> {
    /// Generate a random blind factor
    pub fn rand<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Self(C::ScalarField::rand(rng))
    }
}

/// The nullifier represents a spent/consumed asset record
#[tagged("NUL")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Copy(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    PartialOrd(bound = "C: CapConfig"),
    Ord(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
pub struct Nullifier<C: CapConfig>(pub(crate) C::ScalarField);

impl<C: CapConfig> Nullifier<C> {
    /// Generate a random nullifier
    pub fn random_for_test<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Self(C::ScalarField::rand(rng))
    }
}

/// Asset record to be published
#[tagged("REC")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Copy(bound = "C: CapConfig"),
    Default(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]

pub struct RecordCommitment<C: CapConfig>(pub(crate) C::ScalarField);

impl<C: CapConfig> From<&RecordOpening<C>> for RecordCommitment<C> {
    fn from(ro: &RecordOpening<C>) -> Self {
        ro.derive_record_commitment()
    }
}

impl<C: CapConfig> RecordCommitment<C> {
    /// converting the record commitment to a field element
    pub fn to_field_element(self) -> C::ScalarField {
        self.0
    }

    /// converting the record commitment to a field element
    pub fn from_field_element(f: C::ScalarField) -> Self {
        Self(f)
    }
}

/// Flag indicating whether records is frozen or not
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum FreezeFlag {
    /// Record is spendable or frozable
    #[serde(rename = "0")]
    Unfrozen,
    /// Record can only be unfrozen
    #[serde(rename = "1")]
    Frozen,
}

impl FreezeFlag {
    /// Flip the flag from Unfrozen/Frozen to Frozen/Unfrozen
    pub(crate) fn flip(&self) -> FreezeFlag {
        match self {
            FreezeFlag::Unfrozen => FreezeFlag::Frozen,
            FreezeFlag::Frozen => FreezeFlag::Unfrozen,
        }
    }
}

impl Default for FreezeFlag {
    fn default() -> Self {
        Self::Unfrozen
    }
}

impl From<FreezeFlag> for u8 {
    fn from(flag: FreezeFlag) -> Self {
        match flag {
            FreezeFlag::Unfrozen => 0u8,
            FreezeFlag::Frozen => 1u8,
        }
    }
}

impl From<FreezeFlag> for bool {
    fn from(flag: FreezeFlag) -> Self {
        match flag {
            FreezeFlag::Unfrozen => false,
            FreezeFlag::Frozen => true,
        }
    }
}

/// The opening of an asset record, containing all fields (and secrets) required
/// to compute commitment/proofs/.. values related to this asset record.
#[derive(CanonicalDeserialize, CanonicalSerialize, Serialize, Deserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Default(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
#[serde(bound = "C: CapConfig")]
pub struct RecordOpening<C: CapConfig> {
    /// value
    pub amount: Amount,
    /// asset definition
    pub asset_def: AssetDefinition<C>,
    /// owner public key
    pub pub_key: UserPubKey<C>,
    /// flag indicating if the record is frozen (true) or not (false)
    pub freeze_flag: FreezeFlag,
    /// record commitment blinding factor
    pub blind: BlindFactor<C>,
}

impl<C: CapConfig> RecordOpening<C> {
    /// Create a new RecordOpening with a random blind factor
    pub fn new<R>(
        rng: &mut R,
        amount: Amount,
        asset_def: AssetDefinition<C>,
        pub_key: UserPubKey<C>,
        freeze_flag: FreezeFlag,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let blind = BlindFactor::rand(rng);
        Self {
            amount,
            asset_def,
            pub_key,
            freeze_flag,
            blind,
        }
    }

    /// Create a new dummy record.
    /// Returns record's "spending" key
    pub fn dummy<R>(rng: &mut R, freeze_flag: FreezeFlag) -> (Self, UserKeyPair<C>)
    where
        R: CryptoRng + RngCore,
    {
        // dummy records should contain random user key. Otherwise, the nullifier key is
        // trivially known, and hence an observer can potentially distinguish dummy
        // records from real ones
        let keypair = UserKeyPair::generate(rng);
        let pub_key = keypair.pub_key();
        (
            Self::new(
                rng,
                Amount::from(0u64),
                AssetDefinition::dummy(),
                pub_key,
                freeze_flag,
            ),
            keypair,
        )
    }

    /// True if dummy record, false otherwise
    pub fn is_dummy(&self) -> bool {
        self.asset_def.is_dummy()
    }

    /// computes record's commitment `c = comm(v, at, upk, policy, freeze_flag;
    /// r)` where v is amount/value, at is asset code, upk is user public
    /// key, policy is asset policy, and r is blind factor
    pub(crate) fn derive_record_commitment(&self) -> RecordCommitment<C> {
        let (user_pubkey_x, user_pubkey_y) = (&self.pub_key.address).into();
        let (viewer_pubkey_x, viewer_pubkey_y) = (&self.asset_def.policy.viewer_pk.0).into();
        let (cred_pubkey_x, cred_pubkey_y) = (&self.asset_def.policy.cred_pk.0).into();
        let (freezer_pubkey_x, freezer_pubkey_y) = (&self.asset_def.policy.freezer_pk).into();

        // To minimize the number of Rescue calls, combine `reveal_map` and
        // `freeze_flag` to a single scalar `reveal_map << 1 + freeze_flag`
        let freeze_flag: u8 = self.freeze_flag.into();
        let reveal_map_and_freeze_flag = self.asset_def.policy.reveal_map.to_scalar::<C>().double()
            + C::ScalarField::from(freeze_flag);

        let reveal_threshold = C::ScalarField::from(self.asset_def.policy.reveal_threshold.0);

        let comm = FixedLengthRescueCommitment::<C::ScalarField, 12, 13>::commit(
            &[
                C::ScalarField::from(self.amount.0),
                self.asset_def.code.0,
                user_pubkey_x,
                user_pubkey_y,
                viewer_pubkey_x,
                viewer_pubkey_y,
                cred_pubkey_x,
                cred_pubkey_y,
                freezer_pubkey_x,
                freezer_pubkey_y,
                reveal_map_and_freeze_flag,
                reveal_threshold,
            ],
            Some(&self.blind.0),
        )
        .unwrap();
        RecordCommitment(comm)
    }
}

// The actual credential which is basically a Schnorr signature over attributes
#[tagged("CRED")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
pub(crate) struct Credential<C: CapConfig>(pub(crate) Signature<C::EmbeddedCurveParam>);

/// An identity attribute of a user, usually attested via `ExpirableCredential`
/// created by an identity creator.
#[tagged("ID")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    Default(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
pub struct IdentityAttribute<C: CapConfig>(pub(crate) C::ScalarField);

impl<C: CapConfig> IdentityAttribute<C> {
    /// Create a new `IdentityAttribute` from its value in bytes.
    pub fn new(attr_value: &[u8]) -> Result<Self, TxnApiError> {
        if attr_value.len() > C::PER_ATTR_BYTE_CAPACITY as usize || attr_value.is_empty() {
            return Err(TxnApiError::InvalidParameter(format!(
                "Each identity attribute takes at least 1 byte, at most {} bytes",
                C::PER_ATTR_BYTE_CAPACITY
            )));
        }
        // use PKCS#5 padding:
        // see: https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
        let pad_val = C::SCALAR_REPR_BYTE_LEN as usize - attr_value.len();
        let mut padded = attr_value.to_owned();

        // this ensures the leading bytes is 0
        // so that from_le_bytes_mod_order is always done without mod
        padded.resize((C::SCALAR_REPR_BYTE_LEN - 1) as usize, pad_val as u8);
        Ok(Self(C::ScalarField::from_le_bytes_mod_order(&padded)))
    }

    /// Getter for the attribute value in bytes.
    pub fn value(&self) -> Result<Vec<u8>, TxnApiError> {
        let mut padded_bytes: Vec<u8> = self.0.into_repr().to_bytes_le();

        match padded_bytes.last() {
            None => return Err(TxnApiError::InvalidAttribute),
            Some(p) => {
                if *p != 0 {
                    return Err(TxnApiError::InvalidAttribute);
                }
            },
        }

        let pad_len = padded_bytes[padded_bytes.len() - 2];
        padded_bytes.truncate(C::SCALAR_REPR_BYTE_LEN as usize - pad_len as usize);
        Ok(padded_bytes)
    }

    /// Randomly create an id attribute
    #[allow(dead_code)]
    pub(crate) fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Self(C::ScalarField::rand(rng))
    }

    /// Randomly create a list of `ATTR_LEN` id attributes
    #[allow(dead_code)]
    pub(crate) fn random_vector<R>(rng: &mut R) -> Vec<Self>
    where
        R: RngCore + CryptoRng,
    {
        (0..ATTRS_LEN)
            .into_iter()
            .map(|_| IdentityAttribute::random(rng))
            .collect()
    }

    fn default_vector() -> Vec<Self> {
        (0..ATTRS_LEN)
            .into_iter()
            .map(|_| IdentityAttribute::default())
            .collect()
    }
}

/// A credential with expiry created by a credential creator for a user
/// testifying user's identity attributes
#[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
#[serde(bound = "C: CapConfig")]
pub struct ExpirableCredential<C: CapConfig> {
    pub(crate) user_addr: UserAddress<C>,
    pub(crate) attrs: Vec<IdentityAttribute<C>>,
    pub(crate) expiry: u64,
    pub(crate) cred: Credential<C>,
    pub(crate) creator_pk: CredIssuerPubKey<C>,
}

impl<C: CapConfig> ExpirableCredential<C> {
    /// Issue an credential for a list of attributes with an expiry time
    ///
    /// * `user_addr` - User address that this credential is issuing to
    /// * `attrs` - identity attributes of the user
    /// * `expiry` - expiry date of the credential (specified by the creator)
    /// * `minter_keypair` - credential creator's key
    ///
    /// If the attribute list is not the same length as `ATTRS_LEN`, or each
    /// attribute bytes go beyond 32 bytes, then will return error.
    /// Otherwise an `ExpirableCredential` will be returned
    pub fn create(
        user_addr: UserAddress<C>,
        attrs: Vec<IdentityAttribute<C>>,
        expiry: u64,
        minter_keypair: &CredIssuerKeyPair<C>,
    ) -> Result<Self, TxnApiError> {
        if attrs.len() != ATTRS_LEN {
            return Err(TxnApiError::FailedCredentialCreation(format!(
                "Wrong attribute length, expecting: {}, but got: {}",
                ATTRS_LEN,
                attrs.len()
            )));
        }
        // msg := (expiry || upk || attrs)
        let msg = {
            let attrs: Vec<C::ScalarField> = attrs.iter().map(|attr| attr.0).collect();
            let (upk_x, upk_y) = (&user_addr).into();

            [vec![C::ScalarField::from(expiry), upk_x, upk_y], attrs].concat()
        };
        let cred = minter_keypair.sign(&msg);

        Ok(ExpirableCredential {
            user_addr,
            attrs,
            expiry,
            cred,
            creator_pk: minter_keypair.pub_key(),
        })
    }

    /// Returns true if the credential expired, false otherwise
    pub fn is_expired(&self, now: u64) -> bool {
        self.expiry < now
    }

    /// Verify the credential's validity -- not expired AND correct signature
    /// over claimed list of attributes
    /// * `now` - current timestamp to test whether credential is expired
    /// * returns a boolean flag, 0 for valid credential, 1 for invalid ones
    pub(crate) fn verify(&self, now: u64) -> Result<(), TxnApiError> {
        if self.is_expired(now) {
            return Err(TxnApiError::FailedCredentialVerification(
                "Credential has expired".to_string(),
            ));
        }

        let msg = {
            let attrs: Vec<C::ScalarField> = self.attrs.iter().map(|attr| attr.0).collect();
            let (upk_x, upk_y) = (&self.user_addr).into();
            [vec![C::ScalarField::from(self.expiry), upk_x, upk_y], attrs].concat()
        };
        self.creator_pk.verify(&msg, &self.cred)?;
        Ok(())
    }

    /// Create a dummy unexpired ExpirableCredential as placeholder.
    pub(crate) fn dummy_unexpired() -> Result<Self, TxnApiError> {
        let dummy_user = UserAddress::<C>::default();
        let dummy_minter_keypair = CredIssuerKeyPair::default();
        let dummy_attrs = IdentityAttribute::default_vector();
        let dummy_expiry = 2u64.pow(MAX_TIMESTAMP_LEN as u32) - 1;

        ExpirableCredential::create(dummy_user, dummy_attrs, dummy_expiry, &dummy_minter_keypair)
            .map_err(|_| {
                TxnApiError::InternalError(
                    "Failed to create dummy unexpired credential".to_string(),
                )
            })
    }

    /// Retrieve expiry value
    pub fn expiry(&self) -> u64 {
        self.expiry
    }
}

/// Memos for viewers such as viewers required by the asset policy.
/// Concretely, it is a ciphertext over details of a
/// transaction, enabling asset viewing and identity viewing.
#[tagged("AUDMEMO")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig"),
    Eq(bound = "C: CapConfig"),
    Hash(bound = "C: CapConfig")
)]
pub struct ViewableMemo<C: CapConfig>(pub(crate) elgamal::Ciphertext<C::EmbeddedCurveParam>);

impl<C: CapConfig> ViewableMemo<C> {
    /// Construct a viewing memo directly from internal ciphertext.
    /// **USE WITH CAUTION**: this method is only used during reconstruction
    /// from internal ciphertext of an existing `ViewableMemo`, you should never
    /// pass in an arbitrary ciphertext and deem this memo as valid.
    pub fn new(ciphertext: elgamal::Ciphertext<C::EmbeddedCurveParam>) -> Self {
        Self(ciphertext)
    }

    /// Getter for internal ciphertext
    pub fn internal(&self) -> &elgamal::Ciphertext<C::EmbeddedCurveParam> {
        &self.0
    }

    /// Create an `ViewableMemo` used in minting transactions
    pub(crate) fn new_for_mint_note(
        ro_mint: &RecordOpening<C>,
        randomizer: C::EmbeddedCurveScalarField,
    ) -> Self {
        let viewer_pk = &ro_mint.asset_def.policy.viewer_pk;
        let message = if *viewer_pk == ViewerPubKey::default() {
            vec![C::ScalarField::zero(); 3]
        } else {
            let (addr_x, addr_y) = (&ro_mint.pub_key.address).into();
            vec![addr_x, addr_y, ro_mint.blind.0]
        };
        Self(viewer_pk.encrypt(randomizer, &message))
    }

    /// Create an `ViewableMemo` used in anonymous transfer transactions
    pub(crate) fn new_for_transfer_note(
        input_ros: &[RecordOpening<C>],
        output_ros: &[RecordOpening<C>],
        input_creds: &[ExpirableCredential<C>],
        randomizer: C::EmbeddedCurveScalarField,
    ) -> Result<ViewableMemo<C>, TxnApiError> {
        let asset_def = get_asset_def_in_transfer_txn(input_ros)?;
        if asset_def.is_dummy() {
            return Err(TxnApiError::InternalError(
                "Transaction asset definition cannot be dummy".to_string(),
            ));
        }
        let transfer_amount: Amount = safe_sum_amount(
            input_ros
                .iter()
                .skip(1)
                .filter(|ro| !ro.asset_def.is_dummy())
                .map(|ro| ro.amount)
                .collect::<Vec<Amount>>()
                .as_slice(),
        )
        .ok_or_else(|| TxnApiError::InvalidParameter("Sum overflow for inputs.".to_string()))?;
        let viewer_pk = &asset_def.policy.viewer_pk;
        let viewer_memo = if (*viewer_pk != ViewerPubKey::default())
            && (transfer_amount > asset_def.policy.reveal_threshold)
        {
            // 1. prepare message by concatenating all fields to be revealed (details in
            // formal spec)
            let mut message: Vec<C::ScalarField> = vec![asset_def.code.0];
            // 1.1 extend message to include input records info
            for (input_ro, input_cred) in input_ros.iter().zip(input_creds.iter()).skip(1) {
                let (pk_x, pk_y) = (&input_ro.pub_key.address).into();
                let mut vals = [C::ScalarField::zero(); VIEWABLE_DATA_LEN];
                {
                    let (asset_fields, id_fields) = vals.split_at_mut(ASSET_TRACING_MAP_LEN);
                    // asset viewing fields
                    asset_fields.copy_from_slice(&[
                        pk_x,
                        pk_y,
                        C::ScalarField::from(input_ro.amount.0),
                        input_ro.blind.0,
                    ]);
                    // id viewing fields
                    id_fields.copy_from_slice(
                        &input_cred
                            .attrs
                            .iter()
                            .map(|attr| attr.0)
                            .collect::<Vec<_>>(),
                    );
                }
                let mut reveal_vals = asset_def.policy.reveal_map.hadamard_product::<C>(&vals);
                // when the record is dummy, we replace the random secret key with a dummy one
                // on the viewing memo so that viewer can recognize the record as
                // dummy. Recall that random address on the record is needed for
                // security reasons (it hides the nullifier key)
                let (dummy_x, dummy_y) = (&UserAddress::<C>::default()).into();
                if input_ro.is_dummy() {
                    reveal_vals[0] = dummy_x;
                    reveal_vals[1] = dummy_y;
                }
                message.extend_from_slice(&reveal_vals);
            }

            // 1.2 Extend message to include output records info
            for output_ro in output_ros.iter().skip(1) {
                let (pk_x, pk_y) = (&output_ro.pub_key.address).into();
                let mut vals = vec![];
                {
                    vals.extend_from_slice(&[
                        pk_x,
                        pk_y,
                        C::ScalarField::from(output_ro.amount.0),
                        output_ro.blind.0,
                    ]);
                }
                let reveal_vals = output_ro
                    .asset_def
                    .policy
                    .reveal_map
                    .hadamard_product::<C>(&vals);
                message.extend_from_slice(&reveal_vals);
            }

            // 2. encrypt the message to produce the viewer memo
            ViewableMemo(viewer_pk.encrypt(randomizer, &message))
        } else {
            Self::dummy_for_transfer_note(input_ros.len(), output_ros.len(), randomizer)
        };
        Ok(viewer_memo)
    }

    // Create a dummy viewing memo for transaction transferring non-viewing asset
    // code Use a random viewer public key to encrypt a zeroed vector.
    // Encryption scheme must be key-private (we use ElGamal which is key-private)
    // noted that the length would be the same as that of a viewing asset code to
    // avoid leaking asset code being transferred
    pub(crate) fn dummy_for_transfer_note(
        input_ros_len: usize,
        output_ros_len: usize,
        randomizer: C::EmbeddedCurveScalarField,
    ) -> ViewableMemo<C> {
        // message size starts with the second input and output, (first is always
        // non-viewing native asset code); and for inputs, both asset
        // viewing and id viewing would require VIEWING_VECTOR_LEN = REVEAL_MAP_LEN + 1
        // msg length, as upk takes two scalars; for outputs, only asset
        // viewing is on, thus only 4 scalars viewed; finally, the asset
        // code is always revealed, thus + 1 in the end.
        let bytes = randomizer.hash::<Sha512>();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[0..32]);
        let mut rng = rand_chacha::ChaChaRng::from_seed(seed);
        let random_viewer_pk = ViewerPubKey::<C>::random(&mut rng);
        let msg_size = (input_ros_len - 1) * (VIEWABLE_DATA_LEN) + (output_ros_len - 1) * 4 + 1;
        ViewableMemo(random_viewer_pk.encrypt(randomizer, &vec![C::ScalarField::zero(); msg_size]))
    }
}

/// Transfer ViewableMemo decrypted
#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CapConfig"),
    Clone(bound = "C: CapConfig"),
    PartialEq(bound = "C: CapConfig")
)]
pub struct ViewableData<C: CapConfig> {
    /// asset code of the associated policy
    pub asset_code: AssetCode<C>,
    /// visible user address
    pub user_address: Option<UserAddress<C>>,
    /// tracked amount
    pub amount: Option<Amount>,
    /// tracked blinding factor
    pub blinding_factor: Option<BlindFactor<C>>,
    /// visible attributes
    pub attributes: Vec<Option<IdentityAttribute<C>>>,
}

pub(crate) enum InOrOut {
    In,
    Out,
}

impl<C: CapConfig> ViewableData<C> {
    fn fetch_address(
        x: &C::ScalarField,
        y: &C::ScalarField,
        asset_definition: &AssetDefinition<C>,
    ) -> Result<Option<UserAddress<C>>, TxnApiError> {
        let point_affine = Affine::<C::EmbeddedCurveParam>::new(*x, *y);
        if !point_affine.is_on_curve() || !point_affine.is_in_correct_subgroup_assuming_on_curve() {
            if asset_definition
                .policy
                .reveal_map
                .is_user_address_revealed()
            {
                return Err(TxnApiError::FailedViewableMemoDecryption(
                    "Invalid user address".to_ascii_lowercase(),
                ));
            } else {
                return Ok(None);
            }
        }

        let ver_key = schnorr::VerKey::from(point_affine);
        if asset_definition.policy.is_user_address_revealed()
            || ver_key == schnorr::VerKey::default()
        {
            Ok(Some(UserAddress(ver_key)))
        } else {
            Ok(None)
        }
    }

    fn fetch_blind_factor(
        v: &C::ScalarField,
        asset_definition: &AssetDefinition<C>,
    ) -> Option<BlindFactor<C>> {
        if asset_definition
            .policy_ref()
            .reveal_map
            .is_blinding_factor_revealed()
        {
            Some(BlindFactor(*v))
        } else {
            None
        }
    }

    pub(crate) fn from_mint_note(
        visible_data: &[C::ScalarField],
        mint_note: &MintNote<C>,
    ) -> Result<Self, TxnApiError> {
        if visible_data.len() != 3 {
            return Err(TxnApiError::FailedViewableMemoDecryption(
                "Invalidviewing data len for mint note".to_ascii_lowercase(),
            ));
        }
        let asset_def = &mint_note.mint_asset_def;
        let user_address =
            ViewableData::fetch_address(&visible_data[0], &visible_data[1], asset_def)?;
        let amount = if asset_def.policy_ref().reveal_map.is_amount_revealed() {
            Some(mint_note.mint_amount)
        } else {
            None
        };
        let blinding_factor = ViewableData::fetch_blind_factor(&visible_data[2], asset_def);
        Ok(ViewableData {
            asset_code: asset_def.code,
            user_address,
            amount,
            blinding_factor,
            attributes: vec![],
        })
    }
    pub(crate) fn from_xfr_data_and_asset(
        asset_definition: &AssetDefinition<C>,
        data: &[C::ScalarField],
        in_or_out: InOrOut,
    ) -> Result<Self, TxnApiError> {
        match in_or_out {
            InOrOut::In => {
                if data.len() != VIEWABLE_DATA_LEN {
                    return Err(TxnApiError::FailedViewableMemoDecryption(format!(
                        "Internal Error: plaintext data unexpected length {}, expected {}",
                        data.len(),
                        VIEWABLE_DATA_LEN
                    )));
                }
            },
            InOrOut::Out => {
                if data.len() != 4 {
                    return Err(TxnApiError::FailedViewableMemoDecryption(format!(
                        "Internal Error: plaintext data unexpected length {}, expected {}",
                        data.len(),
                        4
                    )));
                }
            },
        }
        let user_address = ViewableData::fetch_address(&data[0], &data[1], asset_definition)?;

        let amount = if asset_definition.policy.is_amount_revealed() {
            let big_int = data[2].into_repr();
            let mut u128_max_bits_le = vec![true; 128];
            u128_max_bits_le.resize(256, false);
            // if big_int > BigInteger256::from_bits_le(&u128_max_bits_le) {
            if big_int
                > <<C::ScalarField as PrimeField>::BigInt as BigInteger>::from_bits_le(
                    &u128_max_bits_le,
                )
            {
                return Err(TxnApiError::FailedViewableMemoDecryption(
                    "Invalid amount".to_ascii_lowercase(),
                ));
            }
            let mut amount_bytes = [0u8; 16];
            amount_bytes.copy_from_slice(&big_int.to_bytes_le()[0..16]);
            Some(Amount::from(u128::from_le_bytes(amount_bytes)))
        } else {
            None
        };

        let blinding_factor = ViewableData::fetch_blind_factor(&data[3], asset_definition);

        let mut attributes = vec![];
        match in_or_out {
            InOrOut::In => {
                for (i, attr) in data[4..].iter().enumerate() {
                    if asset_definition
                        .policy
                        .reveal_map
                        .is_ith_attribute_revealed(i)?
                    {
                        attributes.push(Some(IdentityAttribute(*attr)));
                    } else {
                        attributes.push(None)
                    }
                }
            },
            _ => (0..ATTRS_LEN).for_each(|_| attributes.push(None)),
        };

        Ok(ViewableData {
            asset_code: asset_definition.code,
            user_address,
            amount,
            blinding_factor,
            attributes,
        })
    }
}
// TODO: (alex) add this after Philippe's MT MR merged
/// The proof of membership in an accumulator (Merkle tree) for an asset record
#[tagged("RECMEMO")]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
/// Encrypted Message for owners of transaction outputs
pub struct ReceiverMemo(pub(crate) aead::Ciphertext);

impl ReceiverMemo {
    /// Create a new ReceiverMemo from an Record Opening.
    /// * `rng` - a pseudo-random number generator
    /// * `ro` - an ooening of an asset record
    /// * `label` - optional, arbitrary label as authenticated associated data
    ///   to the ciphertext
    pub fn from_ro<R: CryptoRng + RngCore, C: CapConfig>(
        rng: &mut R,
        ro: &RecordOpening<C>,
        label: &[u8],
    ) -> Result<Self, TxnApiError> {
        let ro_bytes = bincode::serialize(&ro).map_err(|_| {
            DeserializationError::SerdeError(
                "Unable to deserialize the RecordOpening during ReceiverMemo creation".to_string(),
            )
        })?;
        let ciphertext = ro.pub_key.encrypt(rng, &ro_bytes, label)?;
        Ok(ReceiverMemo(ciphertext))
    }

    /// Decrypts the receiver memo
    /// * `keypair` - Owner's keypair containing a decryption key
    /// * `rc` - expected asset record commitment to check against
    /// * `label` - optional, arbitrary label as authenticated associated data
    /// Return Error if memo info does not match RC or public key
    pub fn decrypt<C: CapConfig>(
        &self,
        keypair: &UserKeyPair<C>,
        rc: &RecordCommitment<C>,
        label: &[u8],
    ) -> Result<RecordOpening<C>, TxnApiError> {
        let ro_bytes = keypair.enc_keypair.decrypt(&self.0, label).map_err(|_| {
            TxnApiError::FailedPrimitives(
                "Failed decryption, probably wrong keypair for the receiver memo".to_string(),
            )
        })?;

        let ro: RecordOpening<C> = bincode::deserialize(&ro_bytes).map_err(|_| {
            DeserializationError::SerdeError(
                "Unable to deserialize RecordOpening during ReceiverMemo decryption".to_string(),
            )
        })?;

        if ro.pub_key != keypair.pub_key() {
            return Err(TxnApiError::InternalError(
                "Wrong public key in ReceiverMemo plaintext".to_string(),
            ));
        }
        if ro.derive_record_commitment() != *rc {
            return Err(TxnApiError::InvalidParameter(
                "ReceiverMemo Error:Wrong RC opening, mismatched commitment".to_string(),
            ));
        }
        Ok(ro)
    }
}

/// All necessary information for the input record that is meant to pay
/// transaction fee in all different transactions.
#[derive(Derivative)]
#[derivative(Debug(bound = "C: CapConfig"))]
pub struct FeeInput<'kp, C: CapConfig> {
    /// Record opening
    pub ro: RecordOpening<C>,
    /// Accumulator membership proof (i.e. Merkle Proof) of the record
    /// commitment
    pub acc_member_witness: AccMemberWitness<C::ScalarField>,
    /// Reference of owner's key pair
    pub owner_keypair: &'kp UserKeyPair<C>,
}

impl<'kp, C: CapConfig> Clone for FeeInput<'kp, C> {
    fn clone(&self) -> Self {
        Self {
            ro: self.ro.clone(),
            acc_member_witness: self.acc_member_witness.clone(),
            owner_keypair: self.owner_keypair,
        }
    }
}
/// Fee structure containing fee input spending info, fee to pay and change
/// record opening
pub struct TxnFeeInfo<'kp, C: CapConfig> {
    /// Fee input spending info
    pub fee_input: FeeInput<'kp, C>,
    /// Fee to pay
    pub fee_amount: Amount,
    /// Fee change record opening
    pub fee_chg_ro: RecordOpening<C>,
}

impl<'kp, C: CapConfig> TxnFeeInfo<'kp, C> {
    /// Create a new Fee struct from fee input and fee to pay
    pub fn new<R: CryptoRng + RngCore>(
        rng: &mut R,
        fee_input: FeeInput<'kp, C>,
        fee: Amount,
    ) -> Result<(Self, RecordOpening<C>), TxnApiError> {
        if fee_input.ro.amount < fee {
            return Err(TxnApiError::InvalidParameter(
                "not enough funds in fee input to pay for fees".to_string(),
            ));
        }
        let fee_chg_ro = RecordOpening::new(
            rng,
            fee_input.ro.amount - fee,
            AssetDefinition::native(),
            fee_input.ro.pub_key.clone(),
            FreezeFlag::Unfrozen,
        );
        Ok((
            TxnFeeInfo {
                fee_input,
                fee_amount: fee,
                fee_chg_ro: fee_chg_ro.clone(),
            },
            fee_chg_ro,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::prelude::Config;
    use ark_std::{convert::TryInto, test_rng};

    type F = <Config as CapConfig>::ScalarField;

    mod reveal_map {

        use super::*;

        #[test]
        fn getters() {
            let mut reveal_map = RevealMap::default();
            assert!(!reveal_map.is_user_address_revealed());
            assert!(!reveal_map.is_amount_revealed());
            assert!(!reveal_map.is_blinding_factor_revealed());
            for i in 0..ATTRS_LEN {
                assert!(!reveal_map.is_ith_attribute_revealed(i).unwrap());
            }
            assert!(reveal_map.is_ith_attribute_revealed(ATTRS_LEN).is_err());

            reveal_map.reveal_all();
            assert!(reveal_map.is_user_address_revealed());
            assert!(reveal_map.is_amount_revealed());
            assert!(reveal_map.is_blinding_factor_revealed());

            for i in 0..ATTRS_LEN {
                assert!(reveal_map.is_ith_attribute_revealed(i).unwrap());
            }
        }

        #[test]
        fn bitmap_to_scalar_conv() {
            let mut reveal_map = RevealMap::default();
            assert_eq!(
                reveal_map.to_scalar::<Config>(), // (00)0,000,000,000 = 0
                F::zero()
            );
            reveal_map.reveal_record_opening();
            reveal_map.reveal_ith_id_attribute(1).unwrap();
            reveal_map.reveal_ith_id_attribute(2).unwrap();
            reveal_map.reveal_ith_id_attribute(4).unwrap();
            reveal_map.reveal_ith_id_attribute(5).unwrap();
            reveal_map.reveal_ith_id_attribute(6).unwrap();
            assert_eq!(
                reveal_map.to_scalar::<Config>(), // (11)1,101,101,110 = 3950
                F::from(3950u32)
            );
            reveal_map.reveal_all_id_attributes();
            assert_eq!(
                reveal_map.to_scalar::<Config>(), // (11)1,111,111,111 = 4095
                F::from(4095u32)
            );
        }

        #[test]
        fn test_hadamard_product() {
            let zero = F::zero();
            let mut reveal_map = RevealMap::default();
            reveal_map.reveal_all();
            let mut rng = test_rng();
            let mut attrs = [zero; VIEWABLE_DATA_LEN];
            for i in 0..VIEWABLE_DATA_LEN {
                let rand_u64 = rng.next_u64();
                attrs[i] = F::from(rand_u64);
            }
            assert_eq!(reveal_map.hadamard_product::<Config>(&attrs), attrs);
            assert_eq!(
                RevealMap::default().hadamard_product::<Config>(&attrs),
                [zero; VIEWABLE_DATA_LEN]
            );
            let mut expected_mapped_vals = attrs.clone();
            expected_mapped_vals[4] = zero;
            expected_mapped_vals[7] = zero;
            expected_mapped_vals[10] = zero;
            expected_mapped_vals[11] = zero;
            let mut reveal_map = RevealMap::default();
            reveal_map.reveal_record_opening();
            reveal_map.reveal_ith_id_attribute(1).unwrap();
            reveal_map.reveal_ith_id_attribute(2).unwrap();
            reveal_map.reveal_ith_id_attribute(4).unwrap();
            reveal_map.reveal_ith_id_attribute(5).unwrap();
            assert_eq!(
                reveal_map.hadamard_product::<Config>(&attrs),
                expected_mapped_vals
            );
        }
    }

    mod visible_data {
        use super::*;
        use crate::{
            proof,
            proof::universal_setup_for_staging,
            utils::params_builder::{MintParamsBuilder, PolicyRevealAttr},
        };

        #[test]
        fn mint() -> Result<(), TxnApiError> {
            let rng = &mut ark_std::test_rng();
            let tree_depth = 10;
            let max_degree = 32770;
            let universal_param = universal_setup_for_staging::<_, Config>(max_degree, rng)?;
            let (proving_key, ..) =
                proof::mint::preprocess::<Config>(&universal_param, tree_depth)?;

            let input_amount = Amount::from(10u64);
            let fee = Amount::from(4u64);
            let mint_amount = Amount::from(35u64);
            let minter_keypair = UserKeyPair::generate(rng);
            let receiver_keypair = UserKeyPair::generate(rng);
            let viewer_keypair = ViewerKeyPair::generate(rng);

            let builder = MintParamsBuilder::new(
                rng,
                tree_depth,
                input_amount,
                fee,
                mint_amount,
                &minter_keypair,
                &receiver_keypair,
                &viewer_keypair,
            )
            .policy_reveal(PolicyRevealAttr::UserAddr);

            let (note, ..) = builder.build_mint_note(rng, &proving_key)?;
            let receiver_address = receiver_keypair.address();
            let (x, y) = (&receiver_address).into();
            let blinding_factor = F::rand(rng);
            let raw_visible_data = vec![x, y, blinding_factor];
            let visible_data = ViewableData::from_mint_note(&raw_visible_data, &note);
            assert!(visible_data.is_ok());
            let visible_data = visible_data.unwrap();
            assert_eq!(visible_data.user_address.unwrap(), receiver_address);
            assert_eq!(visible_data.blinding_factor, None);
            assert_eq!(visible_data.amount, None);

            // Wrong number of elements
            let wrong_raw_visible_data = vec![x, y, blinding_factor, F::zero()];
            assert!(ViewableData::from_mint_note(&wrong_raw_visible_data, &note).is_err());

            // Wrong address
            let wrong_raw_visible_data = vec![F::zero(), F::zero(), blinding_factor];
            assert!(ViewableData::from_mint_note(&wrong_raw_visible_data, &note).is_err());

            Ok(())
        }

        #[test]
        fn transfer() {
            let mut rng = ark_std::test_rng();
            let viewer_keypair = ViewerKeyPair::<Config>::generate(&mut rng);
            let minter_keypair = CredIssuerKeyPair::generate(&mut rng);
            let freezer_keypair = FreezerKeyPair::generate(&mut rng);
            let (..) = AssetCode::<Config>::random(&mut rng);
            let mut policy = AssetPolicy::default()
                .set_viewer_pub_key(viewer_keypair.pub_key())
                .set_cred_creator_pub_key(minter_keypair.pub_key())
                .set_freezer_pub_key(freezer_keypair.pub_key());

            policy.reveal_map.reveal_user_address();

            let (asset_code, _) = AssetCode::random(&mut rng);
            let asset_def = AssetDefinition::new(asset_code, policy).unwrap();

            // Wrong length for In
            const WRONG_LEN_IN: usize = VIEWABLE_DATA_LEN + 1;
            let data = &[F::from(0_u64); WRONG_LEN_IN];
            let transfer_data =
                ViewableData::from_xfr_data_and_asset(&asset_def, data, InOrOut::In);
            assert!(transfer_data.is_err());

            // Wrong length for Out
            const WRONG_LEN_OUT: usize = VIEWABLE_DATA_LEN + 1;
            let data = &[F::from(0_u64); WRONG_LEN_OUT];
            let transfer_data =
                ViewableData::from_xfr_data_and_asset(&asset_def, data, InOrOut::Out);
            assert!(transfer_data.is_err());

            // Wrong user address
            let wrong_data_user_address = &[F::from(0_u64); VIEWABLE_DATA_LEN];
            let transfer_data = ViewableData::from_xfr_data_and_asset(
                &asset_def,
                wrong_data_user_address,
                InOrOut::In,
            );
            assert!(transfer_data.is_err());

            let user_address = UserPubKey::<Config>::default().address;
            let (x, y) = (&user_address).into();

            // Wrong amount
            let wrong_amount = F::from(u128::MAX) + F::from(1_u128);
            let mut data = vec![x, y, wrong_amount];
            data.extend_from_slice(&[F::from(1_u128); VIEWABLE_DATA_LEN - 3]);
            let transfer_data =
                ViewableData::from_xfr_data_and_asset(&asset_def, &data, InOrOut::In);
            assert!(transfer_data.is_ok());

            // Good parameters
            let mut data = vec![x, y];
            data.extend_from_slice(&[F::from(1_u64); VIEWABLE_DATA_LEN - 2]);
            let transfer_data =
                ViewableData::from_xfr_data_and_asset(&asset_def, &data, InOrOut::In);
            assert!(transfer_data.is_ok());
        }
    }

    #[quickcheck]
    fn id_attr_from_to_bytes_is_deterministic(bytes: Vec<u8>) -> bool {
        let empty_bytes_should_fail =
            bytes.is_empty() && IdentityAttribute::<Config>::new(&bytes).is_err();
        let extra_bytes_should_fail = bytes.len()
            > <Config as CapConfig>::PER_ATTR_BYTE_CAPACITY as usize
            && IdentityAttribute::<Config>::new(&bytes).is_err();

        empty_bytes_should_fail
            || extra_bytes_should_fail
            || bytes
                == IdentityAttribute::<Config>::new(&bytes)
                    .unwrap()
                    .value()
                    .unwrap()
    }

    #[test]
    fn test_expirable_credential() -> Result<(), TxnApiError> {
        let mut rng = ark_std::test_rng();
        let user_keypair = UserKeyPair::<Config>::generate(&mut rng);
        let minter_keypair = CredIssuerKeyPair::<Config>::generate(&mut rng);
        let mut attrs = IdentityAttribute::random_vector(&mut rng);
        let cred_expiry = 1234u64;
        let now = 1000u64;

        // good credential should be verified
        let cred = ExpirableCredential::create(
            user_keypair.address(),
            attrs.clone(),
            cred_expiry,
            &minter_keypair,
        )?;
        assert!(cred.verify(now).is_ok());

        // check is_expired function
        assert_eq!(cred.is_expired(cred.expiry - 1), false);
        assert_eq!(cred.is_expired(cred.expiry + 1), true);

        // invalid credential with wrong upk should fail
        let mut cred2 = cred.clone();
        cred2.user_addr = UserKeyPair::<Config>::generate(&mut rng).address();
        assert!(cred2.verify(now).is_err());

        // invalid credential with wrong attribute should fail
        let mut cred3 = cred.clone();
        cred3.attrs.swap(1, 3);
        assert!(cred3.verify(now).is_err());

        // expired credential should fail
        let cred4 = cred.clone();
        assert!(cred4.verify(cred.expiry + 1).is_err());

        // credential with a wrong credential creator should fail
        let mut cred5 = cred.clone();
        cred5.creator_pk = CredIssuerKeyPair::generate(&mut rng).pub_key();
        assert!(cred5.verify(now).is_err());

        // overflowed attribute bytes should fail
        attrs.push(IdentityAttribute::random(&mut rng));
        assert!(ExpirableCredential::create(
            user_keypair.address(),
            attrs,
            1234,
            &CredIssuerKeyPair::generate(&mut rng)
        )
        .is_err());

        Ok(())
    }

    #[test]
    fn test_asset_code() {
        let rng = &mut ark_std::test_rng();
        let cap_token_description = b"cap_usdx";
        let seed = AssetCodeSeed::<Config>::generate(rng);
        let internal_asset_code = InternalAssetCode::new(seed, cap_token_description);
        let asset_code = AssetCode::new_domestic_from_internal(&internal_asset_code);
        assert!(asset_code.verify_domestic(&internal_asset_code).is_ok());
        let bad_internal = InternalAssetCode(F::zero());
        assert!(asset_code.verify_domestic(&bad_internal).is_err());

        let external_description = b"ERC20 token";
        let external_asset_code = AssetCode::<Config>::new_foreign(external_description);
        assert!(external_asset_code
            .verify_foreign(external_description)
            .is_ok());
        assert!(external_asset_code
            .verify_foreign(cap_token_description)
            .is_err());
    }

    #[test]
    fn test_asset_policy() {
        let mut rng = ark_std::test_rng();
        let viewer_keypair = ViewerKeyPair::<Config>::generate(&mut rng);
        let minter_keypair = CredIssuerKeyPair::generate(&mut rng);
        let freezer_keypair = FreezerKeyPair::generate(&mut rng);
        let (..) = AssetCode::<Config>::random(&mut rng);
        let policy = AssetPolicy::default()
            .set_viewer_pub_key(viewer_keypair.pub_key())
            .set_cred_creator_pub_key(minter_keypair.pub_key())
            .set_freezer_pub_key(freezer_keypair.pub_key());

        assert_eq!(*policy.viewer_pub_key(), viewer_keypair.pub_key());
        assert_eq!(*policy.cred_creator_pub_key(), minter_keypair.pub_key());
        assert_eq!(*policy.freezer_pub_key(), freezer_keypair.pub_key());

        assert!(policy.is_viewer_pub_key_set());
        assert!(policy.is_cred_creator_pub_key_set());
        assert!(policy.is_freezer_pub_key_set());

        // All the public keys are correctly set
        let policy = policy.reveal_user_address();
        assert!(policy.is_ok());

        let policy = policy.unwrap().reveal_amount();
        assert!(policy.is_ok());

        let policy = policy.unwrap().reveal_blinding_factor();
        assert!(policy.is_ok());

        let policy = policy.unwrap().reveal_record_opening();
        assert!(policy.is_ok());

        let policy = policy.unwrap().reveal_all();
        assert!(policy.is_ok());

        let policy_aux = policy.unwrap().clone();
        for i in 0..ATTRS_LEN {
            let policy = policy_aux.clone().reveal_ith_attribute(i);
            assert!(policy.is_ok());
        }
        let policy = policy_aux.reveal_all_attributes();
        assert!(policy.is_ok());

        // The public keys are unset, errors are thrown
        let policy = policy
            .unwrap()
            .set_cred_creator_pub_key(CredIssuerPubKey::default());
        let policy_aux = policy.clone();
        for i in 0..ATTRS_LEN {
            let policy = policy_aux.clone().reveal_ith_attribute(i);
            assert!(policy.is_err());
        }
        let policy = policy_aux.clone().reveal_all_attributes();
        assert!(policy.is_err());

        let policy = policy_aux;
        let policy = policy
            .set_cred_creator_pub_key(minter_keypair.pub_key())
            .set_viewer_pub_key(ViewerPubKey::default());
        let policy_aux = policy.clone();
        for i in 0..ATTRS_LEN {
            let policy = policy_aux.clone().reveal_ith_attribute(i);
            assert!(policy.is_err());
        }

        let policy = policy_aux.clone().reveal_all_attributes();
        assert!(policy.is_err());

        let policy = policy_aux.clone().reveal_user_address();
        assert!(policy.is_err());

        let policy = policy_aux.clone().reveal_amount();
        assert!(policy.is_err());

        let policy = policy_aux.reveal_blinding_factor();
        assert!(policy.is_err());
    }

    #[test]
    fn test_amount() {
        // Arithmetics
        let rng = &mut ark_std::test_rng();
        let a = u64::rand(rng) as u128 / 2;
        let a_amount = Amount::from(a);
        let b = a + u32::rand(rng) as u128;
        let b_amount = Amount::from(b);
        let c = a + b;
        let c_amount = a_amount + b_amount;
        assert_eq!(c_amount, c.into());
        let c = b - a;
        let c_amount = b_amount - a_amount;
        assert_eq!(c_amount, c.into());
        let c = b * a;
        let c_amount = b_amount * a;
        assert_eq!(c_amount, c.into());
        let c = b / a;
        let c_amount = b_amount / a;
        assert_eq!(c_amount, c.into());

        // Conversion to U256
        let a = primitive_types::U256::from(u64::MAX);
        assert_eq!(Amount::try_from(a).unwrap(), Amount::from(u64::MAX));
        let b = primitive_types::U256::from(u64::MAX - 1);
        let b_amount: Amount = b.try_into().unwrap();
        assert_eq!(b_amount, Amount::from(u64::MAX - 1));
        assert_eq!(b, primitive_types::U256::from(b_amount));
        let c = a * a * b;
        assert!(Amount::try_from(c).is_err());
    }

    #[test]
    fn test_serde() {
        let mut rng = ark_std::test_rng();

        // amount value related
        let amount_value = Amount::from(u128::rand(&mut rng));
        let ser_bytes = bincode::serialize(&amount_value).unwrap();
        let amount_value_rec: Amount = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(amount_value, amount_value_rec);

        // asset code related
        let asset_code_seed = AssetCodeSeed::generate(&mut rng);
        let ser_bytes = bincode::serialize(&asset_code_seed).unwrap();
        let asset_code_seed_rec: AssetCodeSeed<Config> =
            bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(asset_code_seed, asset_code_seed_rec);

        // record related
        let asset_def = AssetDefinition::rand_for_test(&mut rng);
        let user_keypair = UserKeyPair::generate(&mut rng);

        let ro = RecordOpening::new(
            &mut rng,
            Amount::from(23u64),
            asset_def,
            user_keypair.pub_key(),
            FreezeFlag::Unfrozen,
        );
        let rc = RecordCommitment::from(&ro);

        // credential related
        let minter_keypair = CredIssuerKeyPair::generate(&mut rng);
        let attrs = IdentityAttribute::random_vector(&mut rng);
        let cred_expiry = 1234u64;
        let cred = ExpirableCredential::create(
            user_keypair.address(),
            attrs.clone(),
            cred_expiry,
            &minter_keypair,
        )
        .unwrap();

        // memo related
        let viewing_memo = {
            let mut asset_def = AssetDefinition::native();
            asset_def.policy.viewer_pk = ViewerPubKey::default();
            let ro = RecordOpening::new(
                &mut rng,
                Amount::from(23u64),
                asset_def.clone(),
                user_keypair.pub_key(),
                FreezeFlag::Unfrozen,
            );
            let randomizer = <Config as CapConfig>::EmbeddedCurveScalarField::rand(&mut rng);
            ViewableMemo::new_for_transfer_note(&[ro.clone()], &[ro], &[cred.clone()], randomizer)
                .unwrap()
        };
        let receiver_memo = ReceiverMemo::from_ro(&mut rng, &ro, &[]).unwrap();

        let ser_bytes = bincode::serialize(&ro).unwrap();
        let de: RecordOpening<Config> = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de, ro);
        let ser_bytes = bincode::serialize(&rc).unwrap();
        let de: RecordCommitment<Config> = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de, rc);
        let ser_bytes = bincode::serialize(&cred).unwrap();
        let de: ExpirableCredential<Config> = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de, cred);
        let ser_bytes = bincode::serialize(&viewing_memo).unwrap();
        let de: ViewableMemo<Config> = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de, viewing_memo);
        let ser_bytes = bincode::serialize(&receiver_memo).unwrap();
        let de: ReceiverMemo = bincode::deserialize(&ser_bytes[..]).unwrap();
        assert_eq!(de, receiver_memo);
    }
}
