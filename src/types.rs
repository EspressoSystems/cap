// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use jf_primitives::{merkle_tree, schnorr_dsa};

/// type alias for scalar field of the jubjub curve
#[cfg(feature = "bn254")]
pub type ScalarField = ark_ed_on_bn254::Fr;

/// type alias for scalar field of the bls curve
#[cfg(feature = "bn254")]
pub type BaseField = ark_bn254::Fr;

/// type alias for jubjub curve parameter
#[cfg(feature = "bn254")]
pub type CurveParam = ark_ed_on_bn254::EdwardsParameters;

/// type alias for pairing parameter
#[cfg(feature = "bn254")]
pub type PairingEngine = ark_bn254::Bn254;

/// type alias for scalar field of the jubjub curve
#[cfg(feature = "bls12_377")]
pub type ScalarField = ark_ed_on_bls12_377::Fr;

/// type alias for scalar field of the bls curve
#[cfg(feature = "bls12_377")]
pub type BaseField = ark_bls12_377::Fr;

/// type alias for jubjub curve parameter
#[cfg(feature = "bls12_377")]
pub type CurveParam = ark_ed_on_bls12_377::EdwardsParameters;

/// type alias for pairing parameter
#[cfg(feature = "bls12_377")]
pub type PairingEngine = ark_bls12_377::Bls12_377;

/// type alias for scalar field of the jubjub curve
#[cfg(feature = "bls12_381")]
pub type ScalarField = ark_ed_on_bls12_381::Fr;

/// type alias for scalar field of the bls curve
#[cfg(feature = "bls12_381")]
pub type BaseField = ark_bls12_381::Fr;

/// type alias for jubjub curve parameter
#[cfg(feature = "bls12_381")]
pub type CurveParam = ark_ed_on_bls12_381::EdwardsParameters;

/// type alias for pairing parameter
#[cfg(feature = "bls12_381")]
pub type PairingEngine = ark_bls12_381::Bls12_381;

// Re-export the types with associated parameters

// merkle tree
/// Represents the value for a node in the merkle tree
pub type NodeValue = merkle_tree::NodeValue<BaseField>;
/// The proof of membership in an accumulator (Merkle tree) for an asset record
pub type AccMemberWitness = merkle_tree::AccMemberWitness<BaseField>;
/// An authentication path of a ternary Merkle tree.
pub type MerklePath = merkle_tree::MerklePath<BaseField>;
/// Merkle Tree.
pub type MerkleTree = merkle_tree::MerkleTree<BaseField>;
/// Elements needed for a full commitment to MerkleTree
pub type MerkleCommitment = merkle_tree::MerkleCommitment<BaseField>;
/// MerkleTree leaf element
pub type MerkleLeaf = merkle_tree::MerkleLeaf<BaseField>;
/// MerkleTree leaf element with associated authenticated path
pub type MerkleLeafProof = merkle_tree::MerkleLeafProof<BaseField>;
/// proof sufficient, with commitment, to define sparse MerkleTree
pub type MerkleFrontier = merkle_tree::MerkleFrontier<BaseField>;

// signature
/// The signature of Schnorr signature scheme
pub type Signature = schnorr_dsa::Signature<CurveParam>;
/// The verification key of Schnorr signature scheme
pub type VerKey = schnorr_dsa::VerKey<CurveParam>;
/// The key pair of Schnorr signature scheme
pub type KeyPair = schnorr_dsa::KeyPair<CurveParam>;

/// plonk
pub type VerifyingKey = jf_plonk::proof_system::structs::VerifyingKey<PairingEngine>;
