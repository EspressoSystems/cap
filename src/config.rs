// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Configuration

use ark_ec::{PairingEngine, TEModelParameters};
use ark_ff::{FpParameters, PrimeField, SquareRootField};
use jf_rescue::RescueParameter;

use crate::structs::AssetCode;

/// Configuration for CAP system
pub trait CapConfig: Sized + Clone {
    /// Pairing-friendly curve the CAP proof will be generated over
    type PairingCurve: PairingEngine<Fr = Self::ScalarField>;
    /// Curve parameter for Jubjub curve embedded in `PairingCurve`
    type JubjubParam: TEModelParameters<ScalarField = Self::JubjubScalarField, BaseField = Self::ScalarField>
        + Clone;

    /// Scalar field over which CAP circuit is over
    type ScalarField: PrimeField + SquareRootField + RescueParameter;
    /// Scalar field of jubjub curve
    type JubjubScalarField: PrimeField + SquareRootField;

    /// Length of a `ScalarField` representation in bytes
    const SCALAR_REPR_BYTE_LEN: u32 =
        (<Self::ScalarField as PrimeField>::Params::MODULUS_BITS + 7) / 8;
    // NOTE: -1 from BLS byte capacity to allow room for padding byte in all case,
    // and avoid extra block.
    /// number of byte can each `identityAttribute` take.
    const PER_ATTR_BYTE_CAPACITY: u32 =
        (<Self::ScalarField as PrimeField>::Params::CAPACITY / 8) - 1;
    /// Native asset code, cannot be 0 as then code is identical to default code
    const NATIVE_ASSET_CODE: AssetCode<Self> = AssetCode(Self::ScalarField::from(1u32));
    /// Dummy asset code, cannot be 0 (default) or 1(native)
    const DUMMY_ASSET_CODE: AssetCode<Self> = AssetCode(Self::ScalarField::from(2u32));
}

/// A concrete instantation of `CapConfig`
#[cfg(feature = "bn254")]
#[derive(Debug, Clone, PartialEq)]
pub struct Config;

#[cfg(feature = "bn254")]
impl CapConfig for Config {
    type PairingCurve = ark_bn254::Bn254;
    type JubjubParam = ark_ed_on_bn254::EdwardsParameters;
    type ScalarField = ark_bn254::Fr;
    type JubjubScalarField = ark_ed_on_bn254::Fr;
}

/// A concrete instantation of `CapConfig`
#[cfg(feature = "bls12_377")]
#[derive(Debug, Clone, PartialEq)]
pub struct Config;

#[cfg(feature = "bls12_377")]
impl CapConfig for Config {
    type PairingCurve = ark_bls12_377::Bls12_377;
    type JubjubParam = ark_ed_on_bls12_377::EdwardsParameters;
    type ScalarField = ark_bls12_377::Fr;
    type JubjubScalarField = ark_ed_on_bls12_377::Fr;
}

/// A concrete instantation of `CapConfig`
#[cfg(feature = "bls12_381")]
#[derive(Debug, Clone, PartialEq)]
pub struct Config;

#[cfg(feature = "bls12_381")]
impl CapConfig for Config {
    type PairingCurve = ark_bls12_381::Bls12_377;
    type JubjubParam = ark_ed_on_bls12_381::EdwardsParameters;
    type ScalarField = ark_bls12_381::Fr;
    type JubjubScalarField = ark_ed_on_bls12_381::Fr;
}
