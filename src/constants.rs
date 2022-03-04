// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Constants used across the whole library
use crate::{structs::AssetCode, BaseField};
use ark_ff::{FpParameters, PrimeField};

/// The number of bits that can be reliably stored for BaseField. (Should equal
/// SELF::MODULUS_BITS - 1)
pub const BLS_SCALAR_BIT_CAPACITY: u32 = <BaseField as PrimeField>::Params::CAPACITY;

/// Length of a ScalarField
pub const BLS_SCALAR_BIT_LEN: u32 = <BaseField as PrimeField>::Params::MODULUS_BITS;

/// Length of a BaseField representation in bytes
pub const BLS_SCALAR_REPR_BYTE_LEN: u32 = if BLS_SCALAR_BIT_LEN % 8 == 0 {
    BLS_SCALAR_BIT_LEN / 8
} else {
    BLS_SCALAR_BIT_LEN / 8 + 1
};

/// Maximum length of a reveal map := (b_0,b_1,b_2, attr_map) where first three
/// bits enables asset tracing, namely revealing (upk, at, \gamma) and the
/// attr_map is a bitmap for all attributes issued in a identity credential.
pub const REVEAL_MAP_LEN: usize = 3 + ATTRS_LEN;

/// length in scalars of (address.x, address.y, amount, blinding factor)
pub(crate) const ASSET_TRACING_MAP_LEN: usize = 4;

/// length in scalars of decrypted transfer audit
/// (address.x, address.y, amount, blinding factor,
/// id_attr_1,...,id_attr_{ATTRS_LEN}
pub const AUDIT_DATA_LEN: usize = REVEAL_MAP_LEN + 1;

/// the number of identity attributes
pub const ATTRS_LEN: usize = 8;

/// The upper bound on the time unit difference between expiry and the current
/// timestamp.
pub const MAX_TIMESTAMP_LEN: usize = 20;

/// Amount value size (in bits)
pub(crate) const AMOUNT_LEN: usize = 63;

// 31 bytes a chunk
pub(crate) const BLS_SCALAR_BYTE_CAPACITY: usize = BLS_SCALAR_BIT_CAPACITY as usize / 8;

// NOTE: -1 from BLS byte capacity to allow room for padding byte in all case,
// and avoid extra block.
/// number of byte can each `identityAttribute` take.
pub const PER_ATTR_BYTE_CAPACITY: usize = BLS_SCALAR_BYTE_CAPACITY - 1;

/// Native asset code, cannot be 0 as then code is identical to default code
pub const NATIVE_ASSET_CODE: AssetCode = AssetCode(BLS_SCALAR_ONE);

/// Dummy asset code, cannot be 0 (default) or 1(native)
pub const DUMMY_ASSET_CODE: AssetCode = AssetCode(BLS_SCALAR_TWO);

/// Minted Asset Code domain separator
pub const DOM_SEP_DOMESTIC_ASSET: &[u8] = b"DOMESTIC_ASSET";

/// External Asset Code domain separator
pub const DOM_SEP_FOREIGN_ASSET: &[u8] = b"FOREIGN_ASSET";

// TODO: (alex) currently upstream doesn't support, turn this on after
// https://github.com/arkworks-rs/algebra/issues/296 is supported.
//
//// / Native asset definition with asset code equals to `BaseField::one()` and
// /// asset policy to be default/empty. To be agreed upon, shared and exported
// to /// the Ledger system.
// pub const NATIVE_ASSET_DEFINITION: AssetDefinition = AssetDefinition {
//     code: AssetCode(BLS_SCALAR_ONE),
//     policy: AssetPolicy {
//         auditor_pk: AuditorPubKey(elgamal::EncKey {
//             key: JUBJUB_POINT_ZERO,
//         }),
//         cred_pk: CredIssuerPubKey(schnorr_dsa::VerKey(JUBJUB_POINT_ZERO)),
//         freezer_pk: FreezerPubKey(JUBJUB_POINT_ZERO),
//         reveal_map: RevealMap([false; REVEAL_MAP_LEN + 1]),
//     },
// };

// value = BaseField::zero()
// const BLS_SCALAR_ZERO: BaseField = ark_ff::field_new!(BaseField, "0");
// value = BaseField::one()
const BLS_SCALAR_ONE: BaseField = ark_ff::field_new!(BaseField, "1");
const BLS_SCALAR_TWO: BaseField = ark_ff::field_new!(BaseField, "2");
// value = JubjubPoint::zero()
// const JUBJUB_POINT_ZERO: JubjubPoint = JubjubPoint::new(
//     BLS_SCALAR_ZERO,
//     BLS_SCALAR_ONE,
//     BLS_SCALAR_ZERO,
//     BLS_SCALAR_ONE,
// );
