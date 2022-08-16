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

/// Maximum length of a reveal map := (b_0,b_1,b_2, attr_map) where first three
/// bits enables asset viewing, namely revealing (upk, at, \gamma) and the
/// attr_map is a bitmap for all attributes issued in a identity credential.
pub const REVEAL_MAP_LEN: usize = 3 + ATTRS_LEN;

/// length in scalars of (address.x, address.y, amount, blinding factor)
pub(crate) const ASSET_TRACING_MAP_LEN: usize = 4;

/// length in scalars of decrypted transfer viewing
/// (address.x, address.y, amount, blinding factor,
/// id_attr_1,...,id_attr_{ATTRS_LEN}
pub const VIEWABLE_DATA_LEN: usize = REVEAL_MAP_LEN + 1;

/// the number of identity attributes
pub const ATTRS_LEN: usize = 8;

/// The upper bound on the time unit difference between expiry and the current
/// timestamp.
pub const MAX_TIMESTAMP_LEN: usize = 20;

/// Amount value size (in bits)
pub(crate) const AMOUNT_LEN: usize = 127;

/// Minted Asset Code domain separator
pub const DOM_SEP_DOMESTIC_ASSET: &[u8] = b"DOMESTIC_ASSET";

/// External Asset Code domain separator
pub const DOM_SEP_FOREIGN_ASSET: &[u8] = b"FOREIGN_ASSET";
