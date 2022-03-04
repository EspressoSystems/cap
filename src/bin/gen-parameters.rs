// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Configurable Asset Privacy (CAP) library.

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

use jf_cap::{errors::TxnApiError, parameters::*};
use std::{path::PathBuf, str::FromStr};
use structopt::StructOpt;

#[derive(Debug)]
enum Circuit {
    Transfer,
    Freezing,
    Mint,
}

impl FromStr for Circuit {
    type Err = TxnApiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "transfer" => Ok(Circuit::Transfer),
            "freezing" => Ok(Circuit::Freezing),
            "mint" => Ok(Circuit::Mint),
            _ => Err(TxnApiError::InvalidParameter(format!(
                "Circuit '{}' not available.",
                s
            ))), // TODO is this the correct error?
        }
    }
}

#[derive(StructOpt, Debug)]
#[structopt(
    about = "Tool to handle public zkp-parameters.",
    rename_all = "kebab-case"
)]
enum Actions {
    ProverSrs {
        /// Number of inputs of the Note
        n_inputs: usize,
        /// Number of outputs of the Note
        n_outputs: usize,
        /// Depth of the Merkle tree
        tree_depth: u8,
        /// Type of circuit
        circuit: Circuit,
        /// Path for fetching the universal srs
        universal_srs_path: Option<PathBuf>,
        /// Path of the file that will store the prover's parameters
        dest: Option<PathBuf>,
    },

    UniversalSrs {
        size: usize,
        dest: Option<PathBuf>,
    },
}

fn main() {
    use Actions::*;
    let action = Actions::from_args();
    match action {
        ProverSrs {
            n_inputs,
            n_outputs,
            tree_depth,
            circuit,
            universal_srs_path,
            dest,
        } => {
            let universal_param = load_universal_parameter(universal_srs_path).unwrap();
            match circuit {
                Circuit::Transfer => store_transfer_proving_key(
                    n_inputs,
                    n_outputs,
                    tree_depth,
                    &universal_param,
                    dest,
                )
                .unwrap(),
                Circuit::Freezing => {
                    store_mint_proving_key(tree_depth, &universal_param, dest).unwrap()
                },
                Circuit::Mint => {
                    store_freeze_proving_key(n_inputs, tree_depth, &universal_param, dest).unwrap()
                },
            }
        },

        UniversalSrs { size, dest } => store_universal_parameter_for_demo(size, dest).unwrap(),
    };
}
