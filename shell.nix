# Copyright (c) 2023 Espresso Systems (espressosys.com)
# This file is part of the Configurable Asset Privacy (CAP) library.

(import
  (
    let
      lock = builtins.fromJSON (builtins.readFile ./flake.lock);
    in
    fetchTarball {
      url = "https://github.com/edolstra/flake-compat/archive/${lock.nodes.flake-compat.locked.rev}.tar.gz";
      sha256 = lock.nodes.flake-compat.locked.narHash;
    }
  )
  {
    src = ./.;
  }).shellNix