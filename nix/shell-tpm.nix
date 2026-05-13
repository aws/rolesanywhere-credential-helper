{ pkgs ? import (builtins.fetchTarball {
    # nixpkgs with Go 1.26.2
    # To update: find a nixpkgs commit with the desired Go version at
    # https://www.nixhub.io/packages/go then replace the commit hash below.
    url = "https://github.com/NixOS/nixpkgs/archive/01fbdeef22b76df85ea168fbfe1bfd9e63681b30.tar.gz";
  }) {} }:

let
  base = import ./shell-base.nix { inherit pkgs; };
in
pkgs.mkShell {
  buildInputs = base.buildInputs ++ (with pkgs; [
    swtpm
    tpm2-tools
    tpm2-abrmd
    tpm2-tss
    tpm2-openssl
    dbus
  ]);

  shellHook = base.shellHook + ''
    export TPM2_OPENSSL="${pkgs.tpm2-openssl}"
    export TPM2_TSS="${pkgs.tpm2-tss}"
    export OPENSSL_MODULES="${pkgs.tpm2-openssl}/lib/ossl-modules"
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.tpm2-tss pkgs.tpm2-abrmd pkgs.tpm2-openssl ]}:''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  '';
}
