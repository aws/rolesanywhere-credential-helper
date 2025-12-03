{ pkgs ? import <nixpkgs> {} }:

# Full test environment with TPM and PKCS11 support
# Use nix/shell-base.nix for builds only
# Use nix/shell-tpm.nix for TPM tests only
# Use nix/shell-pkcs11.nix for PKCS11 tests only

let
  tpm = import ./nix/shell-tpm.nix { inherit pkgs; };
  pkcs11 = import ./nix/shell-pkcs11.nix { inherit pkgs; };
in
pkgs.mkShell {
  nativeBuildInputs = pkcs11.nativeBuildInputs or [];
  buildInputs = tpm.buildInputs ++ pkcs11.buildInputs;

  shellHook = tpm.shellHook + pkcs11.shellHook;
}
