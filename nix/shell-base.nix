{ pkgs ? import (builtins.fetchTarball {
    # nixpkgs with Go 1.26.2
    # To update: find a nixpkgs commit with the desired Go version at
    # https://www.nixhub.io/packages/go then replace the commit hash below.
    url = "https://github.com/NixOS/nixpkgs/archive/01fbdeef22b76df85ea168fbfe1bfd9e63681b30.tar.gz";
  }) {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    go
    openssl_3
  ];
}
