{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    go
    openssl_3
  ];

  shellHook = ''
    echo "Base build environment ready"
  '';
}
