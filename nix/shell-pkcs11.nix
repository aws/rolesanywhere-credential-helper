{ pkgs ? import <nixpkgs> {} }:

let
  base = import ./shell-base.nix { inherit pkgs; };
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    pkg-config
  ];

  buildInputs = base.buildInputs ++ (with pkgs; [
    softhsm
    gnutls
    opensc
    dbus
  ]);

  shellHook = base.shellHook + ''
    # Patch in missing .pc file required by Makefile
    mkdir -p .nix-pkgconfig
    cat > .nix-pkgconfig/softhsm2.pc << EOF
Name: SoftHSM
Description: ${pkgs.softhsm.meta.description}
Version: ${pkgs.softhsm.version}
libdir=${pkgs.softhsm}/lib
EOF
    export PKG_CONFIG_PATH="$(pwd)/.nix-pkgconfig:$PKG_CONFIG_PATH"
    echo "PKCS11 test environment ready"
  '';
}
