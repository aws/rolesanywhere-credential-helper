{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    go
    swtpm
    tpm2-tools
    tpm2-abrmd
    softhsm
    gnutls
    dbus
    tpm2-tss
    openssl_3
    tpm2-openssl
  ];

  shellHook = ''
    export TPM2_OPENSSL="${pkgs.tpm2-openssl}"
    export TPM2_TSS="${pkgs.tpm2-tss}"
    export OPENSSL_MODULES="${pkgs.tpm2-openssl}/lib/ossl-modules"
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.tpm2-tss pkgs.tpm2-abrmd pkgs.tpm2-openssl ]}:''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  '';
}
