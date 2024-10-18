#!/bin/bash

set -exuo pipefail

# This script will emulate the utility of the same name provided by James Bottomley 
# with his OpenSSL ENGINE, using utilities within tpm2-tools. Note that the options 
# in this script will be far more restricted than what Bottomley provides and may not 
# handle errors gracefully. While you may use this script to generate your own keys, 
# it isn't recommended (you may want to consider installing Bottomley's OpenSSL ENGINE 
# and using the utility tools that come with it instead, because, if nothing else, they 
# are better documented). The primary purpose for this script in this codebase is for 
# unit testing. 

ecc_curve=""
rsa_key=false
password=""
filename=""

# Parse command-line options
while getopts "e:rk:" opt; do
  case $opt in
    e)
      ecc_curve=$OPTARG
      ;;
    r)
      rsa_key=true
      ;;
    k)
      password=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument" >&2
      exit 1
      ;;
  esac
done

# Check for mutually exclusive options
if [ -n "$ecc_curve" ] && "$rsa_key"; then
  echo "Error: -e and -r options are mutually exclusive" >&2
  exit 1
fi

# Check for presence of at least one of -e and -r
if [ -z "$ecc_curve" ] && [ ! "$rsa_key" ]; then
  echo "Error: exactly one of -e and -r options should be provided" >&2
  exit 1
fi

# Shift to remove the processed options from the arguments
shift $((OPTIND-1))

# Check if the filename is provided and capture it if so
if [ $# -eq 0 ]; then
  echo "Error: A filename is required" >&2
  echo "Usage: $0 [options] <filename>" >&2
  exit 1
fi
filename=$1

# Create the primary key under the Owner hierarchy
tpm2_createprimary \
  -C o \
  -G ecc256:aes128cfb \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" \
  -c primary.ctx

# Make the primary available at a persistent handle
PRIMARY_HANDLE=$(tpm2_evictcontrol -c primary.ctx | cut -d ' ' -f 2 | head -n 1)

if [ -z "$ecc_curve" ]; then # RSA key
  # Create child key with the appropriate attributes (no sign attribute)
  cmd="tpm2_create -C primary.ctx -a 'decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda' -c child.ctx -u child.pub -r child.priv"
  [ -n "$password" ] && cmd="$cmd -p $password"
  eval $cmd

  # Serialize the ASN.1 DER file
  noPassword=$( [ -z "$password" ] && echo TRUE || echo FALSE )
  hexChildPubData=$(xxd -p child.pub | tr -d '\n')
  hexChildPrivData=$(xxd -p child.priv | tr -d '\n')
  cat > tpm-key-asn1.conf <<EOF
asn1=SEQUENCE:TPMKey

[TPMKey]
type = OID:2.23.133.10.1.3
emptyAuth = EXPLICIT:0,BOOLEAN:$noPassword
parent = INTEGER:0x40000001
pubkey = FORMAT:HEX,OCTETSTRING:$hexChildPubData
privkey = FORMAT:HEX,OCTETSTRING:$hexChildPrivData
EOF

  openssl asn1parse -genconf tpm-key-asn1.conf -out child.der

  # Create a PEM file from the DER file
  echo "-----BEGIN TSS2 PRIVATE KEY-----" > $filename
  base64 -w 64 < child.der >> $filename
  echo "-----END TSS2 PRIVATE KEY-----" >> $filename

  # Remove files that are no longer needed
  rm child.priv child.pub child.ctx child.der tpm-key-asn1.conf
else # EC key
  # Create the child key, using the above primary as its parent
  cmd="openssl genpkey -provider tpm2 -pkeyopt parent:${PRIMARY_HANDLE} -out $filename"
  [ -n "$ecc_curve" ] && cmd+=("-algorithm EC -pkeyopt group:$ecc_curve")
  [ -n "$password" ] && cmd+=("-pkeyopt user-auth:$password")
  ${cmd[@]}

  # Convert the PEM file to DER
  openssl asn1parse -inform PEM -in $filename -out temp.der

  # Find ASN.1 sequence length and decrement it by one (the permanent handle takes up one less byte)
  case $ecc_curve in
    prime256v1)
      seq_replacement="s/3081f1/3081f0/"
      ;;
    secp384r1)
      seq_replacement="s/30820121/30820120/"
      ;;
  esac

  # Change the handle to the permanent one corresponding to the Owner hierarchy
  xxd -p temp.der | tr -d '\n' | sed "s/020500$(echo ${PRIMARY_HANDLE} | awk '{print substr($0, 3)}')/020440000001/" | sed "$seq_replacement" | xxd -r -p > modified.der

  # Create the new PEM file with modified contents
  echo "-----BEGIN TSS2 PRIVATE KEY-----" > $filename
  base64 -w 64 < modified.der >> $filename
  echo "-----END TSS2 PRIVATE KEY-----" >> $filename

  # Remove the temporary DER files
  rm temp.der modified.der
fi

# Remove the persistent handle for the primary (parent)
tpm2_evictcontrol -c ${PRIMARY_HANDLE}

# Remove files related to the primary (parent)
rm primary.ctx
