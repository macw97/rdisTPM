#!/bin/bash

# ----- CONFIG -----
PRIMARY_CTX="primary.ctx"
SECRET_KEY="unlock.key"
SEALED_PUB="unlock.pub"
SEALED_PRIV="unlock.priv"
SEALED_CTX="unlock.ctx"
VERIFY_KEY="verify.key"
# ------------------


echo "======= [1] Primary context check ======="

if [ ! -f $PRIMARY_CTX ]; then
    echo "[+] Generateing primary context..."
    tpm2_createprimary -C o -g sha256 -G ecc -c $PRIMARY_CTX
else
    echo "[+] Primary context already exists. Skipping generation."
fi

echo "======= [2] Secret key check ======="
if [ ! -f $SECRET_KEY ]; then
    head -c 32 /dev/urandom > $SECRET_KEY
    echo "[+] Secret key generated and saved to $SECRET_KEY"
else
    echo "[+] Secret key already exists. Skipping generation."
fi

echo "======= [3] Secret key sealing ======="
read -s -p "[+] Enter the password to seal the secret key: " PASSWORD
echo

if [[ ! -f $SEALED_PUB && ! -f $SEALED_PRIV && -n "$PASSWORD"  ]]; then
    if tpm2_create -C $PRIMARY_CTX \
    -u $SEALED_PUB \
    -r $SEALED_PRIV \
    -i $SECRET_KEY \
    -p "$PASSWORD" && 
    tpm2_load -C $PRIMARY_CTX \
    -u $SEALED_PUB \
    -r $SEALED_PRIV \
    -c $SEALED_CTX; then
        echo "[+] Secret key sealed successfully."
    else
        echo "[-] Sealing failed"
        exit 1
    fi
else
    echo "[+] Secret key already sealed."
fi

echo "======= [4] Verify key sealing ======="
tpm2_unseal -c $SEALED_CTX -p "$PASSWORD" > $VERIFY_KEY
if [ -f $VERIFY_KEY ]; then
    echo "[+] Verify key unsealed successfully and saved to $VERIFY_KEY"
    if  cmp -s $SECRET_KEY $VERIFY_KEY; then
        echo "[+] Verify key matches the original secret key."
        rm $SECRET_KEY
        rm $VERIFY_KEY
    else
        echo "[-] Verify key does NOT match the original secret key. Something went wrong. Please debug context"
    fi
fi


