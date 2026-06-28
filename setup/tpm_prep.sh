#!/bin/bash

# ----- CONFIG -----
PRIMARY_CTX="primary.ctx"
SECRET_KEY="unlock.key"
SEALED_PUB="unlock.pub"
SEALED_PRIV="unlock.priv"
SEALED_CTX="unlock.ctx"
VERIFY_KEY="verify.key"
PRIMARY_HANDLE="0x81000001"
SEALED_HANDLE="0x81000002"
# ------------------

if [[ $EUID -ne 0]]; then
    echo "This script have to be run as root"
    exit 1

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

echo "======= [3.5] Make objects persistent in TPM ======="
echo "[*] Ensuring $PRIMARY_HANDLE is free before making persistent..."
if tpm2_getcap handles-persistent | grep -qi "$PRIMARY_HANDLE"; then
    echo "[*] $PRIMARY_HANDLE already occupied, evicting first..."
    if ! tpm2_evictcontrol -C o -c $PRIMARY_HANDLE; then
        echo "[-] Failed to evict existing object at $PRIMARY_HANDLE" >&2
        exit 1
    fi
fi

if tpm2_evictcontrol -C o -c $PRIMARY_CTX $PRIMARY_HANDLE; then
    echo "[+] Primary context saved to persistent handle $PRIMARY_HANDLE"
else
    echo "[-] Failed to save primary context" >&2
    exit 1
fi

# Reload sealed object using the now-persistent primary
if tpm2_load -C $PRIMARY_HANDLE -u $SEALED_PUB -r $SEALED_PRIV -c $SEALED_CTX; then
    echo "[+] Sealed object reloaded with persistent primary"
else
    echo "[-] Failed to reload sealed object" >&2
    exit 1
fi

echo "[*] Ensuring $SEALED_HANDLE is free before making persistent..."
if tpm2_getcap handles-persistent | grep -qi "$SEALED_HANDLE"; then
    echo "[*] $SEALED_HANDLE already occupied, evicting first..."
    if ! tpm2_evictcontrol -C o -c $SEALED_HANDLE; then
        echo "[-] Failed to evict existing object at $SEALED_HANDLE" >&2
        exit 1
    fi
fi

if tpm2_evictcontrol -C o -c $SEALED_CTX $SEALED_HANDLE; then
    echo "[+] Sealed object saved to persistent handle $SEALED_HANDLE"
else
    echo "[-] Failed to save sealed object" >&2
    exit 1
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


