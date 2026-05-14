#!/bin/bash

# Check if script is run with sudo privileges
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run with sudo privileges"
   exit 1
fi

# Install TPM2 dependencies
apt-get update
apt-get install -y tpm2-tools tpm2-tss libtss2-dev libc6-dev

rustup install stable
rustup toolchain install nightly --component rust-src

# Configure SSH daemon for TPM authentication
echo "Configuring sshd_config..."

# Backup original sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Add or update KbdInteractiveAuthentication setting
if grep -q "^KbdInteractiveAuthentication" /etc/ssh/sshd_config; then
    sed -i 's/^KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
else
    echo "KbdInteractiveAuthentication yes" >> /etc/ssh/sshd_config
fi

# Add or update ForceCommand setting
if grep -q "^ForceCommand" /etc/ssh/sshd_config; then
    sed -i 's|^ForceCommand.*|ForceCommand /usr/local/bin/tpm_shell|' /etc/ssh/sshd_config
else
    echo "ForceCommand /usr/local/bin/tpm_shell" >> /etc/ssh/sshd_config
fi

# Restart SSH service to apply changes
systemctl restart sshd
echo "SSH daemon configured and restarted successfully"
