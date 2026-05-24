#!/bin/bash

# Check if script is run with sudo privileges
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run with sudo privileges"
   exit 1
fi

# Install TPM2 dependencies
apt-get update
apt-get install -y tpm2-tools libtss2-dev libc6-dev

if rustc --version; then
    if rustup --version; then
        rustup install stable
        rustup toolchain install nightly --component rust-src
    else
        echo "Error: rustup is not installed or not added to PATH"
        exit 1
    fi
else
    echo "Error: First install Rust and rustup"
    exit 1
fi

echo "The sudo user is - $SUDO_USER"
groupadd -f ssh_users
usermod -aG ssh_users $SUDO_USER

sudo install -m 440 -o root -g root ssh-cgroup /etc/sudoers.d/ssh-cgroup

visudo -cf /etc/sudoers.d/ssh-cgroup || {
    sudo rm /etc/sudoers.d/ssh-cgroup
    echo "Error: Invalid sudoers configuration. Please check /etc/sudoers.d/ssh-cgroup"
    exit 1
}

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

if sudo install -m 755 ssh_authentication/tpm_shell.sh /usr/local/bin/tpm_shell; then
    echo "TPM shell script installed to /usr/local/bin/tpm_shell"
else
    echo "Error: Failed to install TPM shell script"
fi
