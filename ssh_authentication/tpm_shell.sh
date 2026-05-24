#!/bin/sh
CGROUPS_DIR="/sys/fs/cgroup"
SSH_NON_INTERACTIVE_GROUP="$CGROUPS_DIR/ssh_non_interactive"
SSH_INTERACTIVE_GROUP="$CGROUPS_DIR/ssh_interactive"

if [ ! -d "$SSH_NON_INTERACTIVE_GROUP" ]; then
    sudo mkdir -p "$SSH_NON_INTERACTIVE_GROUP"
fi

if [ ! -d "$SSH_INTERACTIVE_GROUP" ]; then
    sudo mkdir -p "$SSH_INTERACTIVE_GROUP"
fi

# 1. Non-interactive mode (scp, git, vscode)
if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    echo "Non-interactive SSH command detected: $SSH_ORIGINAL_COMMAND"
    
    /usr/local/bin/tpm_auth --non-interactive
    echo $$ | sudo tee "$SSH_NON_INTERACTIVE_GROUP/cgroup.procs" > /dev/null
    exec /bin/sh -c "$SSH_ORIGINAL_COMMAND"
fi

# 2. Interactive session → TPM gate
echo "Welcome to the TPM-protected SSH session!"
if [ -n "$SSH_TTY" ]; then
    /usr/local/bin/tpm_auth
    rc=$?

    if [ $rc -ne 0 ]; then
        echo "TPM authentication failed"
        exit 1
    fi
    echo "TPM authentication successful"
fi

# 3. Login shell
echo $$ | sudo tee "$SSH_INTERACTIVE_GROUP/cgroup.procs" > /dev/null
exec "$SHELL" -l
