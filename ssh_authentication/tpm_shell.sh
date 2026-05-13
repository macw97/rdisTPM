#!/bin/sh

# 1. Non-interactive mode (scp, git, vscode)
if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    echo "Non-interactive SSH command detected: $SSH_ORIGINAL_COMMAND"
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
exec "$SHELL" -l