#include <iostream>
#include <cstring>
#include <cstdlib>
#include "ssh_context_client.hpp"
#include <grpcpp/grpcpp.h>
#include <grpcpp/support/status.h>

#include <ssh_context.grpc.pb.h>
#include <ssh_context.pb.h>

extern "C" {
    #include <syslog.h>
    #include <termios.h>
    #include <unistd.h>
    #include <stdlib.h>
    #include <tss2/tss2_esys.h>
    #include <tss2/tss2_tcti_device.h>
    #include <tss2/tss2_tctildr.h>
    #include <tss2/tss2_mu.h>
}

extern "C" {
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR object = ESYS_TR_NONE;
    TPM2B_SENSITIVE_DATA *out = NULL;
    TSS2_RC rc;
}

enum return_code {
    E_OK = 0,
    E_GENERAL_ERROR = 1,
    E_TERMIOS_ERROR = 2,
};

int read_password_credentials(char *buffer_pass, size_t pass_size, char *buffer_user, size_t user_size) {
    struct termios _old, _new;

    bool has_tty = (tcgetattr(STDIN_FILENO, &_old) == 0);
    if(has_tty) {
        _new = _old;
        _new.c_lflag &= ~ECHO;
        if(tcsetattr(STDIN_FILENO, TCSANOW, &_new) != 0) {
            return return_code::E_TERMIOS_ERROR;
        }
    }

    printf("Enter TPM username: ");
    fflush(stdout);
    if(fgets(buffer_user, user_size, stdin) == NULL) {
        if(has_tty) {
            tcsetattr(STDIN_FILENO, TCSANOW, &_old);
        }
        return return_code::E_TERMIOS_ERROR;
    }

    printf("\nEnter TPM password: ");
    fflush(stdout);
    if(fgets(buffer_pass, pass_size, stdin) == NULL) {
        if(has_tty) {
            tcsetattr(STDIN_FILENO, TCSANOW, &_old);
        }
        return return_code::E_TERMIOS_ERROR;
    }

    if(has_tty) { tcsetattr(STDIN_FILENO, TCSANOW, &_old); }
    buffer_user[strcspn(buffer_user, "\n")] = 0; // Remove newline character
    buffer_pass[strcspn(buffer_pass, "\n")] = 0; // Remove newline character
    return return_code::E_OK;
}

void secure_wipeout(void *v, size_t n) {
    volatile unsigned char *p = static_cast<volatile unsigned char *>(v);
    while (n--) {
        *p++ = 0;
    }
}

TSS2_RC load_sealed_object_from_tpm(ESYS_CONTEXT *ctx, ESYS_TR *sealed_handle) {
    TSS2_RC rc;

    if(!ctx || !sealed_handle) {
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    // Load sealed object from persistent TPM handle 0x81000002
    rc = Esys_TR_FromTPMPublic(ctx, 0x81000002, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, sealed_handle);
    if(rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "Failed to load sealed object from persistent handle: 0x%X", rc);
        return rc;
    }

    return TSS2_RC_SUCCESS;
}

int main(int argc, char *argv[])
{
    ESYS_TR primary_handle = ESYS_TR_NONE;
    size_t primary_handle_size;
    int res = 0;
    bool reauth = false;
    char username[32];
    char password[32];

    TPM2B_PUBLIC pub = {0};
    TPM2B_PRIVATE priv = {0};
    ESYS_TR sealed = ESYS_TR_NONE;
    TPM2B_SENSITIVE_DATA *out = NULL;
    int PID = getpid();
    SSHClient ssh_client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

    std::vector<std::string> flags(argv+1, argv+argc);

    if(flags.size()>=2) {
        if(flags[0] == "--non-interactive") {
            syslog(LOG_INFO, "SSH auth: Running in non-interactive mode, skipping password prompt");
        } else if (flags[0] == "--reauthenticate") {
            reauth = true;
        } else if (flags[0] == "--interactive") {
            syslog(LOG_INFO, "SSH auth: Running in interactive mode, 2FA authentication required");
        } else {
            syslog(LOG_ERR, "SSH auth: Invalid argument: %s", argv[1]);
            return return_code::E_GENERAL_ERROR;
        }

        char* p;
        long int pid = strtol(flags[1].c_str(), &p, 10);
        if(*p) {
            syslog(LOG_ERR, "SSH auth: Invalid PID argument: %s", argv[2]);
            return return_code::E_GENERAL_ERROR;
        } else {
            PID = pid;
        }

        if(flags.size() == 3 && flags[2] == "--vs") {
            ssh_client.SendContext(PID, false, sshinfo::VSCODE_SESSION);
            return return_code::E_OK;
        } 

        if(flags[0] == "--non-interactive") {
            ssh_client.SendContext(PID, false, sshinfo::NOT_TPM_AUTHENTICATED);
            return return_code::E_OK;
        }

    }

    rc = Tss2_TctiLdr_Initialize("device:/dev/tpmrm0", &tcti_ctx);
    if(rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "SSH auth: Failed to initialize TCTI context: 0x%X", rc);
        ssh_client.SendContext(PID, false, sshinfo::NOT_TPM_AUTHENTICATED);
        return return_code::E_GENERAL_ERROR;
    }

    rc = Esys_Initialize(&ctx, tcti_ctx, NULL);
    if(rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "SSH auth: Failed to initialize ESYS context: 0x%X", rc);
        ssh_client.SendContext(PID, false, sshinfo::NOT_TPM_AUTHENTICATED);
        return return_code::E_GENERAL_ERROR;
    }

    res = read_password_credentials(password, sizeof(password), username, sizeof(username));
    if(res != 0) {
        syslog(LOG_ERR, "SSH auth: Failed to read password credentials");
        ssh_client.SendContext(PID, false, sshinfo::NOT_TPM_AUTHENTICATED);
        return return_code::E_GENERAL_ERROR;
    }
    
    if(strcmp(username, "OWNER") != 0) {
        syslog(LOG_ERR, "SSH auth: Invalid username");
        ssh_client.SendContext(PID, false, sshinfo::NOT_TPM_AUTHENTICATED);
        return return_code::E_GENERAL_ERROR;
    }
    
    rc = load_sealed_object_from_tpm(ctx, &sealed);
    if(rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "SSH auth: Failed to load sealed object from TPM: 0x%X", rc);
        ssh_client.SendContext(PID, false, sshinfo::NOT_TPM_AUTHENTICATED);
        return return_code::E_GENERAL_ERROR;
    }

    TPM2B_AUTH auth = {0};
    auth.size = strlen(password);
    memcpy(auth.buffer, password, auth.size);

    rc = Esys_TR_SetAuth(ctx, sealed, &auth);
    if(rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "SSH auth: Failed to set auth value: 0x%X", rc);
        ssh_client.SendContext(PID, false, sshinfo::NOT_TPM_AUTHENTICATED);
        return return_code::E_GENERAL_ERROR;
    }

    rc = Esys_Unseal(ctx, sealed, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &out);
    if(rc != TSS2_RC_SUCCESS) {
        syslog(LOG_ERR, "SSH auth: Failed to unseal data: 0x%X", rc);
        ssh_client.SendContext(PID, false, sshinfo::NOT_TPM_AUTHENTICATED);
        return return_code::E_GENERAL_ERROR;
    } else {
        syslog(LOG_INFO,"SSH auth successful");
    }

    secure_wipeout(username, sizeof(username));
    secure_wipeout(password, sizeof(password));
    
    ssh_client.SendContext(PID, true, reauth ? sshinfo::OWNER_REAUTHENTICATED : sshinfo::OWNER_AUTHENTICATED);

    return return_code::E_OK; // Return 0 for successful authentication, 1 for failure
}
