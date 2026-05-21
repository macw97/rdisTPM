#include <iostream>
#include "ssh_context_client.hpp"

SSHClient::SSHClient(std::shared_ptr<grpc::Channel> channel) : stub_(sshinfo::SSH::NewStub(channel)) {}

std::string SSHClient::ErrorCodeToString(const sshinfo::ErrorCode& error_code) const {
    switch (error_code) {
        case sshinfo::E_OK:
            return "E_OK";
        case sshinfo::E_GENERAL_ERROR:
            return "E_GENERAL_ERROR";
        case sshinfo::E_PID_NOT_WHITELISTED:
            return "E_PID_NOT_WHITELISTED";
        case sshinfo::E_INTERNAL_ERROR:
            return "E_INTERNAL_ERROR";
        default:
            return "UNKNOWN_ERROR_CODE";
    }
}

bool SSHClient::SendContext(uint32_t pid, bool tty, sshinfo::AuthenticationType auth_type) const {
    sshinfo::SSHContext request;
    request.set_pid(pid);
    request.set_tty(tty);
    request.set_auth(auth_type);

    grpc::ClientContext context;
    sshinfo::SSHResponse response;

    grpc::Status status = stub_->ContextSend(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "gRPC call failed: " << status.error_message() << std::endl;
        return false;
    }

    if (!response.successful()) {
        if(response.has_error_code()) {
            std::cerr << "SSH authentication failed: " << ErrorCodeToString(response.error_code()) << std::endl;
        } else {
            std::cerr << "SSH authentication failed with unknown error." << std::endl;
        }
    }

    return response.successful();
}