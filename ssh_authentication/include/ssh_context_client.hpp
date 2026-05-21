#ifndef SSH_CONTEXT_CLIENT_HPP
#define SSH_CONTEXT_CLIENT_HPP

#include <iostream>
#include <memory>
#include <grpcpp/grpcpp.h>
#include <ssh_context.grpc.pb.h>
#include <ssh_context.pb.h>

class SSHClient {
    public:
        SSHClient(std::shared_ptr<grpc::Channel> channel);
        std::string ErrorCodeToString(const sshinfo::ErrorCode& error_code) const;
        bool SendContext(uint32_t pid, bool tty, sshinfo::AuthenticationType auth_type) const;
    
    private:
        std::unique_ptr<sshinfo::SSH::Stub> stub_;
};

#endif