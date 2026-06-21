# lsm_tpm

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package lsm_tpm --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/lsm_tpm` can be
copied to a Linux server or VM and run there.

## Architecture Diagram

```mermaid
graph TB
    SSH["SSH Client"]

    subgraph HOST["Linux Host"]
        SSHD["sshd\nForceCommand → tpm_shell"]

        subgraph SSHAUTH["ssh_authentication/"]
            SH["/usr/local/bin/tpm_shell\nroutes interactive vs non-interactive"]
            TA["/usr/local/bin/tpm_auth\nprompts credentials · calls TPM · notifies daemon"]
        end

        subgraph LSMD["lsm_tpm daemon"]
            CORE["Event Loop\nreads shell-exec events from kernel\ntriggers re-auth when needed"]
            GSRV["gRPC Server\nSSH.ContextSend\nassigns PID to correct cgroup"]
        end

        subgraph KSPACE["Kernel Space"]
            EBPF["eBPF LSM Programs\nbprm_check_security — watches shell execs\nfile_permission — guards cgroup writes\nblacklist enforcement"]
            CG["cgroups v2\nssh_interactive\nssh_non_interactive"]
        end
    end

    TPM2["TPM2 Chip\nsealed secret at handle 0x81000002\nunlocked by user passphrase"]

    SSH  -->|"TCP · public key"| SSHD
    SSHD -->|"ForceCommand"| SH
    SH   -->|"exec"| TA
    TA   -->|"ContextSend\n(auth result + PID)"| GSRV
    TA   -.->|"Esys_Unseal"| TPM2
    TPM2 -.->|"secret or error"| TA
    GSRV -->|"assign PID"| CG
    SH   -->|"assign PID\n(non-interactive)"| CG
    CORE -->|"re-auth:\nfreeze · challenge · resume"| TA
    EBPF -->|"shell exec events"| CORE
    EBPF -->|"enforce\ncgroup write access"| CG
    LSMD <-->|"load · attach · BPF maps"| EBPF

    classDef kernel fill:#EEEDFE,stroke:#534AB7,color:#3C3489
    classDef daemon fill:#E6F1FB,stroke:#185FA5,color:#0C447C
    classDef app    fill:#E1F5EE,stroke:#0F6E56,color:#085041
    classDef ext    fill:#FAECE7,stroke:#993C1D,color:#712B13
    class EBPF,CG kernel
    class CORE,GSRV daemon
    class SSHD,SH,TA app
    class SSH,TPM2 ext
```

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C  as SSH Client
    participant S  as sshd
    participant SH as tpm_shell
    participant TA as tpm_auth
    participant L  as lsm_tpm daemon
    participant B  as eBPF / Kernel
    participant T  as TPM2

    rect rgb(225, 245, 238)
        Note over L,B: Daemon startup
        L->>B: load & attach LSM programs
        L->>B: register cgroup IDs + binary blacklist
        B-->>L: ready — watching all exec events
    end

    rect rgb(238, 237, 254)
        Note over C,S: Phase 1 — SSH public key (1st factor)
        C->>S: connect + public key
        S->>C: challenge
        C->>S: signed response ✓
        S->>SH: invoke ForceCommand
    end

    SH->>SH: SSH_ORIGINAL_COMMAND set?

    alt non-interactive (scp · git · VS Code Remote)
        rect rgb(230, 241, 251)
            Note over SH,L: Phase 2a — classify session, no TPM challenge
            SH->>TA: tpm_auth --non-interactive
            TA->>L: ContextSend(NOT_TPM_AUTHENTICATED)
            L-->>TA: ok
            SH->>SH: place PID in ssh_non_interactive cgroup
            SH->>SH: exec original command
        end

    else interactive shell
        rect rgb(230, 241, 251)
            Note over SH,T: Phase 2b — TPM challenge (2nd factor)
            SH->>TA: tpm_auth --interactive
            TA->>C: Enter TPM username & password
            C->>TA: credentials
            TA->>T: Unseal secret with provided password
            T-->>TA: secret ✓  or  error ✗
            alt success
                TA->>L: ContextSend(OWNER_AUTHENTICATED)
                L->>L: place PID in ssh_interactive cgroup
                L-->>TA: ok
                SH->>C: open login shell
            else failure
                TA->>L: ContextSend(NOT_TPM_AUTHENTICATED)
                SH->>C: authentication failed — disconnect
            end
        end
    end

    rect rgb(250, 236, 231)
        Note over B,T: Phase 3 — Re-auth: non-interactive session opens a shell with PTY
        Note right of B: e.g. VS Code integrated terminal
        B->>B: shell exec detected in ssh_non_interactive + PTY present
        B->>L: security event (shell + non-interactive + PTY)
        L->>L: freeze the process
        L->>TA: tpm_auth --reauthenticate (on user's TTY)
        TA->>C: Enter TPM username & password
        C->>TA: credentials
        TA->>T: Unseal secret
        T-->>TA: result
        alt success
            TA->>L: ContextSend(OWNER_REAUTHENTICATED)
            L->>L: move PID to ssh_interactive cgroup
            L->>L: resume process
            Note right of L: session upgraded to interactive
        else failure
            TA->>L: ContextSend(NOT_TPM_AUTHENTICATED)
            L->>L: resume process (stays non-interactive)
            Note right of L: next shell exec will re-trigger challenge
        end
    end
```
## License

With the exception of eBPF code, lsm_tpm is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
