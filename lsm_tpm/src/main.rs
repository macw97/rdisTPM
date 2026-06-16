use aya::{Btf, programs::Lsm};
use aya::maps::{perf, MapData, HashMap};
use aya::util::online_cpus;
use bytes::BytesMut;
use lsm_tpm_common::SecurityEvent;
use log::{debug, warn, error, info};
use libc::{epoll_create1, epoll_ctl, epoll_wait, EPOLL_CTL_ADD, epoll_event, EPOLLIN};
use std::fs;
use std::io;
use std::os::fd::{FromRawFd, IntoRawFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use tokio::signal;
use tonic::{transport::Server, Request, Response, Status};
use sshinfo::ssh_server::{Ssh, SshServer};
use sshinfo::{SshContext, SshResponse, ErrorCode};

// Configuration constants
const PERF_HEADER_SIZE: usize = 8;
const EVENT_SIZE: usize = std::mem::size_of::<SecurityEvent>() + PERF_HEADER_SIZE;
const MAX_BUFFERS: usize = 64;
const WAKE_EVENT_MARKER: u64 = usize::MAX as u64;
const TPM_AUTH_PATH: &str = "/usr/local/bin/tpm_auth";
const INTERACTIVE_CGROUP_PATH: &str = "/sys/fs/cgroup/ssh_interactive/cgroup.procs";
const SHELL_PATHS: &[&str] = &["/bin/bash", "/usr/bin/bash"];
const GRPC_ADDR: &str = "[::1]:50051";

pub mod sshinfo {
    tonic::include_proto!("sshinfo");
}

#[derive(Debug, Default)]
pub struct SshContextService {}

#[tonic::async_trait]
impl Ssh for SshContextService {
    async fn context_send(&self, request: Request<SshContext>) -> Result<Response<SshResponse>, Status> {
        let ctx = request.into_inner();
        debug!("Received SSH context request: {:?}", ctx);

        if ctx.auth == sshinfo::AuthenticationType::OwnerReauthenticated.into() {
            if let Err(e) = fs::write(INTERACTIVE_CGROUP_PATH, format!("{}\n", ctx.pid)) {
                error!("Failed to migrate pid {} to interactive cgroup: {}", ctx.pid, e);
                return Err(Status::internal(format!("Cgroup migration failed: {}", e)));
            }
            info!("Migrated pid={} to interactive cgroup", ctx.pid);
        }

        Ok(Response::new(SshResponse {
            successful: true,
            error_code: Some(ErrorCode::EOk.into()),
        }))
    }
}

pub struct Epoll {
    epfd: i32,
    wake_fd: i32,
    num_buffers: usize,
}

fn poll_buffers(perf_buffers: &[perf::PerfEventArrayBuffer<&mut MapData>]) -> io::Result<Epoll> {
    // SAFETY: epoll_create1 is safe to call with 0 flags and handles errors via return value
    let epollfd = unsafe { epoll_create1(0) };
    if epollfd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: eventfd with EFD_NONBLOCK is safe and returns error via fd value
    let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
    if wake_fd < 0 {
        unsafe { libc::close(epollfd) };
        return Err(io::Error::last_os_error());
    }

    let mut wake_event = epoll_event {
        events: EPOLLIN as u32,
        u64: WAKE_EVENT_MARKER,
    };

    // SAFETY: epoll_ctl is safe here with valid fds
    unsafe { epoll_ctl(epollfd, EPOLL_CTL_ADD, wake_fd, &mut wake_event) };

    for (i, perf_buffer) in perf_buffers.iter().enumerate() {
        let fd = perf_buffer.as_raw_fd();
        let mut event = epoll_event {
            events: EPOLLIN as u32,
            u64: i as u64,
        };

        // SAFETY: epoll_ctl is safe with valid fds
        let res = unsafe { epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &mut event) };
        if res < 0 {
            unsafe { 
                libc::close(wake_fd);
                libc::close(epollfd);
            }
            return Err(io::Error::last_os_error());
        }
    }

    debug!("Created epoll with {} perf buffers", perf_buffers.len());
    Ok(Epoll { 
        epfd: epollfd,
        wake_fd,
        num_buffers: perf_buffers.len(),
    })
}

fn poll_and_handle_security_events(
    pollfd: Arc<Epoll>,
    mut perf_buffers: Vec<perf::PerfEventArrayBuffer<&mut MapData>>,
    mut out_bufs: [BytesMut; MAX_BUFFERS],
) {
    loop {
        match pollfd.poll_readable() {
            Ok(Some(indices)) => {
                for idx in indices {
                    if idx >= perf_buffers.len() {
                        continue;
                    }

                    loop {
                        match perf_buffers[idx].read_events(&mut out_bufs) {
                            Ok(events) if events.read == 0 => break,
                            Ok(events) => {
                                if events.lost > 0 {
                                    warn!("Lost {} events on CPU {}", events.lost, idx);
                                    println!("Warning: Lost {} events on CPU {}", events.lost, idx);
                                }
                                for buf in out_bufs.iter().take(events.read) {
                                    handle_security_event(buf);
                                }
                            }
                            Err(e) => {
                                error!("Failed to read events from buffer {}: {}", idx, e);
                                eprintln!("Failed to read events from buffer {}: {}", idx, e);
                                break;
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                info!("Received wake event, stopping poll loop");
                break;
            }
            Err(e) => {
                error!("Error during epoll wait: {}", e);
                eprintln!("Error during epoll wait: {}", e);
                break;
            }
        }
    }
}

fn get_tty_of_pid(pid: u32) -> io::Result<String> {

    if pid == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "PID cannot be 0"));
    }

    let fd_path = format!("/proc/{}/fd/0", pid);
    let link = fs::read_link(&fd_path)?;
    let tty_path = link.to_string_lossy().to_string();

    // Basic validation: ensure it points to a TTY
    if !tty_path.starts_with("/dev/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid TTY path: {}", tty_path),
        ));
    }

    Ok(tty_path)
}

fn has_pty(pid: u32) -> bool {
    get_tty_of_pid(pid)
        .ok()
        .map(|path| path.starts_with("/dev/pts/"))
        .unwrap_or(false)
}

fn run_2fa(pid: u32) -> io::Result<()> {
    let tty_path = get_tty_of_pid(pid)?;

    // SAFETY: SIGSTOP is to suspend concurent access to the TTY and pid is validated in get_tty_of_pid
    unsafe { libc::kill(pid as i32, libc::SIGSTOP) };

    let tty_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&tty_path)?;

    // SAFETY: into_raw_fd is safe here as we own the file handle
    let tty_fd = tty_file.into_raw_fd();

    // SAFETY: dup with a valid fd is safe
    let tty_fd_out = unsafe { libc::dup(tty_fd) };
    let tty_fd_err = unsafe { libc::dup(tty_fd) };

    if tty_fd_out < 0 || tty_fd_err < 0 {
        unsafe { libc::kill(pid as i32, libc::SIGCONT) };
        return Err(io::Error::last_os_error());
    }

    let status = std::process::Command::new(TPM_AUTH_PATH)
        .arg("--reauthenticate")
        .arg(pid.to_string())
        .stdin(unsafe { std::process::Stdio::from_raw_fd(tty_fd) })
        .stdout(unsafe { std::process::Stdio::from_raw_fd(tty_fd_out) })
        .stderr(unsafe { std::process::Stdio::from_raw_fd(tty_fd_err) })
        .status()?;

    // SAFETY: SIGCONT to stoped process after 2FA authentication
    unsafe { libc::kill(pid as i32, libc::SIGCONT) };

    if status.success() {
        info!("2FA authentication successful for pid {}", pid);
        Ok(())
    } else {
        error!("2FA authentication failed for pid {}: {}", pid, status);
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("2FA failed: {}", status),
        ))
    }
}

fn trigger_2fa_for_pid(pid: u32) {
    std::thread::spawn(move || {
        if let Err(e) = run_2fa(pid) {
            error!("2FA failed for pid {}: {}", pid, e);
            unsafe { libc::kill(pid as i32, libc::SIGCONT) };
        }
    });
}

fn handle_security_event(buf: &BytesMut) {
    // SAFETY: SecurityEvent is a POD type read from kernel, unaligned read is necessary
    // as perf buffers may not guarantee alignment
    let event: SecurityEvent = unsafe {
        std::ptr::read_unaligned(buf.as_ptr() as *const SecurityEvent)
    };

    // Extract null-terminated filename string
    let filename_end = event._filename
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(event._filename.len());

    let filename = String::from_utf8_lossy(&event._filename[..filename_end]);

    // Log all received events for traceability
    info!(
        "Received event: filename={}, uid={}, pid={}, cgroup_type={}, is_shell={}",
        filename, event._uid, event._pid, event._cgroup_type, event._is_shell
    );

    if event._is_shell && SHELL_PATHS.contains(&filename.as_ref()) && event._cgroup_type == 2 {
        if has_pty(event._pid) {
            info!("Triggering 2FA for shell process: pid={}, cgroup_type={}", event._pid, event._cgroup_type);
            trigger_2fa_for_pid(event._pid);
        }
    }
}

impl Epoll {
    pub fn poll_readable(&self) -> io::Result<Option<Vec<usize>>> {
        loop {
            let mut events = vec![epoll_event { events: 0, u64: 0 }; self.num_buffers];
            
            // SAFETY: epoll_wait is safe with valid epfd and event array
            let nfds = unsafe { 
                epoll_wait(self.epfd, events.as_mut_ptr(), events.len() as i32, -1) 
            };

            if nfds < 0 {
                let err = io::Error::last_os_error();
                // Retry on EINTR (interrupted system call)
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }

            for i in 0..nfds as usize {
                if events[i].u64 == WAKE_EVENT_MARKER {
                    return Ok(None); // Wake event, signal to stop polling
                }
            }

            let indices = (0..nfds as usize)
                .map(|i| events[i].u64 as usize)
                .collect();

            return Ok(Some(indices));
        }
    }

    pub fn wake(&self) {
        let val: u64 = 1;
        // SAFETY: write to a valid eventfd is safe
        unsafe {
            libc::write(self.wake_fd, &val as *const u64 as *const libc::c_void, 8);
        }
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        if self.epfd >= 0 && self.wake_fd >= 0 {
            // SAFETY: close is safe on valid fds; we only call this once via Drop
            unsafe {
                libc::close(self.epfd);
                libc::close(self.wake_fd);
            }
            debug!("Closed epoll fd: {} and wake fd: {}", self.epfd, self.wake_fd);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let ebpf = Box::leak(Box::new(aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lsm_tpm"
    )))?));

    match aya_log::EbpfLogger::init(ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            let _logger_task = tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf.program_mut("bprm_check_security").unwrap().try_into()?;
    program.load("bprm_check_security", &btf)?;
    program.attach()?;
    
    let addr = GRPC_ADDR.parse()?;
    
    {
        let mut cgroup_map: HashMap<_, u64, u32> = HashMap::try_from(ebpf.map_mut("CGROUP_MAP").unwrap())?;
        let interactive_cgroup_id = fs::metadata("/sys/fs/cgroup/ssh_interactive")?.ino();
        let non_interactive_cgroup_id = fs::metadata("/sys/fs/cgroup/ssh_non_interactive")?.ino();

        cgroup_map.insert(interactive_cgroup_id, 1, 0)?;
        cgroup_map.insert(non_interactive_cgroup_id, 2, 0)?;
        info!("Inserted cgroup IDs into map: interactive={}, non-interactive={}", interactive_cgroup_id, non_interactive_cgroup_id);
    }

    let mut perf_array = aya::maps::perf::PerfEventArray::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut perf_buffers = Vec::new();
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        perf_buffers.push(perf_array.open(cpu_id, None)?);
    }

    let out_bufs: [BytesMut; MAX_BUFFERS] = std::array::from_fn(|_| BytesMut::with_capacity(EVENT_SIZE));
    let pollfd = Arc::new(poll_buffers(&perf_buffers)?);
    let pollfd_clone = Arc::clone(&pollfd);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut grpc_handle = tokio::spawn(
        Server::builder()
            .add_service(SshServer::new(SshContextService::default()))
            .serve_with_shutdown(addr, async { 
                let _ = shutdown_rx.await;
            }),
    );

    std::thread::spawn(move || { 
        poll_and_handle_security_events(pollfd_clone, perf_buffers, out_bufs);
    });

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received Ctrl-C, exiting...");
                pollfd.wake();
                let _ = shutdown_tx.send(());
                break;
            }
            result = &mut grpc_handle => {
                match result {
                    Ok(Ok(())) => error!("gRPC server stopped unexpectedly"),
                    Ok(Err(e)) => error!("gRPC server error: {e}"),
                    Err(e)     => error!("gRPC task panicked: {e}"),
                }
                break;
            }
        }
    }

    info!("Exiting...");
    Ok(())
}
