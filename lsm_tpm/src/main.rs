use aya::{Btf, programs::Lsm};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use aya::maps::{perf, MapData};
use aya::maps::HashMap;
use std::fs;
use std::sync::Arc;
use aya::util::online_cpus;
use bytes::BytesMut;
use lsm_tpm_common::SecurityEvent;
use libc::{epoll_create1, epoll_ctl, epoll_wait, EPOLL_CTL_ADD, epoll_event, EPOLLIN};
use std::os::fd::AsRawFd;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::fd::FromRawFd;
use std::os::fd::IntoRawFd;

use tonic::{transport::Server, Request, Response, Status};
use sshinfo::ssh_server::{Ssh, SshServer};
use sshinfo::{SshContext, SshResponse, ErrorCode};

const PERF_HEADER_SIZE: usize = 8;
const EVENT_SIZE: usize = std::mem::size_of::<SecurityEvent>() + PERF_HEADER_SIZE;

pub mod sshinfo {
    tonic::include_proto!("sshinfo");
}

#[derive(Debug, Default)]
pub struct SshContextService {}

#[tonic::async_trait]
impl Ssh for SshContextService {
    async fn context_send(&self, request: Request<SshContext>) -> Result<Response<SshResponse>, Status> {
        // Implementation for getting SSH context
        println!("Received SSH context request: {:?}", request);

        let ctx = request.into_inner();

        if ctx.auth == sshinfo::AuthenticationType::OwnerReauthenticated.into() {
            fs::write("/sys/fs/cgroup/ssh_interactive/cgroup.procs", format!("{}\n", ctx.pid)
            ).map_err(|e| Status::internal(e.to_string()))?;

            println!("Migrated pid={} to interactive cgroup", ctx.pid);
        }

        let reply = SshResponse {
            successful: true,
            error_code: Some(ErrorCode::EOk.into()),
        };
        Ok(Response::new(reply))
    }
}

pub struct Epoll {
    epfd: i32,
    wake_fd: i32,
    num_buffers: usize,
}

fn poll_buffers(perf_buffers: &Vec<perf::PerfEventArrayBuffer<&mut MapData>>) -> io::Result<Epoll> {
    let epollfd = unsafe { epoll_create1(0) };
    
    if epollfd < 0 {
        println!("Something wrong with epoll!");
        return Err(io::Error::last_os_error());
    }
    println!("Created epoll instance with fd: {epollfd}");

    let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
    if wake_fd < 0 {
        println!("Failed to create eventfd for wakeup: {wake_fd}");
        unsafe { libc::close(epollfd) };
        return Err(io::Error::last_os_error());
    }

    let mut wake_event = epoll_event {
        events: EPOLLIN as u32,
        u64: usize::MAX as u64, // Use a special value to identify wake events
    };

    unsafe { epoll_ctl(epollfd, EPOLL_CTL_ADD, wake_fd, &mut wake_event) };

    for (i, perf_buffer) in perf_buffers.iter().enumerate() {
        let fd = perf_buffer.as_raw_fd();
        println!("Registering CPU {i} perf buffer fd={fd} to epoll");
        let mut event = epoll_event {
            events: EPOLLIN as u32,
            u64: i as u64, // Use the index as the user data
        };

        let res = unsafe { epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &mut event) };
        if res < 0 {
            println!("Failed to add fd {fd} to epoll: {res}");
            return Err(io::Error::last_os_error());
        }
    }
    Ok(Epoll { 
        epfd: epollfd,
        wake_fd,
        num_buffers: perf_buffers.len(),
    })
}

fn poll_and_handle_security_events(
    pollfd: Arc<Epoll>,
    mut perf_buffers: Vec<perf::PerfEventArrayBuffer<&mut MapData>>,
    mut out_bufs: [bytes::BytesMut; 64],
)  
{
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
                                    println!("Warning: Lost {} events on CPU {}", events.lost, idx);
                                }
                                for buf in out_bufs.iter().take(events.read) { 
                                    handle_security_event(buf);
                                }
                            },
                            Err(e) => eprintln!("Failed to read events from buffer {idx}: {e}"),
                        }
                    }
                }
            }
            Ok(None) => {
                println!("Received wake event, stopping poll loop");
                break;
            }
            Err(e) => {
                eprintln!("Error during epoll wait: {e}");
                break;
            }
        }
    }

}

fn get_tty_of_pid(pid: u32) -> io::Result<String> {
    let link = std::fs::read_link(format!("/proc/{pid}/fd/0"))?;
    Ok(link.to_string_lossy().to_string())
}

fn has_pty(pid: u32) -> bool {
    if let Ok(link) = std::fs::read_link(format!("/proc/{pid}/fd/0")) {
        link.to_string_lossy().starts_with("/dev/pts/")
    } else {
        false
    }
}

fn run_2fa(pid: u32) -> io::Result<()> {
    let tty_path = get_tty_of_pid(pid)?;

    unsafe { libc::kill(pid as i32, libc::SIGSTOP) }; // Stop the process until 2FA is done
    let tty_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tty_path)?;

    let tty_fd = tty_file.into_raw_fd();

    let tty_fd_out = unsafe { libc::dup(tty_fd) };
    let tty_fd_err = unsafe { libc::dup(tty_fd) };

    let mut child =
        std::process::Command::new("/usr/local/bin/tpm_auth")
            .arg("--reauthenticate")
            .arg(pid.to_string())
            .stdin(unsafe { std::process::Stdio::from_raw_fd(tty_fd) })
            .stdout(unsafe { std::process::Stdio::from_raw_fd(tty_fd_out) })
            .stderr(unsafe { std::process::Stdio::from_raw_fd(tty_fd_err) })
            .spawn()?;

    let status = child.wait()?;
    unsafe { libc::kill(pid as i32, libc::SIGCONT) }; // Continue the process after 2FA is done

    if status.success() {
        println!("2FA successful for pid {pid}");
    } else {
        println!("2FA failed for pid {pid}, status: {status}");
    }

    Ok(())
}

fn trigger_2fa_for_pid(pid: u32) {
    
    std::thread::spawn(move || {
        if let Err(e) = run_2fa(pid) {
            eprintln!("Error during 2FA for pid {pid}: {e}");
            unsafe { libc::kill(pid as i32, libc::SIGCONT) }; // Ensure process is continued even if 2FA fails
        }
    });
}

fn handle_security_event(buf: &bytes::BytesMut) {
    let event: SecurityEvent = unsafe {
        std::ptr::read_unaligned(buf.as_ptr() as *const SecurityEvent)
    };

    let filename_end = event._filename
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(event._filename.len());

    let filename = String::from_utf8_lossy(&event._filename[..filename_end]);
    if event._is_shell && (filename == "/bin/bash" || filename == "/usr/bin/bash") {
        if has_pty(event._pid) {
            println!("Received shell open event pid: {}, cgroup_type: {}", event._pid, event._cgroup_type);
            trigger_2fa_for_pid(event._pid);
        }
    }
    
    println!(
        "Received event: filename={}, uid={}, pid={}, cgroup_type={}",
        filename, event._uid, event._pid, event._cgroup_type
    );
}

impl Epoll {
    pub fn poll_readable(&self) -> io::Result<Option<Vec<usize>>> {
        loop {
            let mut events = vec![epoll_event { events: 0, u64: 0 }; self.num_buffers];
            let nfds = unsafe { epoll_wait(self.epfd, events.as_mut_ptr(), events.len() as i32, -1) };
            
            if nfds < 0 {
                let err = io::Error::last_os_error();
                // Retry on EINTR (interrupted system call)
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                println!("Error during epoll_wait: {nfds}");
                return Err(err);
            }

            for i in 0..nfds as usize {
                if events[i].u64 == usize::MAX as u64 {
                    return Ok(None); // Wake event, signal to stop polling
                }
            }

            let indices = (0..nfds as usize).map(|i| events[i].u64 as usize).collect();

            return Ok(Some(indices));
        }
    }

    pub fn wake(&self) {
        let val: u64 = 1;
        unsafe {
            libc::write(self.wake_fd, &val as *const u64 as *const libc::c_void, 8);
        }
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        if self.epfd >= 0 && self.wake_fd >= 0 {
            unsafe { 
                libc::close(self.epfd);
                libc::close(self.wake_fd);
            };
            println!("Closed epoll fd: {} and wake fd: {}", self.epfd, self.wake_fd);
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
    
    let addr = "[::1]:50051".parse()?;
    
    {
        let mut cgroup_map: HashMap<_, u64, u32> = HashMap::try_from(ebpf.map_mut("CGROUP_MAP").unwrap())?;
        let interactive_cgroup_id = fs::metadata("/sys/fs/cgroup/ssh_interactive")?.ino();
        let non_interactive_cgroup_id = fs::metadata("/sys/fs/cgroup/ssh_non_interactive")?.ino();

        cgroup_map.insert(interactive_cgroup_id, 1, 0)?;
        cgroup_map.insert(non_interactive_cgroup_id, 2, 0)?;
        println!("Inserted cgroup IDs into map: interactive={}, non-interactive={}", interactive_cgroup_id, non_interactive_cgroup_id);
    }

    let mut perf_array = aya::maps::perf::PerfEventArray::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut perf_buffers = Vec::new();
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        perf_buffers.push(perf_array.open(cpu_id, None)?);
    }

    let mut out_bufs: [BytesMut; 64] = std::array::from_fn(|_| BytesMut::with_capacity(EVENT_SIZE));
    let pollfd = Arc::new(poll_buffers(&perf_buffers)?);
    let pollfd_clone = Arc::clone(&pollfd);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut grpc_handle = tokio::spawn(
    Server::builder()
        .add_service(SshServer::new(SshContextService::default()))
        .serve_with_shutdown(addr, async { shutdown_rx.await.ok(); }),
    );

    std::thread::spawn(move || { 
        poll_and_handle_security_events(pollfd_clone, perf_buffers, out_bufs);
    });

    loop {
        tokio::select! {

            _ = async { signal::ctrl_c().await } => {
                println!("Received Ctrl-C, exiting...");
                pollfd.wake(); // Ensure epoll fd is closed before exiting
                let _ = shutdown_tx.send(()); // Signal gRPC server to shut down
                break;
            }

            result = &mut grpc_handle => {  // watch for unexpected termination
                match result {
                    Ok(Ok(())) => eprintln!("gRPC server stopped unexpectedly"),
                    Ok(Err(e)) => eprintln!("gRPC server error: {e}"),
                    Err(e)     => eprintln!("gRPC task panicked: {e}"),
                }
                break;
            }

        }
    }

    println!("Exiting...");
    Ok(())
}
