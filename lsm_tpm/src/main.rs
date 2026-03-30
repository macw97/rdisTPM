use aya::{Btf, programs::Lsm};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use aya::maps::{perf, MapData};
use aya::util::online_cpus;
use bytes::BytesMut;
use lsm_tpm_common::SecurityEvent;
use libc::{epoll_create1, epoll_ctl, epoll_wait, EPOLL_CTL_ADD, epoll_event, EPOLLIN};
use std::os::fd::AsRawFd;
use std::io;

pub struct Epoll {
    epfd: i32,
    num_buffers: usize,
}

fn poll_buffers(perf_buffers: &Vec<perf::PerfEventArrayBuffer<&mut MapData>>) -> io::Result<Epoll> {
    let epollfd = unsafe { epoll_create1(0) };
    
    if epollfd < 0 {
        println!("Something wrong with epoll!");
        return Err(io::Error::last_os_error());
    }
    println!("Created epoll instance with fd: {epollfd}");

    for (i, perf_buffer) in perf_buffers.iter().enumerate() {
        let fd = perf_buffer.as_raw_fd();
        println!("Registering perf buffer {i} with fd: {fd} to epoll");

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
        num_buffers: perf_buffers.len(),
    })
}

impl Epoll {
    pub fn poll_readable(&self) -> io::Result<Vec<usize>> {
        let mut events = vec![epoll_event { events: 0, u64: 0 }; self.num_buffers];
        let nfds = unsafe { epoll_wait(self.epfd, events.as_mut_ptr(), events.len() as i32, -1) };
        
        if nfds < 0 {
            println!("Error during epoll_wait: {nfds}");
            return Err(io::Error::last_os_error());
        }

        let mut ready_indices = Vec::new();
        for i in 0..nfds as usize {
            let idx = events[i].u64 as usize;
            ready_indices.push(idx);
        }
        Ok(ready_indices)
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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lsm_tpm"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
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

    let mut perf_array = aya::maps::perf::PerfEventArray::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut perf_buffers = Vec::new();
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        perf_buffers.push(perf_array.open(cpu_id, None)?);
    }

    let mut out_bufs = [bytes::BytesMut::with_capacity(1024)];
    let pollfd = poll_buffers(&perf_buffers)?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Received Ctrl-C, exiting...");
                break;
            }

            result = async { pollfd.poll_readable() } => {
                match result {
                    Ok(indices) => {
                        for idx in indices {
                            if idx < perf_buffers.len() {
                                match perf_buffers[idx].read_events(&mut out_bufs) {
                                    Ok(_events) => {
                                        let event: SecurityEvent = unsafe {
                                            std::ptr::read_unaligned(out_bufs[0].as_ptr() as *const SecurityEvent)
                                        };
                                        println!("Received event: {:?} , {:?}, {:?}", event._filename, event._uid, event._unsafe);
                                    }
                                    Err(e) => eprintln!("Failed to read events: {e}"),
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("Poll error: {e}"),
                }
            }
        }
    }

    Ok(())
}
