#![no_std]
#![no_main]

#[allow(
    clippy::all,
    dead_code,
    improper_ctypes_definitions,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn,
)]
#[rustfmt::skip]
mod vmlinux;
//use aya_ebpf::btf_maps::Array;
use aya_ebpf::{macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;
use aya_ebpf::helpers::{self, bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes};
use aya_ebpf::maps::{PerfEventArray, HashMap, Array};
use core::str;
use aya_ebpf::macros::map;
use vmlinux::{file, linux_binprm};
use lsm_tpm_common::SecurityEvent;

const CGROUP_INTERACTIVE: u32 = 1;
const CGROUP_NON_INTERACTIVE: u32 = 2;
const CGROUP_INTERACTIVE_PROCS: u32 = 3;

const MAY_WRITE: i32 = 0x2;

#[map(name="EVENTS")]
static EVENTS: PerfEventArray<SecurityEvent> = PerfEventArray::new(0);

#[map(name="CGROUP_MAP")]
static CGROUP_MAP: HashMap<u64, u32> = HashMap::with_max_entries(4,0);

#[map(name = "DEAMON_PID")]
static DEAMON_PID: Array<u32> = Array::with_max_entries(1,0);

#[map(name="BLACKLIST_MAP")]
static BLACKLIST_MAP: HashMap<[u8; 64], u8> = HashMap::with_max_entries(256,0);

#[map(name="BLACKLIST_PATHS")]
static BLACKLIST_PATHS: Array<[u8; 64]> = Array::with_max_entries(32,0);

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match unsafe { try_bprm_check_security(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[lsm(hook = "file_permission")]
pub fn file_permission(ctx: LsmContext) -> i32 {
    match unsafe { try_file_permission(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {

    let p: *const linux_binprm = ctx.arg(0);
    if p.is_null() {
        info!(&ctx, "linux_binprm is null");
    } else {
        let bprm = unsafe { &*p };
        let mut buf = [0u8; 64];
        let str_bytes = unsafe { 
            bpf_probe_read_kernel_str_bytes(bprm.filename, &mut buf)
            .map_err(|e| e as i32)?
        };

        let filename = unsafe { str::from_utf8_unchecked(str_bytes) };
        let cgroup_id = unsafe { helpers::bpf_get_current_cgroup_id() };
        let cgroup_type = unsafe { CGROUP_MAP.get(&cgroup_id) }.copied().unwrap_or(0);
        let creds = bprm.cred;
        if creds.is_null() {
            info!(&ctx, "real_cred is null");
            return Ok(0);
        }
        
        // Copy the actual bytes from buf into the event
        let mut filename_bytes = [0u8; 32];
        let copy_len = str_bytes.len().min(32);
        filename_bytes[..copy_len].copy_from_slice(&filename.as_bytes()[..copy_len]);
        
        let pid: u32 = bpf_get_current_pid_tgid() as u32;

        let is_shell = filename == "/bin/bash"
            || filename == "/bin/sh"
            || filename == "/usr/bin/bash"
            || filename == "/usr/bin/sh";
        
        
        let event = SecurityEvent {
            _filename: filename_bytes,
            _uid: unsafe { (*creds).uid.val },
            _pid: pid,
            _cgroup_type: cgroup_type,
            _is_shell: is_shell,
        }; 
        
        EVENTS.output(&ctx, &event, 0);

        // BLACKLISTs path and binary checks
        if cgroup_type == CGROUP_NON_INTERACTIVE {
            
            // for i in 0..32 {
            //     if let Some(path) = BLACKLIST_PATHS.get(i) {
            //         let trimmed = match path.iter().position(|&b| b == 0) {
            //             Some(end) => &path[..end],
            //             None => path.as_slice(),
            //         };
            //         if trimmed.is_empty() { continue; }
            //         if str_bytes.starts_with(trimmed) { return Ok(-1); }
            //     }
            // }

            let file = bprm.file;
            let dentry = unsafe{ (*file).f_path.dentry };
            let name_ptr = unsafe { (*dentry).d_name.name };
            let mut name_buf = [0u8; 64];
            unsafe { bpf_probe_read_kernel_str_bytes(name_ptr, &mut name_buf).map_err(|e| e as i32)? };

            if unsafe { BLACKLIST_MAP.get(&name_buf) }.is_some() {
                return Ok(-1);
            }
        }
        
    }

    Ok(0)
}

unsafe fn try_file_permission(ctx: LsmContext) -> Result<i32, i32> {

    let file: *const file = ctx.arg(0);
    let mask: i32 = ctx.arg(1);

    // MAY_WRITE = 0x02 - only care about write operations
    if mask & MAY_WRITE == 0 {
        return Ok(0);
    }

    let file_ref = unsafe { &*file };
    let f_inode = file_ref.f_inode;
    let ino = unsafe { (*f_inode).i_ino };

    let file_type = unsafe { CGROUP_MAP.get(&ino).copied().unwrap_or(0) };
    if file_type != CGROUP_INTERACTIVE_PROCS {
        return Ok(0)
    }
    
    let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    match DEAMON_PID.get(0) {
        Some(deamon_pid) if current_pid == *deamon_pid => {
           return Ok(0);
        }
        Some(_) => {
            info!(&ctx, "file_permission: denied cgroup_procs write from pid {}", current_pid);
           return Ok(-1);
        }
        None => return Ok(0),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
