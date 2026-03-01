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
use aya_ebpf::{macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;
use aya_ebpf::helpers;
use core::str;
use vmlinux::linux_binprm;

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match unsafe { try_bprm_check_security(ctx) } {
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
            helpers::bpf_probe_read_kernel_str_bytes(bprm.filename, &mut buf)
                .map_err(|e| e as i32)?
        };

        let filename = unsafe { str::from_utf8_unchecked(str_bytes) };
        
        let creds = bprm.cred;
        if creds.is_null() {
            info!(&ctx, "real_cred is null");
        } else {
            let uid = unsafe { (*creds).uid.val };
            info!(&ctx, "filename: {} uid: {}", filename, uid);
        }
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
