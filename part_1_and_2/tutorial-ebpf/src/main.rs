#![no_std]
#![no_main]

use core::ffi::{c_int, c_uint};
use aya_ebpf::{bpf_printk, macros::tracepoint, programs::TracePointContext, EbpfContext};
use aya_log_ebpf::info;

#[tracepoint]
pub fn tutorial_func(ctx: TracePointContext) -> u32 {
    match try_tutorial(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tutorial(ctx: TracePointContext) -> Result<u32, i64> {

    let fd: c_int = unsafe {ctx.read_at(16)?};
    let addrlen: c_int = unsafe {ctx.read_at(32)?};
    info!(&ctx, "tracepoint sys_enter_connect called, fd : {}, addlen: {}, pid: {}, tgid: {}", fd, addrlen, ctx.pid(), ctx.tgid());
    unsafe{bpf_printk!(b"racepoint sys_enter_connect called, fd : %d, addlen: %d, pid: %d, tgid: %d", fd, addrlen, ctx.pid(), ctx.tgid())};
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
