#![no_std]
#![no_main]

use core::ffi::c_short;
use core::mem;
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_ebpf::helpers::{bpf_probe_read, bpf_probe_read_kernel};
use aya_log_ebpf::info;
use tcp_kprobe_common::sock::{sock, sock_common};

#[kprobe]
pub fn tcp_kprobe(ctx: ProbeContext) -> u32 {
    match try_tcp_kprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_kprobe(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe called");

    let skc_ptr : *const sock_common = ctx.arg(0).ok_or(1u32)?;

    let result = unsafe { bpf_probe_read_kernel(skc_ptr)};

    if result.is_err() {
        return Err(1);
    }

    let sk_common = result.map_err(|_| 2u32)?;
    let skc_dport = unsafe{sk_common.__bindgen_anon_3.__bindgen_anon_1}.skc_dport as u16;

    match sk_common.skc_family {
        2 => {
            let skc_daddr = unsafe{sk_common.__bindgen_anon_1.__bindgen_anon_1}.skc_daddr;
            info!(&ctx, "kprobe called, {:i}, {}, {}", skc_daddr, u16::from_be(skc_dport), sk_common.skc_family);
        },
        10 => {
            info!(&ctx, "kprobe called, {:i}, {}, {}", unsafe{sk_common.skc_v6_daddr.in6_u.u6_addr8}, u16::from_be(skc_dport), sk_common.skc_family);
        },
        _ => ()
    }


    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
