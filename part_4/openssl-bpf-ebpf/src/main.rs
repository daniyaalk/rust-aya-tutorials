#![no_std]
#![no_main]

use core::ffi::{c_int, c_void};
use aya_ebpf::{macros::uprobe, programs::ProbeContext};
use aya_ebpf::helpers::bpf_probe_read_user_buf;
use aya_ebpf::macros::map;
use aya_ebpf::maps::PerfEventArray;
use aya_log_ebpf::info;
use openssl_bpf_common::SSLData;

const MAX_READ_CHUNKS: usize =  10;

#[map]
static EVENTS: PerfEventArray<SSLData> = PerfEventArray::new(0);

#[uprobe]
pub fn openssl_bpf(ctx: ProbeContext) -> u32 {
    match try_openssl_bpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_openssl_bpf(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function SSL_write called by openssl");

    let buf_ptr: *const c_void = ctx.arg(1).ok_or(1u32)?;
    let num_bytes_ptr: *const c_int = ctx.arg(2).ok_or(1u32)?;

    if buf_ptr.is_null() || num_bytes_ptr.is_null() {
        return Err(1u32);
    }


    send(&ctx, buf_ptr, num_bytes_ptr as usize);

    Ok(0)
}

fn send(ctx: &ProbeContext, buf_ptr: *const c_void, num_bytes: usize) {

    let mut ebpf_buf= [0u8; 200];


    let mut offset = 0;

    for i in 0..MAX_READ_CHUNKS {
        let remaining = num_bytes - offset;

        if remaining == 0 {break;}

        let buf_size = match num_bytes {
            0..200 => remaining,
            200.. => 200
        };

        unsafe {
            bpf_probe_read_user_buf(
                buf_ptr.add(offset) as *const u8,
                &mut ebpf_buf[..buf_size]
            )};

        let data: SSLData = SSLData{buf: ebpf_buf, num_bytes: buf_size};
        EVENTS.output(ctx, &data, 0);

        offset += buf_size;

    }

}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
