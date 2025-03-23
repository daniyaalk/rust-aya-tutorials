use aya::maps::AsyncPerfEventArray;
use aya::programs::UProbe;
use aya::util::online_cpus;
use bytes::BytesMut;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{signal, task};
use openssl_bpf_common::SSLData;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/openssl-bpf"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { pid } = opt;
    let program: &mut UProbe = ebpf.program_mut("openssl_bpf").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_write"), 0, "libssl", pid)?;

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus().map_err(|(_, e)| e)?.into_iter() {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {

            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();

            loop {

                let events = buf.read_events(&mut buffers).await.unwrap();

                for buf in buffers.iter_mut().take(events.read) {

                    let ptr = buf.as_ptr() as *const SSLData;
                    let data = unsafe { ptr.as_ref() }.unwrap();

                    print_data(data);

                }
            }
        });
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn print_data(data: &SSLData) {

    for i in 0..data.num_bytes {

        let c = data.buf[i];

        if c.is_ascii_graphic() || c.is_ascii_whitespace() {
            print!("{}", c as char);
        }

    }
    
    println!();

}
