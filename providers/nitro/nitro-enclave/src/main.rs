mod nitro;
use nix::sys::socket::SockAddr;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use vsock::VsockListener;

fn main() {
    // TODO: subscriber for production to forward to vsock
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let port = std::env::args()
        .next()
        .map(|x| x.parse::<u32>().ok())
        .flatten()
        .unwrap_or(5050);
    const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
    let addr = SockAddr::new_vsock(VMADDR_CID_ANY, port);
    let listener = VsockListener::bind(&addr).expect("bind address");
    info!("waiting for config to be pushed on {}", addr);
    for conn in listener.incoming() {
        if aws_ne_sys::seed_entropy(512).is_err() {
            error!("failed to seed initial entropy!");
            std::process::exit(1);
        }
        match conn {
            Ok(stream) => {
                info!("got connection on {:?}", addr);
                if let Err(e) = nitro::entry(stream) {
                    error!("io error {}", e);
                }
            }
            Err(e) => {
                warn!("connection error {}", e);
            }
        }
    }
}
