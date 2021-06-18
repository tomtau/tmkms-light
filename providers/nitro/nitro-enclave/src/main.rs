use tracing::Level;
use tracing::{error, info, warn, Subscriber};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use vsock::{SockAddr, VsockListener};

use tmkms_nitro_helper::tracing_layer::Layer;
use tmkms_nitro_helper::VSOCK_HOST_CID;
use tracing_subscriber::filter::LevelFilter;

mod nitro;

fn main() {
    let mut env_args = std::env::args();
    let port = env_args
        .next()
        .map(|x| x.parse::<u32>().ok())
        .flatten()
        .unwrap_or(5050);

    let log_server_port = env_args
        .next()
        .map(|x| x.parse::<u32>().ok())
        .flatten()
        .unwrap_or(6050);

    let log_level = env_args
        .next()
        .map(|x| {
            if x.to_lowercase() == "--verbose" || x.to_lowercase() == "-v" {
                Level::INFO
            } else {
                Level::DEBUG
            }
        })
        .unwrap_or_else(|| Level::INFO);
    let log_layer = LevelFilter::from(log_level);
    let layer = Layer::new(VSOCK_HOST_CID, log_server_port);
    let fmt_layer = fmt::layer().with_target(false);
    let layered = tracing_subscriber::registry()
        .with(log_layer)
        .with(fmt_layer)
        .with(layer);

    tracing::subscriber::set_global_default(layered).expect("setting default subscriber failed");

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
