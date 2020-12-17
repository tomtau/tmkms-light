#[cfg(target_env = "sgx")]
mod sgx_app;

#[cfg(target_env = "sgx")]
fn main() -> std::io::Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    // "init" stream is provided by the enclave runner
    // user call extension (in sgx-runner)
    let init_conn = std::net::TcpStream::connect("init")?;
    tracing::info!("connected");
    sgx_app::entry(init_conn)
}

#[cfg(not(target_env = "sgx"))]
fn main() {
    eprintln!("`tmkms-light-sgx-app` should be compiled for `x86_64-fortanix-unknown-sgx` target");
}
