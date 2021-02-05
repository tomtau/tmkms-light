#[cfg(target_env = "sgx")]
mod sgx_app;

#[cfg(target_env = "sgx")]
fn main() -> std::io::Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    let mut args = std::env::args();
    let command = args.next();
    if command.is_none() {
        tracing::error!("no enclave command provided");
        return Err(std::io::ErrorKind::Other.into());
    }
    let request = serde_json::from_str(&command.unwrap());
    if request.is_err() {
        tracing::error!("invalid enclave command provided");
        return Err(std::io::ErrorKind::Other.into());
    }
    let request = request.unwrap();
    let mcloud_key = args.next();
    let cloud_key = if let Some(k) = mcloud_key {
        let decoded_vec = subtle_encoding::hex::decode(k)
            .map_err(|_e| std::io::Error::from(std::io::ErrorKind::Other))?;
        sgx_app::keypair_seal::CloudWrapKey::new(decoded_vec)
    } else {
        None
    };
    // "init" stream is provided by the enclave runner
    // user call extension (in sgx-runner)
    let init_conn = std::net::TcpStream::connect("init")?;
    tracing::info!("connected to init stream");
    if let Err(e) = sgx_app::entry(init_conn, request, cloud_key) {
        tracing::error!("error: {}", e);
        Err(e)
    } else {
        Ok(())
    }
}

#[cfg(not(target_env = "sgx"))]
fn main() {
    eprintln!("`tmkms-light-sgx-app` should be compiled for `x86_64-fortanix-unknown-sgx` target");
}
