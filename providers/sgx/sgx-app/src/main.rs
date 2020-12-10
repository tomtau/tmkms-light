#[cfg(target_env = "sgx")]
mod sgx_app;

#[cfg(target_env = "sgx")]
fn main() -> std::io::Result<()> {
    todo!()
}

#[cfg(not(target_env = "sgx"))]
fn main() {
    eprintln!("`tmkms-light-sgx-app` should be compiled for `x86_64-fortanix-unknown-sgx` target");
}
