use bytes::Bytes;
use ed25519_dalek::{Keypair, PublicKey};
use rand_core::OsRng;
use rusoto_core::{region::Region, HttpClient};
use rusoto_credential::InstanceMetadataProvider;
use rusoto_kms::{EncryptRequest, Kms, KmsClient};
use std::str::FromStr;
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

/// Generates key and encrypts with AWS KMS at the given path
/// TODO: generate in NE after this is merged https://github.com/aws/aws-nitro-enclaves-sdk-c/pull/25
pub fn generate_key(
    path: impl AsRef<Path>,
    region: &str,
    key_id: String,
) -> Result<PublicKey, String> {
    let region = Region::from_str(region).map_err(|e| format!("invalid region: {}", e))?;
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let public = keypair.public;
    let mut rt = tokio::runtime::Runtime::new()
        .map_err(|err| format!("Failed to init tokio runtime: {}", err))?;
    let ciphertext = rt
        .block_on(async move {
            let provider = InstanceMetadataProvider::new();
            let dispatcher = HttpClient::new()
                .map_err(|e| format!("failed to create request dispatcher {}", e))?;
            let client = KmsClient::new_with(dispatcher, provider, region);
            client
                .encrypt(EncryptRequest {
                    encryption_context: None,
                    grant_tokens: None,
                    encryption_algorithm: None,
                    key_id,
                    plaintext: Bytes::copy_from_slice(keypair.secret.as_bytes()),
                })
                .await
                .map_err(|err| format!("Failed to obtain ciphertext from instance: {}", err))
        })?
        .ciphertext_blob
        .ok_or_else(|| "failed to obtain ciphertext blob".to_owned())?;

    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path.as_ref())
        .and_then(|mut file| file.write_all(&*ciphertext))
        .map_err(|e| format!("couldn't write `{}`: {}", path.as_ref().display(), e))?;
    Ok(public)
}
