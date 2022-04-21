use crate::shared::AwsCredentials;
use crate::shared::{NitroKeygenConfig, NitroKeygenResponse, NitroRequest, NitroResponse};

use ed25519_dalek::PublicKey;
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::Path};
use tmkms_light::utils::{read_u16_payload, write_u16_payload};
use vsock::SockAddr;

pub(crate) mod credential {
    use crate::shared::AwsCredentials;
    use aws_config::imds::credentials;
    use aws_types::credentials::ProvideCredentials;
    use tokio::runtime::Builder;

    /// get credentials from Aws Instance Metadata Service Version 2
    /// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
    pub fn get_credentials() -> Result<AwsCredentials, String> {
        let client = credentials::ImdsCredentialsProvider::builder().build();
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to create tokio runtime: {:?}", e))?;
        let aws_credential = rt
            .block_on(client.provide_credentials())
            .map_err(|e| format!("invalid credential: {:?}", e))?;
        let credentials = AwsCredentials {
            aws_key_id: aws_credential.access_key_id().into(),
            aws_secret_key: aws_credential.secret_access_key().into(),
            aws_session_token: aws_credential.session_token().unwrap().into(),
        };

        Ok(credentials)
    }
}

/// Generates a keypair and encrypts with AWS KMS at the given path
/// and returns the public key with attestation doc for it and
/// the used AWS KMS key id
pub fn generate_key(
    cid: u32,
    port: u32,
    path: impl AsRef<Path>,
    region: &str,
    credentials: AwsCredentials,
    kms_key_id: String,
) -> Result<(PublicKey, Vec<u8>), String> {
    let keygen_request = NitroKeygenConfig {
        credentials,
        kms_key_id,
        aws_region: region.into(),
    };

    let request = NitroRequest::Keygen(keygen_request);
    let addr = SockAddr::new_vsock(cid, port);
    let mut socket = vsock::VsockStream::connect(&addr).map_err(|e| {
        format!(
            "failed to connect to the enclave to generate key pair: {:?}",
            e
        )
    })?;
    let request_raw = serde_json::to_vec(&request)
        .map_err(|e| format!("failed to serialize the keygen request: {:?}", e))?;
    write_u16_payload(&mut socket, &request_raw)
        .map_err(|e| format!("failed to write the config: {:?}", e))?;
    // get the response
    let json_raw =
        read_u16_payload(&mut socket).map_err(|_e| "failed to read config".to_string())?;
    let response: NitroResponse = serde_json::from_slice(&json_raw)
        .map_err(|e| format!("failed to get keygen response from enclave: {:?}", e))?;

    let resp: NitroKeygenResponse = response?;
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path.as_ref())
        .and_then(|mut file| file.write_all(&resp.encrypted_secret))
        .map_err(|e| format!("couldn't write `{}`: {}", path.as_ref().display(), e))?;
    Ok((
        PublicKey::from_bytes(&resp.public_key)
            .map_err(|e| format!("Invalid pubkey key: {:?}", e))?,
        resp.attestation_doc,
    ))
}
