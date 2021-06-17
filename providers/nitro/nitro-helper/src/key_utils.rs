use crate::shared::AwsCredentials;
use aws_sdk_kms::config::Config;
use aws_sdk_kms::Credentials as KmsCredentials;
use aws_sdk_kms::{Client as KmsClient, Region};
use ed25519_dalek::{Keypair, PublicKey};
use rand_core::OsRng;
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::Path};
use tokio::runtime::Builder;
use zeroize::Zeroizing;

// TODO: use aws-rust-sdk after the issue fixed
// https://github.com/awslabs/aws-sdk-rust/issues/97
pub(crate) mod credential {
    use crate::shared::AwsCredentials;
    use reqwest::blocking::Client;
    use reqwest::header::{HeaderName, HeaderValue};
    use secrecy::{ExposeSecret, SecretString};
    use serde::Deserialize;
    use std::str::FromStr;

    const AWS_CREDENTIALS_PROVIDER_IP: &str = "169.254.169.254";
    const AWS_CREDENTIALS_PROVIDER_PATH: &str = "latest/meta-data/iam/security-credentials";
    const AWS_TOKEN_PATH: &str = "latest/api/token";

    #[derive(Clone, Debug, Deserialize)]
    pub struct AwsCredentialsResponse {
        #[serde(alias = "AccessKeyId")]
        aws_key_id: SecretString,
        #[serde(alias = "SecretAccessKey")]
        aws_secret_key: SecretString,
        #[serde(default, alias = "Token")]
        aws_session_token: Option<SecretString>,
    }

    impl From<AwsCredentialsResponse> for AwsCredentials {
        fn from(r: AwsCredentialsResponse) -> AwsCredentials {
            AwsCredentials {
                aws_key_id: r.aws_key_id.expose_secret().into(),
                aws_secret_key: r.aws_secret_key.expose_secret().into(),
                // note: the token should not be none so that unwrap can be used
                aws_session_token: r.aws_session_token.unwrap().expose_secret().into(),
            }
        }
    }

    /// get credentials from Aws Instance Metadata Service Version 2
    /// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
    pub fn get_credentials() -> Result<AwsCredentials, String> {
        let token_address = format!("http://{}/{}/", AWS_CREDENTIALS_PROVIDER_IP, AWS_TOKEN_PATH);
        let client = Client::new();
        let header_key = HeaderName::from_str("X-aws-ec2-metadata-token-ttl-seconds").unwrap();
        let header_value = HeaderValue::from_str("30").unwrap();
        let token_response = client
            .put(token_address)
            .header(header_key, header_value)
            .send()
            .map_err(|e| format!("get aws token error: {:?}", e))?;

        let token = if token_response.status().is_success() {
            token_response
                .text()
                .map_err(|e| format!("can't get token: {:?}", e))?
        } else {
            return Err(format!(
                "get aws sdk token failed, error code: {}",
                token_response.status()
            ));
        };

        let header_token_name = HeaderName::from_str("X-aws-ec2-metadata-token").unwrap();
        let header_token_value =
            HeaderValue::from_str(&token).map_err(|_| "invalid token".to_string())?;

        /// Gets the role name to get credentials
        let role_name_address = format!(
            "http://{}/{}/",
            AWS_CREDENTIALS_PROVIDER_IP, AWS_CREDENTIALS_PROVIDER_PATH
        );
        let role_name = client
            .get(role_name_address)
            .header(header_token_name.clone(), header_token_value.clone())
            .send()
            .map_err(|e| format!("get role name error: {:?}", e))?
            .text()
            .map_err(|e| format!("get role name result failed: {:?}", e))?;
        let credentials_provider_url = format!(
            "http://{}/{}/{}",
            AWS_CREDENTIALS_PROVIDER_IP, AWS_CREDENTIALS_PROVIDER_PATH, role_name
        );
        let credentials: AwsCredentialsResponse = client
            .get(credentials_provider_url)
            .header(header_token_name, header_token_value)
            .send()
            .map_err(|e| format!("get credentials error: {:?}", e))?
            .json()
            .map_err(|e| format!("get credentials result failed: {:?}", e))?;
        if credentials.aws_session_token.is_none() {
            return Err("aws session is empty in credentials".to_string());
        }
        Ok(credentials.into())
    }
}

/// Generates key and encrypts with AWS KMS at the given path
/// TODO: generate in NE after this is merged https://github.com/aws/aws-nitro-enclaves-sdk-c/pull/55
pub fn generate_key(
    path: impl AsRef<Path>,
    region: &str,
    credentials: AwsCredentials,
    kms_key_id: String,
) -> Result<PublicKey, String> {
    let credientials = KmsCredentials::from_keys(
        credentials.aws_key_id,
        &credentials.aws_secret_key,
        Some(credentials.aws_session_token),
    );
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    let public = keypair.public;
    let private_key = Zeroizing::new(keypair.secret.as_bytes().to_vec());
    let privkey_blob = smithy_types::Blob::new(<Vec<u8> as AsRef<[u8]>>::as_ref(&private_key));
    let kms_config = Config::builder()
        .region(Region::new(region.to_string()))
        .credentials_provider(credientials)
        .build();

    let client = KmsClient::from_conf(kms_config);
    let generator = client
        .encrypt()
        .set_plaintext(Some(privkey_blob))
        .set_key_id(Some(kms_key_id));

    let rt = Builder::new_current_thread()
        .build()
        .map_err(|err| format!("Failed to init tokio runtime: {}", err))?;
    let output = rt
        .block_on(generator.send())
        .map_err(|e| format!("send to mks to encrypt error: {:?}", e))?;
    let ciphertext = output
        .ciphertext_blob
        .ok_or_else(|| "empty private key ciphertext in response".to_string())?
        .into_inner();
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
