use serde::{Deserialize, Serialize};
use tendermint::{chain, node};

/// CID for listening on the host
pub const VSOCK_HOST_CID: u32 = 3;

/// Nitro config to be pushed to the enclave
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NitroConfig {
    /// Chain ID of the Tendermint network this validator is part of
    pub chain_id: chain::Id,
    /// Height at which to stop signing
    pub max_height: Option<tendermint::block::Height>,
    /// AWS KMS-encrypted key
    pub sealed_consensus_key: Vec<u8>,
    /// AWS KMS-encrypted Ed25519 identity key (if secret connection)
    pub sealed_id_key: Option<Vec<u8>>,
    /// peer id to check with secret connections
    pub peer_id: Option<node::Id>,
    /// Vsock port to listen on for state synchronization
    pub enclave_state_port: u32,
    /// Vsock port to forward privval plain traffic to TM over UDS or TCP
    pub enclave_tendermint_conn: u32,
    /// AWS credentials -- if not set, they'll be obtained from IAM
    pub credentials: AwsCredentials,
    /// AWS region
    pub aws_region: String,
}

/// configuration sent during key generation
#[derive(Debug, Serialize, Deserialize)]
pub struct NitroKeygenConfig {
    /// AWS credentials -- if not set, they'll be obtained from IAM
    pub credentials: AwsCredentials,
    /// AWS key id
    pub kms_key_id: String,
    /// AWS region
    pub aws_region: String,
}

/// types of initial requests sent to NE
#[derive(Debug, Serialize, Deserialize)]
pub enum NitroRequest {
    /// generate a key
    Keygen(NitroKeygenConfig),
    /// start up TMKMS processing
    Start(NitroConfig),
}

/// response from key generation
#[derive(Debug, Serialize, Deserialize)]
pub struct NitroKeygenResponse {
    /// payload returned from AWS KMS
    pub encrypted_secret: Vec<u8>,
    /// public key for consensus or P2P
    pub public_key: Vec<u8>,
    /// attestation payload (COSE_Sign1) for the public key + encryption key id
    pub attestation_doc: Vec<u8>,
}

/// response from the enclave
pub type NitroResponse = Result<NitroKeygenResponse, String>;

/// Credentials, generally obtained from parent instance IAM
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsCredentials {
    /// AccessKeyId
    pub aws_key_id: String,
    /// SecretAccessKey
    pub aws_secret_key: String,
    /// SessionToken
    pub aws_session_token: String,
}
