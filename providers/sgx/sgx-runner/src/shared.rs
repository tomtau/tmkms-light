use serde::{Deserialize, Serialize};
use sgx_isa::{Keypolicy, Keyrequest, Report, Targetinfo};
use std::convert::TryInto;
use tendermint::consensus;
use tendermint::node;
use tmkms_light::config::validator::ValidatorConfig;

/// keyseal is fixed in the enclave app
pub type AesGcm128SivNonce = [u8; 12];

/// it can potentially be fixed size, as one always seals the ed25519 keypairs
pub type Ciphertext = Vec<u8>;

/// this partially duplicates `Keyrequest` from sgx-isa,
/// which doesn't implement serde traits
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub struct KeyRequestWrap {
    pub keyname: u16,
    pub keypolicy: u16,
    pub isvsvn: u16,
    pub cpusvn: [u8; 16],
    pub attributemask: [u64; 2],
    pub keyid: PublicKey,
    pub miscmask: u32,
}

impl TryInto<Keyrequest> for KeyRequestWrap {
    type Error = ();

    fn try_into(self) -> Result<Keyrequest, ()> {
        let keypolicy = Keypolicy::from_bits(self.keypolicy).ok_or(())?;
        Ok(Keyrequest {
            keyname: self.keyname,
            keypolicy,
            isvsvn: self.isvsvn,
            cpusvn: self.cpusvn,
            attributemask: self.attributemask,
            keyid: self.keyid,
            miscmask: self.miscmask,
            ..Default::default()
        })
    }
}

impl From<Keyrequest> for KeyRequestWrap {
    fn from(kr: Keyrequest) -> Self {
        KeyRequestWrap {
            keyname: kr.keyname,
            keypolicy: kr.keypolicy.bits(),
            isvsvn: kr.isvsvn,
            cpusvn: kr.cpusvn,
            attributemask: kr.attributemask,
            keyid: kr.keyid,
            miscmask: kr.miscmask,
        }
    }
}

/// Returned from the enclave app after keygen
/// and expected to be persisted by tmkms
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SealedKeyData {
    pub seal_key_request: KeyRequestWrap,
    pub nonce: AesGcm128SivNonce,
    pub sealed_secret: Ciphertext,
}

/// ed25519 pubkey alias
pub type PublicKey = [u8; 32];

/// length of symmetric key wrap for cloud backup using e.g. cloud KMS
pub const CLOUD_KEY_LEN: usize = 16;

/// Returned from the enclave app after keygen
/// if the cloud backup option is requested.
/// This may be needed in cloud settings
/// without HW/CPU affinity, as instances
/// may be relocated and fail to unseal `SealedKeyData`
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloudBackupKeyData {
    pub nonce: AesGcm128SivNonce,
    pub sealed_secret: Ciphertext,
    pub public_key: ed25519_dalek::PublicKey,
}

/// configuration for direct remote communication with TM
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteConnectionConfig {
    /// Remote peer ID
    pub peer_id: Option<node::Id>,

    /// Hostname or IP address
    pub host: String,

    /// Port
    pub port: u16,

    /// Sealed key for TM SecretConnection
    pub sealed_key: SealedKeyData,
}

/// request sent to the enclave app
#[derive(Debug, Serialize, Deserialize)]
pub enum SgxInitRequest {
    /// generates a wrapping key for cloud backups
    GenWrapKey {
        /// if dcap is used
        targetinfo: Option<Targetinfo>,
    },
    /// generate a new keypair
    KeyGen,
    /// reseal the keypair from a backup
    CloudRecover { key_data: CloudBackupKeyData },
    /// start the main loop for processing Tendermint privval requests
    Start {
        sealed_key: SealedKeyData,
        config: ValidatorConfig,
        secret_connection: Option<RemoteConnectionConfig>,
        initial_state: consensus::State,
    },
}

/// response sent from the enclave app
#[derive(Debug, Serialize, Deserialize)]
pub enum SgxInitResponse {
    WrapKey {
        /// key sealed for local CPU
        wrap_key_sealed: SealedKeyData,
        /// wrapping public key
        wrap_pub_key: rsa::RSAPublicKey,
        /// report attesting the wrapping public key
        /// (to be used for a quote)
        pub_key_report: Report,
    },
    /// response to key generation or recovery
    GenOrRecover {
        /// freshly generated or recovered sealed keypair
        sealed_key_data: SealedKeyData,
        /// if requested, keypair encrypted with the provided key
        cloud_backup_key_data: Option<CloudBackupKeyData>,
    },
}

impl SgxInitResponse {
    /// get key generation or recovery response
    pub fn get_gen_response(self) -> Option<(SealedKeyData, Option<CloudBackupKeyData>)> {
        match self {
            SgxInitResponse::GenOrRecover {
                sealed_key_data,
                cloud_backup_key_data,
            } => Some((sealed_key_data, cloud_backup_key_data)),
            _ => None,
        }
    }
}
