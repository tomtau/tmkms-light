use secrecy::{DebugSecret, Secret, SerializableSecret};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use sgx_isa::{Keypolicy, Keyrequest};
use std::convert::TryInto;
use tendermint::node;
use tmkms_light::config::validator::ValidatorConfig;
use zeroize::{Zeroize, Zeroizing};

/// keyseal is fixed in the enclave app
pub type AesGcm128SivNonce = [u8; 12];

/// it can potentially be fixed size, as one always seals the ed25519 keypairs
pub type Ciphertext = Vec<u8>;

/// this partially duplicates `Keyrequest` from sgx-isa,
/// which doesn't implement serde traits
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub struct KeyRequest {
    pub keyname: u16,
    pub keypolicy: u16,
    pub isvsvn: u16,
    pub cpusvn: [u8; 16],
    pub attributemask: [u64; 2],
    pub keyid: PublicKey,
    pub miscmask: u32,
}

impl TryInto<Keyrequest> for KeyRequest {
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

impl From<Keyrequest> for KeyRequest {
    fn from(kr: Keyrequest) -> Self {
        KeyRequest {
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
    pub seal_key_request: KeyRequest,
    pub nonce: AesGcm128SivNonce,
    pub sealed_secret: Ciphertext,
}

/// ed25519 pubkey alias
pub type PublicKey = [u8; 32];

const CLOUD_KEY_LEN: usize = 16;

/// symmetric key wrap -- e.g. from cloud KMS
#[derive(Zeroize, Clone)]
pub struct CloudWrapKeyInner([u8; CLOUD_KEY_LEN]);

impl<'de> Deserialize<'de> for CloudWrapKeyInner {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = Zeroizing::new(
            Vec::deserialize(deserializer).map_err(|e| D::Error::custom(format!("{}", e)))?,
        );
        if data.len() != CLOUD_KEY_LEN {
            return Err(D::Error::custom("incorrect key length"));
        } else {
            let mut inner = [0u8; CLOUD_KEY_LEN];
            inner.clone_from_slice(&data);
            return Ok(Self(inner));
        }
    }
}

impl Serialize for CloudWrapKeyInner {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Zeroizing::new(self.0).serialize(serializer)
    }
}

impl SerializableSecret for CloudWrapKeyInner {}
impl DebugSecret for CloudWrapKeyInner {}

/// symmetric key wrap -- e.g. from cloud KMS
pub type CloudWrapKey = Secret<CloudWrapKeyInner>;

/// Returned from the enclave app after keygen
/// if the cloud backup option is requested.
/// This may be needed in cloud settings
/// without HW/CPU affinity, as instances
/// may be relocated and fail to unseal `SealedKeyData`
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloudBackupKeyData {
    pub nonce: AesGcm128SivNonce,
    pub sealed_secret: Ciphertext,
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
    /// generate a new keypair
    KeyGen {
        cloud_backup_key: Option<CloudWrapKey>,
    },
    /// reseal the keypair from a backup
    CloudRecover {
        cloud_backup_key: CloudWrapKey,
        key_data: CloudBackupKeyData,
    },
    /// start the main loop for processing Tendermint privval requests
    Start {
        sealed_key: SealedKeyData,
        config: ValidatorConfig,
        secret_connection: Option<RemoteConnectionConfig>,
    },
}

/// response sent from the enclave app
#[derive(Debug, Serialize, Deserialize)]
pub struct SgxInitResponse {
    /// freshly generated or recovered sealed keypair
    pub sealed_key_data: SealedKeyData,
    /// if requested, keypair encrypted with the provided key
    pub cloud_backup_key_data: Option<CloudBackupKeyData>,
}
