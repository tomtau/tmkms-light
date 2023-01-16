use base64::{engine::general_purpose, Engine as _};
use rsa::PublicKeyParts;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sgx_isa::{Keypolicy, Keyrequest, Report, Targetinfo};
use std::convert::TryInto;
use std::fmt;
use std::str::FromStr;
use tendermint::consensus;
use tendermint::node;
use tmkms_light::config::validator::ValidatorConfig;

/// keyseal is fixed in the enclave app
pub type AesGcmSivNonce = [u8; 12];

/// from sealing the ed25519 keypairs + RSA PKCS1
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
    pub nonce: AesGcmSivNonce,
    pub sealed_secret: Ciphertext,
}

/// ed25519 pubkey alias
pub type PublicKey = [u8; 32];

/// Returned from the enclave app after keygen
/// if the cloud backup option is requested.
/// This may be needed in cloud settings
/// without HW/CPU affinity, as instances
/// may be relocated and fail to unseal `SealedKeyData`
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloudBackupKeyData {
    pub nonce: AesGcmSivNonce,
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

/// package for cloud backups
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloudBackupKey {
    pub sealed_rsa_key: SealedKeyData,
    pub backup_key: CloudBackupSeal,
}

/// payload from cloud environments for backups
#[derive(Debug, Clone)]
pub struct CloudBackupSeal {
    /// kek encrypted using RSA-OAEP+SHA-256
    pub encrypted_symmetric_key: [u8; 256],
    /// 32-byte key that can be unwrapped with the decrypted kek
    /// using RFC3394/RFC5649 AES-KWP
    pub wrapped_cloud_sealing_key: [u8; 40],
}

impl CloudBackupSeal {
    /// returns the struct if the payload length matches the expected on
    pub fn new(payload: Vec<u8>) -> Option<Self> {
        if payload.len() != 296 {
            None
        } else {
            let mut encrypted_symmetric_key = [0u8; 256];
            encrypted_symmetric_key.copy_from_slice(&payload[..256]);
            let mut wrapped_cloud_sealing_key = [0u8; 40];
            wrapped_cloud_sealing_key.copy_from_slice(&payload[256..]);
            Some(Self {
                encrypted_symmetric_key,
                wrapped_cloud_sealing_key,
            })
        }
    }
}

impl Serialize for CloudBackupSeal {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CloudBackupSeal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrVisitor;

        impl<'de> de::Visitor<'de> for StrVisitor {
            type Value = CloudBackupSeal;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("CloudBackupSeal")
            }

            #[inline]
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                CloudBackupSeal::from_str(value).map_err(|err| de::Error::custom(err.to_string()))
            }
        }

        deserializer.deserialize_str(StrVisitor)
    }
}

impl fmt::Display for CloudBackupSeal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let full = [
            &self.encrypted_symmetric_key[..],
            &self.wrapped_cloud_sealing_key[..],
        ]
        .concat();
        let full_str = general_purpose::STANDARD.encode(&full);
        write!(f, "{}", full_str)
    }
}

impl FromStr for CloudBackupSeal {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = general_purpose::STANDARD.decode(s)?;
        CloudBackupSeal::new(bytes).ok_or(base64::DecodeError::InvalidLength)
    }
}

/// request sent to the enclave app
/// TODO: check the clippy size diff warning (it may not be worth it, given these are one-off requests)
#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SgxInitRequest {
    /// generates a wrapping key for cloud backups
    GenWrapKey {
        /// if dcap is used
        targetinfo: Option<Targetinfo>,
    },
    /// generate a new keypair
    KeyGen {
        cloud_backup: Option<CloudBackupKey>,
    },
    /// reseal the keypair from a backup
    CloudRecover {
        cloud_backup: CloudBackupKey,
        key_data: CloudBackupKeyData,
    },
    /// start the main loop for processing Tendermint privval requests
    Start {
        sealed_key: SealedKeyData,
        config: ValidatorConfig,
        secret_connection: Option<RemoteConnectionConfig>,
        initial_state: consensus::State,
    },
}

/// response sent from the enclave app
/// TODO: check the clippy size diff warning (it may not be worth it, given these are one-off requests)
#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SgxInitResponse {
    WrapKey {
        /// key sealed for local CPU
        wrap_key_sealed: SealedKeyData,
        /// wrapping public key
        wrap_pub_key: rsa::RsaPublicKey,
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

/// obtain a json claim for RSA pubkey
/// (bigendian values  are encoded in URL-safe base64)
pub fn get_claim(wrap_pub_key: &rsa::RsaPublicKey) -> String {
    let n = wrap_pub_key.n().to_bytes_be();
    let e = wrap_pub_key.e().to_bytes_be();
    let encoded_n = general_purpose::URL_SAFE.encode(&n);
    let encoded_e = general_purpose::URL_SAFE.encode(&e);
    format!(
        "{{\"kid\":\"wrapping-key\",\"kty\":\"RSA\",\"e\":\"{}\",\"n\":\"{}\"}}",
        encoded_e, encoded_n
    )
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
