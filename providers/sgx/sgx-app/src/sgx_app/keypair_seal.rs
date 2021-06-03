use aes_gcm_siv::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    Aes128GcmSiv, Aes256GcmSiv,
};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretVec};
use sgx_isa::{ErrorCode, Keyname, Keypolicy, Keyrequest, Report};
use std::convert::TryInto;
use tmkms_light_sgx_runner::{CloudBackupKeyData, SealedKeyData, CLOUD_KEY_LEN};
use zeroize::Zeroize;

/// symmetric key wrap -- e.g. from cloud KMS
pub struct CloudWrapKey(SecretVec<u8>);

impl ExposeSecret<Vec<u8>> for CloudWrapKey {
    fn expose_secret(&self) -> &Vec<u8> {
        self.0.expose_secret()
    }
}

impl CloudWrapKey {
    /// creates the new wrapper if the length is correct
    pub fn new(secret: Vec<u8>) -> Option<Self> {
        if secret.len() == CLOUD_KEY_LEN {
            Some(Self(SecretVec::new(secret)))
        } else {
            None
        }
    }
}

/// As cloud vendors may not guarantee HW affinity,
/// this is optionally used to seal the keypair with the externally provided
/// key (e.g. injected from cloud HSM) with `Aes256GcmSiv`.
/// The payload encrypted with this key can then be used to recover
/// when the instance is relocated etc.
pub fn cloud_backup(
    csprng: &mut OsRng,
    seal_key: CloudWrapKey,
    keypair: &Keypair,
) -> Result<CloudBackupKeyData, aes_gcm_siv::aead::Error> {
    let mut nonce = [0u8; 12];
    csprng.fill_bytes(&mut nonce);
    let payload = Payload {
        msg: keypair.secret.as_bytes(),
        aad: keypair.public.as_bytes(),
    };
    let nonce_ga = GenericArray::from_slice(&nonce);
    let gk = GenericArray::from_slice(seal_key.expose_secret());
    let aead = Aes256GcmSiv::new(gk);
    aead.encrypt(nonce_ga, payload)
        .map(|sealed_secret| CloudBackupKeyData {
            sealed_secret,
            nonce,
            public_key: keypair.public,
        })
}

/// Recovers the backed up keypair (decrypt it using the externally
/// provided key, e.g. injected from cloud HSM) and seals it on that CPU.
pub fn seal_recover_cloud_backup(
    csprng: &mut OsRng,
    seal_key: CloudWrapKey,
    backup_data: CloudBackupKeyData,
) -> Result<SealedKeyData, ErrorCode> {
    let nonce_ga = GenericArray::from_slice(&backup_data.nonce);
    let gk = GenericArray::from_slice(&seal_key.expose_secret());
    let aead = Aes256GcmSiv::new(gk);
    let payload = Payload {
        msg: &backup_data.sealed_secret,
        aad: backup_data.public_key.as_bytes(),
    };
    if let Ok(mut secret_key) = aead.decrypt(nonce_ga, payload) {
        drop(seal_key);
        let secret = SecretKey::from_bytes(&secret_key).map_err(|_| ErrorCode::InvalidSignature)?;
        secret_key.zeroize();
        let public = PublicKey::from(&secret);
        let mut kp = Keypair { secret, public };
        let sealed = seal(csprng, &kp);
        kp.secret.zeroize();
        sealed
    } else {
        drop(seal_key);
        Err(ErrorCode::MacCompareFail)
    }
}

fn seal_payload(
    csprng: &mut OsRng,
    payload: Payload,
    keyid: [u8; 32],
) -> Result<SealedKeyData, ErrorCode> {
    let mut nonce = [0u8; 12];
    csprng.fill_bytes(&mut nonce);
    let report = Report::for_self();
    let key_request = Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRSIGNER,
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        keyid,
        ..Default::default()
    };
    let nonce_ga = GenericArray::from_slice(&nonce);
    let mut key = key_request.egetkey()?;
    let gk = GenericArray::from_slice(&key);
    let aead = Aes128GcmSiv::new(gk);
    if let Ok(sealed_secret) = aead.encrypt(nonce_ga, payload) {
        key.zeroize();
        Ok(SealedKeyData {
            seal_key_request: key_request.into(),
            nonce,
            sealed_secret,
        })
    } else {
        key.zeroize();
        Err(ErrorCode::MacCompareFail)
    }
}

/// Seals the provided ed25519 keypair with `Aes128GcmSiv`
/// via a key request against MRSIGNER (so that versions with higher `isvsvn`
/// can unseal the keypair)
pub fn seal(csprng: &mut OsRng, keypair: &Keypair) -> Result<SealedKeyData, ErrorCode> {
    let payload = Payload {
        msg: keypair.secret.as_bytes(),
        aad: keypair.public.as_bytes(),
    };
    seal_payload(csprng, payload, keypair.public.to_bytes())
}

pub fn seal_secret(
    csprng: &mut OsRng,
    secret: &[u8],
    keyid: [u8; 32],
) -> Result<SealedKeyData, ErrorCode> {
    let payload = Payload {
        msg: secret,
        aad: &keyid,
    };
    seal_payload(csprng, payload, keyid)
}

pub fn unseal_secret(sealed_data: &SealedKeyData) -> Result<Vec<u8>, ErrorCode> {
    if sealed_data.seal_key_request.keyname != (Keyname::Seal as u16) {
        return Err(ErrorCode::InvalidKeyname);
    }
    let key_request: Keyrequest = sealed_data
        .seal_key_request
        .try_into()
        .map_err(|_| ErrorCode::InvalidAttribute)?;
    let payload = Payload {
        msg: &sealed_data.sealed_secret,
        aad: &sealed_data.seal_key_request.keyid,
    };
    let nonce_ga = GenericArray::from_slice(&sealed_data.nonce);
    let mut key = key_request.egetkey()?;
    let gk = GenericArray::from_slice(&key);
    let aead = Aes128GcmSiv::new(gk);
    if let Ok(secret_key) = aead.decrypt(nonce_ga, payload) {
        key.zeroize();
        Ok(secret_key)
    } else {
        key.zeroize();
        Err(ErrorCode::MacCompareFail)
    }
}

/// Checks the provided keyrequests
/// and attempts to unseal the ed25519 keypair with `Aes128GcmSiv`
pub fn unseal(sealed_data: &SealedKeyData) -> Result<Keypair, ErrorCode> {
    if let Ok(public) = PublicKey::from_bytes(&sealed_data.seal_key_request.keyid) {
        let mut secret_key = unseal_secret(sealed_data)?;
        let secret = SecretKey::from_bytes(&secret_key).map_err(|_| ErrorCode::InvalidSignature)?;
        secret_key.zeroize();
        Ok(Keypair { secret, public })
    } else {
        Err(ErrorCode::InvalidSignature)
    }
}
