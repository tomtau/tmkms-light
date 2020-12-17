use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm_siv::Aes128GcmSiv;
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sgx_isa::{ErrorCode, Keyname, Keypolicy, Keyrequest, Report};
use std::convert::TryInto;
use tmkms_light_sgx_runner::SealedKeyData;
use zeroize::Zeroize;

/// Seals the provided ed25519 keypair with `Aes128GcmSiv`
/// via a key request against MRSIGNER (so that versions with higher `isvsvn`
/// can unseal the keypair)
pub fn seal(csprng: &mut OsRng, keypair: &Keypair) -> Result<SealedKeyData, ErrorCode> {
    let mut nonce = [0u8; 12];
    csprng.fill_bytes(&mut nonce);
    let report = Report::for_self();
    let key_request = Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRSIGNER,
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        keyid: keypair.public.to_bytes(),
        ..Default::default()
    };
    let payload = Payload {
        msg: keypair.secret.as_bytes(),
        aad: keypair.public.as_bytes(),
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

/// Checks the provided keyrequests
/// and attempts to unseal the ed25519 keypair with `Aes128GcmSiv`
pub fn unseal(sealed_data: &SealedKeyData) -> Result<Keypair, ErrorCode> {
    if sealed_data.seal_key_request.keyname != (Keyname::Seal as u16) {
        return Err(ErrorCode::InvalidKeyname);
    }
    if let Ok(public) = PublicKey::from_bytes(&sealed_data.seal_key_request.keyid) {
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
        if let Ok(mut secret_key) = aead.decrypt(nonce_ga, payload) {
            key.zeroize();
            let secret =
                SecretKey::from_bytes(&secret_key).map_err(|_| ErrorCode::InvalidSignature)?;
            secret_key.zeroize();
            Ok(Keypair { secret, public })
        } else {
            key.zeroize();
            Err(ErrorCode::MacCompareFail)
        }
    } else {
        Err(ErrorCode::InvalidSignature)
    }
}
