/// RFC3394/RFC5649 key unwrapping of 32-byte keys
mod keywrap;

use crate::sgx_app::keypair_seal::seal;
use aes::cipher::generic_array::typenum::U32;
use aes::cipher::generic_array::GenericArray;
use aes_gcm_siv::{
    aead::{Aead, Payload},
    Aes256GcmSiv, KeyInit,
};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1::{der::Document, DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use sgx_isa::ErrorCode;
use sgx_isa::{Report, Targetinfo};
use sha2::{Digest, Sha256};
use tmkms_light_sgx_runner::{
    get_claim, CloudBackupKey, CloudBackupKeyData, CloudBackupSeal, SealedKeyData,
};
use zeroize::Zeroize;

/// Possible errors in cloud backup or recovery
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum CloudError {
    /// RSA generation or PKCS1 issues
    SecretGenerationError,
    /// errors from local CPU sealing
    SealingError(ErrorCode),
    /// RFC3394/RFC5649 AES-KWP unwrap failed
    UnwrapError(keywrap::UnwrapError),
    /// RSA-OAEP+SHA-256 decryption failed
    DecryptionError,
    /// AES-GCM-SIV encryption failed
    EncryptionError,
}

/// Generates an RSA keypair (2048bit with e=65537),
/// seals the private key to a local CPU,
/// and gets a report for sha256 of the public key in JWE.
pub fn generate_keypair(
    csprng: &mut OsRng,
    targetinfo: Targetinfo,
) -> Result<(RsaPublicKey, SealedKeyData, Report), CloudError> {
    const BITS: usize = 2048;
    // default exponent 65537
    let mut priv_key =
        RsaPrivateKey::new(csprng, BITS).map_err(|_| CloudError::SecretGenerationError)?;
    let pub_key = RsaPublicKey::from(&priv_key);

    let claim_payload = get_claim(&pub_key);
    let mut hasher = Sha256::new();
    hasher.update(claim_payload);
    let result: GenericArray<u8, U32> = hasher.finalize();
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(&result);
    let report = Report::for_target(&targetinfo, &report_data);
    let pkcs1 = priv_key.to_pkcs1_der();
    priv_key.zeroize();
    if let Ok(secret) = pkcs1 {
        match crate::sgx_app::keypair_seal::seal_secret(csprng, secret.as_der(), result.into()) {
            Ok(sealed_secret) => Ok((pub_key, sealed_secret, report)),
            Err(e) => Err(CloudError::SealingError(e)),
        }
    } else {
        Err(CloudError::SecretGenerationError)
    }
}

/// helper to decrypt the backup key
fn decrypt_wrapped_key(
    priv_key: &RsaPrivateKey,
    backup_data_seal: CloudBackupSeal,
) -> Result<GenericArray<u8, U32>, CloudError> {
    let mut wrapping_key = priv_key
        .decrypt(
            PaddingScheme::new_oaep::<sha2::Sha256>(),
            &backup_data_seal.encrypted_symmetric_key,
        )
        .map_err(|_| CloudError::DecryptionError)?;
    let msealing_key = keywrap::aes256_unwrap_key_with_pad(
        &wrapping_key,
        &backup_data_seal.wrapped_cloud_sealing_key,
    );
    wrapping_key.zeroize();
    msealing_key.map_err(CloudError::UnwrapError)
}

/// As cloud vendors may not guarantee HW affinity,
/// this is optionally used to seal the keypair with the externally provided
/// key (e.g. injected from cloud HSM) with `Aes256GcmSiv`.
/// The payload encrypted with this key can then be used to recover
/// when the instance is relocated etc.
pub fn cloud_backup(
    csprng: &mut OsRng,
    backup: CloudBackupKey,
    keypair: &Keypair,
) -> Result<CloudBackupKeyData, CloudError> {
    let mut priv_key_raw = crate::sgx_app::keypair_seal::unseal_secret(&backup.sealed_rsa_key)
        .map_err(CloudError::SealingError)?;
    let mpriv_key = RsaPrivateKey::from_pkcs1_der(&priv_key_raw);
    priv_key_raw.zeroize();
    let mut priv_key = mpriv_key.map_err(|_| CloudError::SecretGenerationError)?;
    let mbackup_key = decrypt_wrapped_key(&priv_key, backup.backup_key);
    priv_key.zeroize();
    let mut gk = mbackup_key?;
    let mut nonce = [0u8; 12];
    csprng.fill_bytes(&mut nonce);
    let payload = Payload {
        msg: keypair.secret.as_bytes(),
        aad: keypair.public.as_bytes(),
    };
    let nonce_ga = GenericArray::from_slice(&nonce);
    let aead = Aes256GcmSiv::new(&gk);
    let r = aead
        .encrypt(nonce_ga, payload)
        .map(|sealed_secret| CloudBackupKeyData {
            sealed_secret,
            nonce,
            public_key: keypair.public,
        })
        .map_err(|_| CloudError::EncryptionError);
    gk.zeroize();
    r
}

/// tries to recover the secret from the cloud backup data
/// and (re-)seal it for the current CPU
pub fn reseal_recover_cloud(
    csprng: &mut OsRng,
    backup: CloudBackupKey,
    cloud_backup: CloudBackupKeyData,
) -> Result<SealedKeyData, CloudError> {
    let mut priv_key_raw = crate::sgx_app::keypair_seal::unseal_secret(&backup.sealed_rsa_key)
        .map_err(CloudError::SealingError)?;
    let mpriv_key = RsaPrivateKey::from_pkcs1_der(&priv_key_raw);
    priv_key_raw.zeroize();
    let mut priv_key = mpriv_key.map_err(|_| CloudError::SecretGenerationError)?;
    let mbackup_key = decrypt_wrapped_key(&priv_key, backup.backup_key);
    priv_key.zeroize();
    let backup_key = mbackup_key?;
    seal_recover_cloud_backup(csprng, backup_key, cloud_backup).map_err(CloudError::SealingError)
}

/// Recovers the backed up keypair (decrypt it using the externally
/// provided key, e.g. injected from cloud HSM) and seals it on that CPU.
pub fn seal_recover_cloud_backup(
    csprng: &mut OsRng,
    mut seal_key: GenericArray<u8, U32>,
    backup_data: CloudBackupKeyData,
) -> Result<SealedKeyData, ErrorCode> {
    let nonce_ga = GenericArray::from_slice(&backup_data.nonce);
    let aead = Aes256GcmSiv::new(&seal_key);
    let payload = Payload {
        msg: &backup_data.sealed_secret,
        aad: backup_data.public_key.as_bytes(),
    };
    if let Ok(mut secret_key) = aead.decrypt(nonce_ga, payload) {
        seal_key.zeroize();
        let secret = SecretKey::from_bytes(&secret_key).map_err(|_| ErrorCode::InvalidSignature)?;
        secret_key.zeroize();
        let public = PublicKey::from(&secret);
        let mut kp = Keypair { secret, public };
        let sealed = seal(csprng, &kp);
        kp.secret.zeroize();
        sealed
    } else {
        seal_key.zeroize();
        Err(ErrorCode::MacCompareFail)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::RngCore;
    use rsa::BigUint;
    use rsa::PublicKey;
    use rsa::PublicKeyParts;

    pub fn get_wrapped_key(csprng: &mut OsRng, rsa_pub: RsaPublicKey) -> CloudBackupSeal {
        let mut wrap_key1 = [0u8; 32];
        csprng.fill_bytes(&mut wrap_key1);

        let mut wrap_key2 = [0u8; 32];
        csprng.fill_bytes(&mut wrap_key2);
        let wrapped_key = keywrap::tests::aes256_wrap_key_with_pad(&wrap_key1, &wrap_key2);
        let mut wrapped_cloud_sealing_key = [0u8; 40];
        wrapped_cloud_sealing_key.copy_from_slice(&wrapped_key);
        let enc_data = rsa_pub
            .encrypt(
                csprng,
                PaddingScheme::new_oaep::<sha2::Sha256>(),
                &wrap_key1[..],
            )
            .expect("failed to encrypt");
        let mut encrypted_symmetric_key = [0u8; 256];
        encrypted_symmetric_key.copy_from_slice(&enc_data);
        CloudBackupSeal {
            encrypted_symmetric_key,
            wrapped_cloud_sealing_key,
        }
    }

    #[test]
    fn test_hash() {
        let payload = "{\"kid\":\"wrapping-key\",\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"kyk2V71OnhuVJAZq5occtRdYxX6eGiR3qQ04UKTZQxesiU3UsnbCq7FURSEr5NTKaU1L3die6VzPn829jdVYiht55hiqsEPYrRutNtmc-dI111lPGmkSaN_WcrK9rScbNn1btnBytf6KkST5Qmeri_Ue_BBjdg_G_WPNFKy1Ds_8lDqDMl3JLHaEjtKA-OtCjNsClzqtavgMJcbxdvHqUB1grbYePM6HrlMyIY1wZUvmdZw3_gwKbNkj5_whq6jYHSG68HdH3QGdbbV8_LFdB4IcfdN0ERXbuo1_0ZXoSd-koSjhfafuBbzrKGwiyzbDm9bSaocnECqENXASMt-YLQ\"}";
        let mut hasher = Sha256::new();

        hasher.update(payload);

        let result = hasher.finalize();
        let mine = subtle_encoding::hex::encode(&result);
        assert_eq!(
            mine,
            "f353c435a23153ed43bc832c230a705b6d2b16b04732844d82538e8e691fcca9"
                .as_bytes()
                .to_vec()
        );
    }

    #[test]
    fn test_rsa() {
        let nb64 = "kyk2V71OnhuVJAZq5occtRdYxX6eGiR3qQ04UKTZQxesiU3UsnbCq7FURSEr5NTKaU1L3die6VzPn829jdVYiht55hiqsEPYrRutNtmc-dI111lPGmkSaN_WcrK9rScbNn1btnBytf6KkST5Qmeri_Ue_BBjdg_G_WPNFKy1Ds_8lDqDMl3JLHaEjtKA-OtCjNsClzqtavgMJcbxdvHqUB1grbYePM6HrlMyIY1wZUvmdZw3_gwKbNkj5_whq6jYHSG68HdH3QGdbbV8_LFdB4IcfdN0ERXbuo1_0ZXoSd-koSjhfafuBbzrKGwiyzbDm9bSaocnECqENXASMt-YLQ==";
        let eb64 = "AQAB";

        let nb = base64::decode_config(&nb64, base64::URL_SAFE).unwrap();
        let eb = base64::decode_config(&eb64, base64::URL_SAFE).unwrap();
        let n = BigUint::from_bytes_be(&nb);
        let e = BigUint::from_bytes_be(&eb);
        let pubkey = RsaPublicKey::new(n, e).unwrap();
        let n = pubkey.n().to_bytes_be();
        let e = pubkey.e().to_bytes_be();
        let encoded_n = base64::encode_config(&n, base64::URL_SAFE);
        let encoded_e = base64::encode_config(&e, base64::URL_SAFE);
        assert_eq!(nb64, encoded_n);
        assert_eq!(eb64, encoded_e);
    }

    #[test]
    fn test_report() {
        let rhex = "11110305FF80060000000000000000000000000000000000000000000000000000000000000000000000000000000000050000000000000007000000000000002E2BAC88632809B802B56A638D33824191AE9C3DAADA50A9875AC3EB6F8F202100000000000000000000000000000000000000000000000000000000000000005356F230E3BEC1436E7D7E023663BA453F69E2EDAD820865B098BE457D1B6B32000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007192385C3C0605DE55BB9476CE1D90748190ECB32A8EED7F5207B30CF6A1FE890000000000000000000000000000000000000000000000000000000000000000C88FDB58A572BAC124E1CD4B6BC59C7F00000000000000000000000000000000FB3D7DBC9826DC535BDA22B0F6A38FB5";
        let rb = subtle_encoding::hex::decode_upper(&rhex).unwrap();
        let report = Report::try_copy_from(&rb).unwrap();
        let mut hasher = Sha256::new();

        hasher.update(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

        let rdata = hasher.finalize();
        let x: &[u8] = &rdata;
        let y: &[u8] = &report.reportdata[..32];
        assert_eq!(x, y);
    }

    #[test]
    fn test_rsa2() {
        // test-only private key
        let file_content = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtPy5JuUM9yKTpC1msedjJv9aFt33vATkopleDa+FctypZwUc
IfA9ZZk0DZhLRnMnp3Du6V+/KF8E8UMVXrkD0PLT2FBWY2lJJP+596ZFl9g02Y/x
lB4Irv3F06RkVgtuUR83W+w+XFCAzkWhT6Wsrf1LFvgeBxi86DBxJOnDGl4TRr4/
AgkX6U4LTRCsd58//XUSEMknz7sxabh/xxRcqHMT661nNDCbvgmSv4jsZnm2/M6g
tno5exr2dmtFqN5C4N4APZdf/lIAe3h0CXN/VyU/w66mZ1IBDxhvj7TY47kfztjC
bgh0F4e7aZkBMsy34ca03wtGk7uBAAeGrtM7dwIDAQABAoIBAANyc1ybEX5c7N7O
j2s8J3jL40IEGGe+/PgV1mxlBQ+5xcGiexDnRPeFMkKI4j2TDAuDlcXhaAlKTpRv
NALHfAmfZ4HyIcQ58lgNINRC4j0nxfXp+wDYjLzKNLUmlQpayPO+umONBrEItFfn
HpoxYxvthU2tDD8TpC8nE1QGlTBZsxLU5LhuR0IOblbr3NsPHB15IgVHO8//bJsi
REAdbL6QrQYc2i0W7LTl2Ch+XKXzOjUJJwlv8hH41Ob2hOxzP9rQTOt7QCMpn873
yeL+eCGf4AWEIuIwmN7gkIL8ObOoRkW7zBtc3worJoZTYH9uwmhVE7gPKH3WKCoe
xDpmEAkCgYEA9dTHOCjykJVh6qtMVCV036l8vFY86iUJPO7tz6f8a4UxVXcT3K7i
SPnuR+TmalzEGGrxamYzHmNvOPk0WgOOQ7bZKHjEniQBSYOrrV1+OlVsOKSdyvPe
9ecGLdLSjZUk8fGEEMLDNsmggjG37+xcw3hPXmWhe91AZ4HzqHTD/lkCgYEAvHlI
JR7g4yuNtBhBLNe3qg57Bjq8xU2QTGifiiUbmpcuFKrMjM2nYB5sym0CK124dV2J
G/DTQYy2EIkJw8LtddOoV4rkvLMHwGIipuXHp5Qg6CFzXcs/b4aHqoA3ORAlxAFx
NJLLrurr5qiZEnT0kMMND07wtA0WadFFiBzJ7k8CgYALQrXlcqq5yL31e+dBK34R
CLh4ABNGPnAP5HnsOyuq2S0LVysHvtMKuLgbfva3BIzO+YcZcpkA2Vks6O1m+ia4
H1YPLokDHW8ZqPhiNpgjn+oXJiM8OrOJ3A1CaBfQ+HX6xy9ffSxoBBBgJlrgmJkf
MxGfp1QgUmAy3ZcFrmOT8QKBgQCDSC+6u6GGW4YfFm3/oFsst112X1+yR27l6lKG
1YY+zmOovbgxs+aMi2TYM8o5DtU322lv7vYYSL1hEzOcCqGBW2d9YyAlWMdjeHgO
rSu/TO0HBJXplXOgaaMCXsEYnGjR+Pcz2bTLKJQdXP8S3iik1Vi5exErOZqNJto6
D2OQ/QKBgDqYXNWmWWxYZrIrv/ju3IuxgxgWkyrFwTv3gcx1d/ppA/k317gr8YZI
BTDF9yEwtrEQ1/xuPQMv8x6cnZFYH0ljjbXcTh6VJNv03MSC30pAQCrLSLl3nvHk
0DQm0TNriAxlF7X5zwR8v2b9yJkbwyyY8IbRQfImWFrzHPF4XzLe
-----END RSA PRIVATE KEY-----
"#;
        let der_encoded = file_content
            .lines()
            .filter(|line| !line.starts_with("-"))
            .fold(String::new(), |mut data, line| {
                data.push_str(&line);
                data
            });
        let der_bytes = base64::decode(&der_encoded).expect("failed to decode base64 content");
        let secret = RsaPrivateKey::from_pkcs1_der(&der_bytes).expect("failed to parse key");

        let encrypted_key = "nsohDxPYH9/iyLQvMujkFiTUJr5IiYfNrnYo0hoqoo0rFlUYw995X2REbsogKYcfqWQz7Rld6zEqLfBnD2ess+6pN6O+e1HXxmp6mNXxSAMl2rKGf08Ahl3XbQw0vQ7TNOGGdTlQoli2zbIKE/OsUl5DMqpjSyjDxNDJsKDis65tlnf39k1iMqjYLZMzUZEKTv5Sv16sKhk6TKyvaScNOOd+ctzVay8YFCh0cV9TT4rF/pq64RmX/T8VUTRAgUq/kAt7ZJYw/f2kILMBbBvugc00dq0WxQ+QRC6vDLhxZTxkLDBLHxLxeLlYpVbMMe83uxLcfCoXNOg5og3XeNRMpBNs/asA+eScIlW50xPbpzel9l0AZ9PEu2LAjBjcTAikGdigjKMuDEc=";
        let enckey_payload = base64::decode(&encrypted_key).expect("decode enc key");
        assert_eq!(enckey_payload.len(), 296);
        let seal = CloudBackupSeal::new(enckey_payload).expect("seal");
        let sealing_key = decrypt_wrapped_key(&secret, seal).expect("sealing key");
        let sealing_key_hex = "924a14cdcb1b8b0e630cbe643bfbd83ed070879562fe51ece24de27af2a77e5a";
        let expected_sealing_key = subtle_encoding::hex::decode(&sealing_key_hex).unwrap();
        let sealkey_ref: &[u8] = sealing_key.as_ref();
        assert_eq!(sealkey_ref, &expected_sealing_key);
    }

    #[test]
    fn test_cloud_reseal() {
        let mut csprng = OsRng {};
        let (rsa_pub, sealed_rsa_priv, _report) =
            generate_keypair(&mut csprng, Targetinfo::from(Report::for_self())).expect("gen rsa");
        let cloud_seal = get_wrapped_key(&mut csprng, rsa_pub);
        let cbk = CloudBackupKey {
            sealed_rsa_key: sealed_rsa_priv,
            backup_key: cloud_seal,
        };
        let kp = Keypair::generate(&mut csprng);
        let backup = cloud_backup(&mut csprng, cbk.clone(), &kp).expect("backup");
        reseal_recover_cloud(&mut csprng, cbk, backup).expect("reseal");
    }

    #[test]
    fn test_recover_fail() {
        let mut csprng = OsRng {};
        let (rsa_pub, sealed_rsa_priv, _report) =
            generate_keypair(&mut csprng, Targetinfo::from(Report::for_self())).expect("gen rsa");
        let cloud_seal = get_wrapped_key(&mut csprng, rsa_pub);
        let cbk = CloudBackupKey {
            sealed_rsa_key: sealed_rsa_priv,
            backup_key: cloud_seal,
        };
        let kp = Keypair::generate(&mut csprng);
        let backup = cloud_backup(&mut csprng, cbk.clone(), &kp).expect("backup");
        let mut bm = backup.clone();
        bm.sealed_secret[0] ^= 1;
        assert!(reseal_recover_cloud(&mut csprng, cbk.clone(), bm).is_err());
        let mut cbkm = cbk.clone();
        cbkm.backup_key.encrypted_symmetric_key[0] ^= 1;
        assert!(reseal_recover_cloud(&mut csprng, cbkm, backup).is_err());
    }
}
