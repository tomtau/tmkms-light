/// RFC3394/RFC5649 key unwrapping of 32-byte keys
mod keywrap;

use crate::sgx_app::keypair_seal::{seal_recover_cloud_backup, CloudWrapKey};
use aes::cipher::generic_array::typenum::U32;
use aes::cipher::generic_array::GenericArray;
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PrivateKeyEncoding, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use sgx_isa::ErrorCode;
use sgx_isa::{Report, Targetinfo};
use sha2::{Digest, Sha256};
use tmkms_light_sgx_runner::{get_claim, CloudBackupKeyData, SealedKeyData};
use zeroize::Zeroize;

/// Possible errors in cloud backup or recovery
#[derive(Debug)]
pub enum CloudError {
    /// RSA generation or PKCS1 issues
    SecretGenerationError,
    /// errors from local CPU sealing
    SealingError(ErrorCode),
    /// RFC3394/RFC5649 AES-KWP unwrap failed
    UnwrapError(keywrap::UnwrapError),
    /// RSA-OAEP+SHA-256 decryption failed
    DecryptionError,
}

/// Generates an RSA keypair (2048bit with e=65537),
/// seals the private key to a local CPU,
/// and gets a report for sha256 of the public key in JWE.
pub fn generate_keypair(
    csprng: &mut OsRng,
    targetinfo: Targetinfo,
) -> Result<(RSAPublicKey, SealedKeyData, Report), CloudError> {
    let bits = 2048;
    // default exponent 65537
    let mut priv_key =
        RSAPrivateKey::new(csprng, bits).map_err(|_| CloudError::SecretGenerationError)?;
    let pub_key = RSAPublicKey::from(&priv_key);

    let claim_payload = get_claim(&pub_key);
    let mut hasher = Sha256::new();
    hasher.update(claim_payload);
    let result = hasher.finalize();
    let result_len = result.as_slice().len();
    let mut report_data = [0u8; 64];
    for i in 0..result_len {
        report_data[i] = result[i];
    }
    let report = Report::for_target(&targetinfo, &report_data);
    let pkcs1 = priv_key.to_pkcs1();
    priv_key.zeroize();
    if let Ok(mut secret) = pkcs1 {
        match crate::sgx_app::keypair_seal::seal_secret(csprng, &secret, result.into()) {
            Ok(sealed_secret) => {
                secret.zeroize();
                Ok((pub_key, sealed_secret, report))
            }
            Err(e) => {
                secret.zeroize();
                Err(CloudError::SealingError(e))
            }
        }
    } else {
        Err(CloudError::SecretGenerationError)
    }
}

/// payload from cloud environments for backups
pub struct CloudSeal {
    /// kek encrypted using RSA-OAEP+SHA-256
    encrypted_symmetric_key: [u8; 256],
    /// 32-byte key that can be unwrapped with the decrypted kek
    /// using RFC3394/RFC5649 AES-KWP
    wrapped_cloud_sealing_key: [u8; 40],
}

impl CloudSeal {
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

/// helper to decrypt the backup key
fn decrypt_wrapped_key(
    priv_key: &RSAPrivateKey,
    backup_data_seal: CloudSeal,
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

/// tries to recover the secret from the cloud backup data
/// and (re-)seal it for the current CPU
pub fn reseal_recover_cloud(
    csprng: &mut OsRng,
    sealed_rsa_key: SealedKeyData,
    backup_data_seal: CloudSeal,
    cloud_backup: CloudBackupKeyData,
) -> Result<SealedKeyData, CloudError> {
    let mut priv_key_raw = crate::sgx_app::keypair_seal::unseal_secret(&sealed_rsa_key)
        .map_err(CloudError::SealingError)?;
    let mpriv_key = RSAPrivateKey::from_pkcs1(&priv_key_raw);
    priv_key_raw.zeroize();
    let mut priv_key = mpriv_key.map_err(|_| CloudError::SecretGenerationError)?;
    let mbackup_key = decrypt_wrapped_key(&priv_key, backup_data_seal);
    priv_key.zeroize();
    let mut backup_key = mbackup_key?;
    // FIXME: directly pass backup_key to seal_recover_cloud_backup
    let cloud_backup_key = CloudWrapKey::new(backup_key.to_vec()).unwrap();
    backup_key.zeroize();
    seal_recover_cloud_backup(csprng, cloud_backup_key, cloud_backup)
        .map_err(CloudError::SealingError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sgx_app::keypair_seal::cloud_backup;
    use ed25519_dalek::Keypair;
    use rand::RngCore;
    use rsa::BigUint;
    use rsa::PublicKey;

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
        let pubkey = RSAPublicKey::new(n, e).unwrap();
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
        let secret = RSAPrivateKey::from_pkcs1(&der_bytes).expect("failed to parse key");

        let encrypted_key = "nsohDxPYH9/iyLQvMujkFiTUJr5IiYfNrnYo0hoqoo0rFlUYw995X2REbsogKYcfqWQz7Rld6zEqLfBnD2ess+6pN6O+e1HXxmp6mNXxSAMl2rKGf08Ahl3XbQw0vQ7TNOGGdTlQoli2zbIKE/OsUl5DMqpjSyjDxNDJsKDis65tlnf39k1iMqjYLZMzUZEKTv5Sv16sKhk6TKyvaScNOOd+ctzVay8YFCh0cV9TT4rF/pq64RmX/T8VUTRAgUq/kAt7ZJYw/f2kILMBbBvugc00dq0WxQ+QRC6vDLhxZTxkLDBLHxLxeLlYpVbMMe83uxLcfCoXNOg5og3XeNRMpBNs/asA+eScIlW50xPbpzel9l0AZ9PEu2LAjBjcTAikGdigjKMuDEc=";
        let enckey_payload = base64::decode(&encrypted_key).expect("decode enc key");
        assert_eq!(enckey_payload.len(), 296);
        let seal = CloudSeal::new(enckey_payload).expect("seal");
        let sealing_key = decrypt_wrapped_key(&secret, seal).expect("sealing key");
        let sealing_key_hex = "924a14cdcb1b8b0e630cbe643bfbd83ed070879562fe51ece24de27af2a77e5a";
        let expected_sealing_key = subtle_encoding::hex::decode(&sealing_key_hex).unwrap();
        let sealkey_ref: &[u8] = sealing_key.as_ref();
        assert_eq!(sealkey_ref, &expected_sealing_key);
    }

    // can be run with `cargo test --target x86_64-fortanix-unknown-sgx`
    #[test]
    fn test_cloud_seal() {
        let mut csprng = OsRng {};
        let (rsa_pub, sealed_rsa_priv, _report) =
            generate_keypair(&mut csprng, Targetinfo::from(Report::for_self())).expect("gen rsa");
        let mut wrap_key1 = [0u8; 32];
        csprng.fill_bytes(&mut wrap_key1);
        //let wrap_keyy = Aes256KeyWrap::new(&wrap_key1);

        let mut wrap_key2 = [0u8; 32];
        csprng.fill_bytes(&mut wrap_key2);
        let wrapped_key = aes_keywrap_rs::Aes256Kw::aes_wrap_key_with_pad(&wrap_key1, &wrap_key2)
            .expect("wrap key"); //wrap_keyy.encapsulate(&wrap_key2).expect("wrap");
        let mut wrapped_cloud_sealing_key = [0u8; 40];
        wrapped_cloud_sealing_key.copy_from_slice(&wrapped_key);
        let enc_data = rsa_pub
            .encrypt(
                &mut csprng,
                PaddingScheme::new_oaep::<sha2::Sha256>(),
                &wrap_key1[..],
            )
            .expect("failed to encrypt");
        let mut encrypted_symmetric_key = [0u8; 256];
        encrypted_symmetric_key.copy_from_slice(&enc_data);
        let cloud_seal = CloudSeal {
            encrypted_symmetric_key,
            wrapped_cloud_sealing_key,
        };
        let kp = Keypair::generate(&mut csprng);
        let cloud_sealing = CloudWrapKey::new(wrap_key2.to_vec()).unwrap();

        let backup = cloud_backup(&mut csprng, cloud_sealing, &kp).expect("backup");
        reseal_recover_cloud(&mut csprng, sealed_rsa_priv, cloud_seal, backup).expect("reseal");
    }
}
