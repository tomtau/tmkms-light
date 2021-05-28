use crate::sgx_app::keypair_seal::{seal_recover_cloud_backup, CloudWrapKey};
use aes_keywrap::Aes256KeyWrap;
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PrivateKeyEncoding, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use sgx_isa::ErrorCode;
use sgx_isa::{Report, Targetinfo};
use sha2::{Digest, Sha256};
use tmkms_light_sgx_runner::{get_claim, CloudBackupKeyData, SealedKeyData};

pub fn generate_keypair(
    csprng: &mut OsRng,
    targetinfo: Targetinfo,
) -> Result<(RSAPublicKey, SealedKeyData, Report), ErrorCode> {
    let bits = 2048;
    // default exponent 65537
    let priv_key = RSAPrivateKey::new(csprng, bits).expect("failed to generate a key");
    let pub_key = RSAPublicKey::from(&priv_key);

    let claim_payload = get_claim(&pub_key);
    // create a Sha256 object
    let mut hasher = Sha256::new();

    // write input message
    hasher.update(claim_payload);

    // read hash digest and consume hasher
    let result = hasher.finalize();
    let result_len = result.as_slice().len();
    let mut report_data = [0u8; 64];
    for i in 0..result_len {
        report_data[i] = result[i];
    }
    let report = Report::for_target(&targetinfo, &report_data);
    let secret = priv_key.to_pkcs1().expect("pkcs1");
    let sealed_secret = crate::sgx_app::keypair_seal::seal_secret(csprng, &secret, result.into())?;
    Ok((pub_key, sealed_secret, report))
}

pub struct CloudSeal {
    encrypted_symmetric_key: [u8; 256],
    wrapped_cloud_sealing_key: [u8; 40],
}

pub fn reseal_recover_cloud(
    csprng: &mut OsRng,
    sealed_rsa_key: SealedKeyData,
    backup_data_seal: CloudSeal,
    cloud_backup: CloudBackupKeyData,
) -> Result<SealedKeyData, ErrorCode> {
    let priv_key_raw = crate::sgx_app::keypair_seal::unseal_secret(&sealed_rsa_key)?;
    let priv_key = RSAPrivateKey::from_pkcs1(&priv_key_raw).expect("priv key");
    let wrapping_key = priv_key
        .decrypt(
            PaddingScheme::new_pkcs1v15_encrypt(),
            &backup_data_seal.encrypted_symmetric_key,
        )
        .expect("failed to decrypt");
    let mut wrap_key = [0u8; 32];
    wrap_key.copy_from_slice(&wrapping_key);
    let wrap_keyy = Aes256KeyWrap::new(&wrap_key);
    let sealing_key = wrap_keyy
        .decapsulate(&backup_data_seal.wrapped_cloud_sealing_key, 32)
        .expect("unwrapping");
    let cloud_sealing = CloudWrapKey::new(sealing_key[..16].to_vec()).unwrap();
    seal_recover_cloud_backup(csprng, cloud_sealing, cloud_backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sgx_app::keypair_seal::cloud_backup;
    use ed25519_dalek::Keypair;
    use rand::RngCore;
    use rsa::BigUint;
    use rsa::PublicKey;
    use tmkms_light::utils::read_u16_payload;

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

    // can be run with `cargo test --target x86_64-fortanix-unknown-sgx`
    #[test]
    fn test_cloud_seal() {
        let mut csprng = OsRng {};
        let (rsa_pub, sealed_rsa_priv, _report) =
            generate_keypair(&mut csprng, Targetinfo::from(Report::for_self())).expect("gen rsa");
        let mut wrap_key1 = [0u8; 32];
        csprng.fill_bytes(&mut wrap_key1);
        let wrap_keyy = Aes256KeyWrap::new(&wrap_key1);

        let mut wrap_key2 = [0u8; 32];
        csprng.fill_bytes(&mut wrap_key2);
        let wrapped_key = wrap_keyy.encapsulate(&wrap_key2).expect("wrap");
        let mut wrapped_cloud_sealing_key = [0u8; 40];
        wrapped_cloud_sealing_key.copy_from_slice(&wrapped_key);
        let enc_data = rsa_pub
            .encrypt(
                &mut csprng,
                PaddingScheme::new_pkcs1v15_encrypt(),
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
        let cloud_sealing = CloudWrapKey::new(wrap_key2[..16].to_vec()).unwrap();

        let backup = cloud_backup(&mut csprng, cloud_sealing, &kp).expect("backup");
        reseal_recover_cloud(&mut csprng, sealed_rsa_priv, cloud_seal, backup).expect("reseal");
    }
}
