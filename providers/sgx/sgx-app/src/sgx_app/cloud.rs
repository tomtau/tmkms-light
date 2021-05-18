use crate::sgx_app::keypair_seal::{seal_recover_cloud_backup, CloudWrapKey};
use aes_keywrap::Aes256KeyWrap;
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PrivateKeyEncoding, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use sgx_isa::ErrorCode;
use sgx_isa::{Report, Targetinfo};
use sha2::{Digest, Sha256};
use tmkms_light_sgx_runner::{CloudBackupKeyData, SealedKeyData};

pub fn generate_keypair(
    csprng: &mut OsRng,
    targetinfo: Targetinfo,
) -> Result<(RSAPublicKey, SealedKeyData, Report), ErrorCode> {
    let bits = 2048;
    // default exponent 65537
    let priv_key = RSAPrivateKey::new(csprng, bits).expect("failed to generate a key");
    let pub_key = RSAPublicKey::from(&priv_key);
    // TODO: check if BE is expected
    let n = pub_key.n().to_bytes_be();
    let e = pub_key.e().to_bytes_be();
    let encoded_n = String::from_utf8(subtle_encoding::base64::encode(&n)).expect("encoded n");
    let encoded_e = String::from_utf8(subtle_encoding::base64::encode(&e)).expect("encoded e");
    let claim_payload = format!(
        "{{\"kid\":\"wrapping-key\",\"kty\":\"RSA\",\"e\":\"{}\",\"n\":\"{}\"}}",
        encoded_e, encoded_n
    );
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
    use rsa::PublicKey;
    use tmkms_light::utils::read_u16_payload;

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
