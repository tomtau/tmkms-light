use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{
    cipher::generic_array::{
        typenum::{U32, U40},
        GenericArray,
    },
    Aes256,
};
use std::convert::TryInto;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// helper for `aes256_unwrap_key_with_pad`
fn aes256_unwrap_key_and_iv(
    kek: &GenericArray<u8, U32>,
    input: &GenericArray<u8, U40>,
) -> (GenericArray<u8, U32>, [u8; 8]) {
    // https://www.ietf.org/rfc/rfc3394.txt
    // Section 2.2.2 step 1) init
    let n = input.len() / 8 - 1;

    let mut r = vec![0u8; input.len()];
    r[8..].copy_from_slice(&input[8..]);

    let cipher = Aes256::new(kek);
    // SAFETY: lengths are statically checked
    let mut a = u64::from_be_bytes(input[..8].try_into().unwrap());
    // Section 2.2.2 step 2) intermediate values
    for j in (0..6).rev() {
        for i in (1..n + 1).rev() {
            let t = (n * j + i) as u64;
            let mut ciphertext = [0u8; 16];
            let b_i = i * 8;
            ciphertext[..8].copy_from_slice(&(a ^ t).to_be_bytes());
            ciphertext[8..].copy_from_slice(&r[b_i..][0..8]);
            let block = GenericArray::from_mut_slice(&mut ciphertext);
            cipher.decrypt_block(block);
            // SAFETY: static allocation above
            a = u64::from_be_bytes(ciphertext[..8].try_into().unwrap());
            r[b_i..][0..8].copy_from_slice(&ciphertext[8..]);
        }
    }
    let key = GenericArray::clone_from_slice(&r[8..]);
    r.zeroize();
    (key, a.to_be_bytes())
}

/// Possible errors in unwrapping
#[derive(Debug, PartialEq, Eq)]
pub enum UnwrapError {
    /// key or payload incorrect length
    IncorrectLength,
    /// AIV mismmatch
    AuthFailed,
}

/// This unwraps the key as per RFC3394/RFC5649
/// but hardcodes the length assumptions for kek to be 32-bytes
/// and the unwrapped key to be 32-bytes (as that's what's provided
/// in cloud environments).
///
/// NOTE: RFC3394/RFC5649-compliant AES-KW / AES-KWP
/// is implemented in the `aes-keywrap-rs`
/// (`aes-keywrap` doesn't implement it: https://github.com/jedisct1/rust-aes-keywrap/issues/2),
/// but 1) it depends on the `crypto2` crate which may not have received as much scrutiny
/// as the `aes` crate (which is used everywhere else here),
/// 2) we don't need most of its functionality.
/// Hence, this custom partial implementation.
pub fn aes256_unwrap_key_with_pad(
    kek: &[u8],
    wrapped: &[u8],
) -> Result<GenericArray<u8, U32>, UnwrapError> {
    if kek.len() != 32 || wrapped.len() != 40 {
        return Err(UnwrapError::IncorrectLength);
    }
    let kek = GenericArray::from_slice(kek);
    let wrapped = GenericArray::from_slice(wrapped);
    let (mut key, key_iv) = aes256_unwrap_key_and_iv(kek, wrapped);

    // Alternate initial value for aes key wrapping, as defined in RFC 5649 section 3
    // http://www.ietf.org/rfc/rfc5649.txt
    // big-ending length hardcoded to 32 (as here, it's always unwrapping 32-byte sealing key)
    const IV_5649: [u8; 8] = [0xa6, 0x59, 0x59, 0xa6, 0, 0, 0, 32];

    if IV_5649.ct_eq(&key_iv).unwrap_u8() == 0u8 {
        key.zeroize();
        return Err(UnwrapError::AuthFailed);
    }
    // no need to remove padding, as the length is hardcoded to 32
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

    #[derive(Clone, Copy, Debug)]
    struct KeyWrap(pub [u8; 32]);

    impl Arbitrary for KeyWrap {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut raw = [0u8; 32];
            for i in 0..raw.len() {
                let b = u8::arbitrary(g);
                raw[i] = b;
            }
            Self(raw)
        }
    }

    #[test]
    fn test_wrong_len() {
        assert_eq!(
            aes256_unwrap_key_with_pad(&[0u8; 10], &[0u8; 40]),
            Err(UnwrapError::IncorrectLength)
        );
        assert_eq!(
            aes256_unwrap_key_with_pad(&[0u8; 32], &[0u8; 10]),
            Err(UnwrapError::IncorrectLength)
        );
    }

    #[test]
    fn test_wrong_auth() {
        assert_eq!(
            aes256_unwrap_key_with_pad(&[0u8; 32], &[0u8; 40]),
            Err(UnwrapError::AuthFailed)
        );
    }

    #[test]
    fn test_padded_256bit_kek_and_256bit_key() {
        let kek = subtle_encoding::hex::decode_upper(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        )
        .unwrap();
        let cipher = subtle_encoding::hex::decode_upper(
            "4A8029243027353B0694CF1BD8FC745BB0CE8A739B19B1960B12426D4C39CFEDA926D103AB34E9F6",
        )
        .unwrap();
        let plain = subtle_encoding::hex::decode_upper(
            "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        )
        .unwrap();
        // assert_eq!(cipher, aes_wrap_key(&kek, &plain).unwrap());
        assert_eq!(
            plain,
            aes256_unwrap_key_with_pad(&kek, &cipher).unwrap().to_vec()
        );
    }

    // #[quickcheck]
    // fn wrap_unwrap(kek: KeyWrap, key: KeyWrap) -> bool {
    //     let wrapped =
    //         aes_keywrap_rs::Aes256Kw::aes_wrap_key_with_pad(&kek.0, &key.0).expect("wrap key");
    //     let unwrap = aes256_unwrap_key_with_pad(&kek.0, &wrapped).expect("unwrap");
    //     let uref: &[u8] = unwrap.as_ref();
    //     uref == &key.0
    // }
}
