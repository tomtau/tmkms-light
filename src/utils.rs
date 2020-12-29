use std::str::FromStr;

/// Options for displaying public key
#[derive(Debug)]
pub enum PubkeyDisplay {
    Base64,
    Bech32,
}

impl FromStr for PubkeyDisplay {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "base64" => Ok(PubkeyDisplay::Base64),
            "bech32" => Ok(PubkeyDisplay::Bech32),
            _ => Err("unknown display type".to_owned()),
        }
    }
}

/// prints public key in the desired format
pub fn print_pubkey(
    bech32_prefix: Option<String>,
    ptype: Option<PubkeyDisplay>,
    public: ed25519_dalek::PublicKey,
) {
    match ptype {
        Some(PubkeyDisplay::Bech32) => {
            let prefix = bech32_prefix.unwrap_or("cosmosvalconspub".to_owned());
            let mut data = vec![0x16, 0x24, 0xDE, 0x64, 0x20];
            data.extend_from_slice(public.as_bytes());
            println!(
                "public key: {}",
                subtle_encoding::bech32::encode(prefix, data)
            );
        }
        _ => {
            println!(
                "public key: {}",
                String::from_utf8(subtle_encoding::base64::encode(public)).unwrap()
            );
            let id = tendermint::node::Id::from(public);
            println!("address: {}", id);
        }
    }
}
