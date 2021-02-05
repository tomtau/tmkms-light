use std::{fs, path::PathBuf};

use crate::{SgxInitRequest, CLOUD_KEY_LEN};
use tendermint::net;
use tmkms_light::{
    config::validator::ValidatorConfig,
    utils::{print_pubkey, PubkeyDisplay},
};
use tracing::{debug, error};
use zeroize::Zeroizing;

use crate::{config, runner::TmkmsSgxSigner};

pub fn init(
    config_path: Option<PathBuf>,
    pubkey_display: Option<PubkeyDisplay>,
    bech32_prefix: Option<String>,
    external_backup_key_path: Option<PathBuf>,
    key_backup_data_path: Option<PathBuf>,
) {
    let cp = config_path.unwrap_or("tmkms.toml".into());
    let config = config::SgxSignOpt::default();
    let t = toml::to_string_pretty(&config).expect("config in toml");
    fs::write(cp, t).expect("written config");
    fs::create_dir_all(
        config
            .sealed_consensus_key_path
            .parent()
            .expect("not root dir"),
    )
    .expect("create dirs for key storage");
    fs::create_dir_all(config.state_file_path.parent().expect("not root dir"))
        .expect("create dirs for key storage");
    let request = SgxInitRequest::KeyGen;
    let request_bytes = serde_json::to_vec(&request).expect("serde");
    let backup_key = if let Some(bkp) = external_backup_key_path {
        let key_bytes = Zeroizing::new(fs::read(bkp).expect("key"));
        if key_bytes.len() != CLOUD_KEY_LEN {
            error!("incorrect backup key length");
            std::process::exit(1);
        }
        Some(Zeroizing::new(subtle_encoding::hex::encode(&*key_bytes)))
    } else {
        None
    };
    debug!("launching enclave");
    let (state_syncer, _, state_stream) = TmkmsSgxSigner::get_state_syncer(&config.state_file_path);
    let mut enclave_args: Vec<&[u8]> = vec![request_bytes.as_ref()];
    if let Some(ref bkp) = backup_key {
        enclave_args.push(&*bkp);
    }
    let runner = TmkmsSgxSigner::launch_enclave_app(
        &config.enclave_path,
        None,
        state_syncer,
        state_stream,
        &enclave_args,
    )
    .expect("runner");
    debug!("waiting for keygen");
    let sealed_key = runner.keygen().expect("gen key");
    config::write_sealed_file(config.sealed_consensus_key_path, &sealed_key.0).expect("write key");
    let public_key = ed25519_dalek::PublicKey::from_bytes(&sealed_key.0.seal_key_request.keyid)
        .expect("valid public key");
    print_pubkey(bech32_prefix, pubkey_display, public_key);
    let base_backup_path = key_backup_data_path.unwrap_or("".into());
    if let Some(bkp) = sealed_key.1 {
        config::write_backup_file(base_backup_path.join("consensus-key.backup"), &bkp)
            .expect("write backup");
    }
    if let Some(id_path) = config.sealed_id_key_path {
        let (state_syncer, _, state_stream) =
            TmkmsSgxSigner::get_state_syncer(&config.state_file_path);

        let runner = TmkmsSgxSigner::launch_enclave_app(
            &config.enclave_path,
            None,
            state_syncer,
            state_stream,
            &enclave_args,
        )
        .expect("runner");
        let sealed_key = runner.keygen().expect("gen key");
        config::write_sealed_file(id_path, &sealed_key.0).expect("write key");
        if let Some(bkp) = sealed_key.1 {
            config::write_backup_file(base_backup_path.join("id-key.backup"), &bkp)
                .expect("write backup");
        }
    }
}

pub fn start(config_path: Option<PathBuf>) {
    let cp = config_path.unwrap_or("tmkms.toml".into());
    if !cp.exists() {
        error!("missing tmkms.toml file");
        std::process::exit(1);
    } else {
        let toml_string = fs::read_to_string(cp).expect("toml config file read");
        let config: config::SgxSignOpt = toml::from_str(&toml_string).expect("configuration");
        let tm_conn = match &config.address {
            net::Address::Unix { path } => {
                debug!(
                    "{}: Connecting to socket at {}...",
                    &config.chain_id, &config.address
                );

                Some(path.clone())
            }
            _ => None,
        };
        let remote = if let (None, Some(path)) = (&tm_conn, config.sealed_id_key_path) {
            Some((config.address, path))
        } else {
            None
        };
        let (state_syncer, state, state_stream) =
            TmkmsSgxSigner::get_state_syncer(&config.state_file_path);
        let start_request_bytes = TmkmsSgxSigner::get_start_request_bytes(
            config.sealed_consensus_key_path,
            ValidatorConfig {
                chain_id: config.chain_id,
                max_height: config.max_height,
            },
            state,
            remote,
        )
        .expect("start");
        let runner = TmkmsSgxSigner::launch_enclave_app(
            &config.enclave_path,
            tm_conn,
            state_syncer,
            state_stream,
            &[&start_request_bytes],
        )
        .expect("runner");
        runner.start().expect("request loop");
    }
}

pub fn recover(
    config_path: Option<PathBuf>,
    pubkey_display: Option<PubkeyDisplay>,
    bech32_prefix: Option<String>,
    external_backup_key_path: PathBuf,
    key_backup_data_path: PathBuf,
    show_pubkey: bool,
) {
    let cp = config_path.unwrap_or("tmkms.toml".into());
    if !cp.exists() {
        eprintln!("missing tmkms.toml file");
        std::process::exit(1);
    } else {
        let toml_string = fs::read_to_string(cp).expect("toml config file read");
        let config: config::SgxSignOpt = toml::from_str(&toml_string).expect("configuration");
        let backup_key = {
            let key_bytes = Zeroizing::new(fs::read(external_backup_key_path).expect("key"));
            if key_bytes.len() != CLOUD_KEY_LEN {
                eprintln!("incorrect backup key length");
                std::process::exit(1);
            }
            Zeroizing::new(subtle_encoding::hex::encode(&*key_bytes))
        };
        let key_data =
            serde_json::from_str(&fs::read_to_string(key_backup_data_path).expect("backup data"))
                .expect("backup data parse");
        let request = SgxInitRequest::CloudRecover { key_data };
        let request_bytes = serde_json::to_vec(&request).expect("serde");
        debug!("launching enclave");
        let (state_syncer, _, state_stream) =
            TmkmsSgxSigner::get_state_syncer(&config.state_file_path);
        let runner = TmkmsSgxSigner::launch_enclave_app(
            &config.enclave_path,
            None,
            state_syncer,
            state_stream,
            &[request_bytes.as_ref(), &*backup_key],
        )
        .expect("runner");
        debug!("waiting for recover");
        let sealed_key = runner.keygen().expect("gen key");
        config::write_sealed_file(config.sealed_consensus_key_path, &sealed_key.0)
            .expect("write key");
        let public_key = ed25519_dalek::PublicKey::from_bytes(&sealed_key.0.seal_key_request.keyid)
            .expect("valid public key");
        if show_pubkey {
            println!("recovered key");
            print_pubkey(bech32_prefix, pubkey_display, public_key);
        }
    }
}
