use std::{fs, path::PathBuf};

use crate::{config, runner::TmkmsSgxSigner};
use crate::{shared::get_claim, shared::SgxInitResponse, SgxInitRequest, CLOUD_KEY_LEN};
use tendermint::net;
use tmkms_light::{
    config::validator::ValidatorConfig,
    utils::{print_pubkey, PubkeyDisplay},
};
use tracing::debug;
use zeroize::Zeroizing;

/// generate a key wrap for cloud backups
pub fn keywrap(
    enclave_path: PathBuf,
    sealed_output_path: PathBuf,
    dcap: bool,
) -> Result<(), String> {
    let targetinfo = if dcap {
        if dcap_ql::is_loaded() {
            let ti = dcap_ql::target_info().map_err(|e| format!("dcap target info: {:?}", e))?;
            Some(ti)
        } else {
            return Err("DCAP QL not loaded".to_owned());
        }
    } else {
        None
    };
    let request = SgxInitRequest::GenWrapKey { targetinfo };
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|e| format!("failed to convert request to json: {:?}", e))?;
    let (state_syncer, _, state_stream) = TmkmsSgxSigner::get_state_syncer("/tmp/state.json")
        .map_err(|e| format!("state persistence error: {:?}", e))?;
    let enclave_args: Vec<&[u8]> = vec![request_bytes.as_ref()];
    let runner = TmkmsSgxSigner::launch_enclave_app(
        &enclave_path,
        None,
        state_syncer,
        state_stream,
        &enclave_args,
    )
    .map_err(|e| format!("failed to launch the enclave app: {:?}", e))?;
    debug!("waiting for keygen");
    let sealed_key = runner
        .get_init_response()
        .map_err(|e| format!("failed to generate a wrapping key: {:?}", e))?;
    match sealed_key {
        SgxInitResponse::WrapKey {
            wrap_key_sealed,
            wrap_pub_key,
            pub_key_report,
        } => {
            let quote = if dcap {
                let q =
                    dcap_ql::quote(&pub_key_report).map_err(|e| format!("dcap quote: {:?}", e))?;
                Some(q)
            } else {
                None
            };

            config::write_sealed_file(sealed_output_path, &wrap_key_sealed)
                .map_err(|e| format!("failed to write wrapping key: {:?}", e))?;
            let claim_payload = get_claim(&wrap_pub_key);
            let encoded_claim = base64::encode_config(&claim_payload, base64::URL_SAFE);
            if let Some(quote) = quote {
                let encoded_quote = base64::encode_config(&quote, base64::URL_SAFE);
                println!("\"report\": \"{}\"", encoded_quote)
            }
            println!(
                "\"runtimeData\": {{ \"data\": \"{}\", \"dataType\": \"Binary\" }}",
                encoded_claim
            );
            Ok(())
        }
        _ => Err("unexpected enclave response".to_owned()),
    }
}

/// write tmkms.toml + generate keys (sealed for machine CPU
/// + backup if an external key is provided)
pub fn init(
    config_path: Option<PathBuf>,
    pubkey_display: Option<PubkeyDisplay>,
    bech32_prefix: Option<String>,
    external_backup_key_path: Option<PathBuf>,
    key_backup_data_path: Option<PathBuf>,
) -> Result<(), String> {
    let cp = config_path.unwrap_or_else(|| "tmkms.toml".into());
    let config = config::SgxSignOpt::default();
    let t =
        toml::to_string_pretty(&config).map_err(|e| format!("config to toml failed: {:?}", e))?;
    fs::write(cp, t).map_err(|e| format!("failed to write a config: {:?}", e))?;
    fs::create_dir_all(
        config
            .sealed_consensus_key_path
            .parent()
            .ok_or_else(|| "cannot create a dir in a root directory".to_owned())?,
    )
    .map_err(|e| format!("failed to create dirs for key storage: {:?}", e))?;
    fs::create_dir_all(
        config
            .state_file_path
            .parent()
            .ok_or_else(|| "cannot create a dir in a root directory".to_owned())?,
    )
    .map_err(|e| format!("failed to create dirs for state storage: {:?}", e))?;
    let request = SgxInitRequest::KeyGen;
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|e| format!("failed to convert request to json: {:?}", e))?;
    let backup_key = if let Some(bkp) = external_backup_key_path {
        let key_bytes = Zeroizing::new(
            fs::read(bkp).map_err(|e| format!("failed to read backup key: {:?}", e))?,
        );
        if key_bytes.len() != CLOUD_KEY_LEN {
            return Err("incorrect backup key length".to_owned());
        }
        Some(Zeroizing::new(subtle_encoding::hex::encode(&*key_bytes)))
    } else {
        None
    };
    debug!("launching enclave");
    let (state_syncer, _, state_stream) = TmkmsSgxSigner::get_state_syncer(&config.state_file_path)
        .map_err(|e| format!("state persistence error: {:?}", e))?;
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
    .map_err(|e| format!("failed to launch the enclave app: {:?}", e))?;
    debug!("waiting for keygen");
    let sealed_key = runner
        .get_init_response()
        .map_err(|e| format!("failed to generate consensus key: {:?}", e))?;
    let (sealed_key_data, cloud_backup_key_data) = sealed_key
        .get_gen_response()
        .ok_or("failed to generate consensus key".to_owned())?;
    config::write_sealed_file(config.sealed_consensus_key_path, &sealed_key_data)
        .map_err(|e| format!("failed to write consensus key: {:?}", e))?;
    let public_key = ed25519_dalek::PublicKey::from_bytes(&sealed_key_data.seal_key_request.keyid)
        .map_err(|e| format!("invalid keyid: {:?}", e))?;
    print_pubkey(bech32_prefix, pubkey_display, public_key);
    let base_backup_path = key_backup_data_path.unwrap_or_else(|| "".into());
    if let Some(bkp) = cloud_backup_key_data {
        config::write_backup_file(base_backup_path.join("consensus-key.backup"), &bkp)
            .map_err(|e| format!("failed to write consensus key backup: {:?}", e))?;
    }
    if let Some(id_path) = config.sealed_id_key_path {
        let (state_syncer, _, state_stream) =
            TmkmsSgxSigner::get_state_syncer(&config.state_file_path)
                .map_err(|e| format!("state persistence error: {:?}", e))?;

        let runner = TmkmsSgxSigner::launch_enclave_app(
            &config.enclave_path,
            None,
            state_syncer,
            state_stream,
            &enclave_args,
        )
        .map_err(|e| format!("failed to launch the enclave app: {:?}", e))?;
        let sealed_key = runner
            .get_init_response()
            .map_err(|e| format!("failed to generate id key: {:?}", e))?;
        let (sealed_key_data, cloud_backup_key_data) = sealed_key
            .get_gen_response()
            .ok_or("failed to generate id key".to_owned())?;

        config::write_sealed_file(id_path, &sealed_key_data)
            .map_err(|e| format!("failed to write id key: {:?}", e))?;
        if let Some(bkp) = cloud_backup_key_data {
            config::write_backup_file(base_backup_path.join("id-key.backup"), &bkp)
                .map_err(|e| format!("failed to write id key backup: {:?}", e))?;
        }
    }
    Ok(())
}

/// startup the enclave with Unix socket pairs for retrieving state updates and persisting them on the host
pub fn start(config_path: Option<PathBuf>) -> Result<(), String> {
    let cp = config_path.unwrap_or_else(|| "tmkms.toml".into());
    if !cp.exists() {
        Err("missing tmkms.toml file".to_owned())
    } else {
        let toml_string = fs::read_to_string(cp)
            .map_err(|e| format!("toml config file failed to read: {:?}", e))?;
        let config: config::SgxSignOpt = toml::from_str(&toml_string)
            .map_err(|e| format!("toml config file failed to parse: {:?}", e))?;
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
            TmkmsSgxSigner::get_state_syncer(&config.state_file_path)
                .map_err(|e| format!("state persistence error: {:?}", e))?;
        let start_request_bytes = TmkmsSgxSigner::get_start_request_bytes(
            config.sealed_consensus_key_path,
            ValidatorConfig {
                chain_id: config.chain_id,
                max_height: config.max_height,
            },
            state,
            remote,
        )
        .map_err(|e| format!("failed to get enclave request: {:?}", e))?;
        let runner = TmkmsSgxSigner::launch_enclave_app(
            &config.enclave_path,
            tm_conn,
            state_syncer,
            state_stream,
            &[&start_request_bytes],
        )
        .map_err(|e| format!("failed to launch the enclave app: {:?}", e))?;
        runner
            .start()
            .map_err(|e| format!("enclave running failed: {:?}", e))?;
        Ok(())
    }
}

/// recover the previously backed up id/consensus key (e.g. in cloud settings where
/// physical CPU-affinity isn't guaranteed)
pub fn recover(
    config_path: Option<PathBuf>,
    pubkey_display: Option<PubkeyDisplay>,
    bech32_prefix: Option<String>,
    external_backup_key_path: PathBuf,
    key_backup_data_path: PathBuf,
    recover_consensus_key: bool,
) -> Result<(), String> {
    let cp = config_path.unwrap_or_else(|| "tmkms.toml".into());
    if !cp.exists() {
        Err("missing tmkms.toml file".to_owned())
    } else {
        let toml_string = fs::read_to_string(cp)
            .map_err(|e| format!("toml config file failed to read: {:?}", e))?;
        let config: config::SgxSignOpt = toml::from_str(&toml_string)
            .map_err(|e| format!("toml config file failed to parse: {:?}", e))?;
        if !recover_consensus_key && config.sealed_id_key_path.is_none() {
            return Err("empty id key path in config".to_owned());
        }
        let backup_key = {
            let key_bytes = Zeroizing::new(
                fs::read(external_backup_key_path)
                    .map_err(|e| format!("failed to read backup key: {:?}", e))?,
            );
            if key_bytes.len() != CLOUD_KEY_LEN {
                return Err("incorrect backup key length".to_owned());
            }
            Zeroizing::new(subtle_encoding::hex::encode(&*key_bytes))
        };
        let key_data = serde_json::from_str(
            &fs::read_to_string(key_backup_data_path.join("consensus-key.backup"))
                .map_err(|e| format!("failed to read backup data: {:?}", e))?,
        )
        .map_err(|e| format!("failed to parse backup data: {:?}", e))?;
        let request = SgxInitRequest::CloudRecover { key_data };
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| format!("failed to convert request to json: {:?}", e))?;
        debug!("launching enclave");
        let (state_syncer, _, state_stream) =
            TmkmsSgxSigner::get_state_syncer(&config.state_file_path)
                .map_err(|e| format!("state persistence error: {:?}", e))?;
        let runner = TmkmsSgxSigner::launch_enclave_app(
            &config.enclave_path,
            None,
            state_syncer,
            state_stream,
            &[request_bytes.as_ref(), &*backup_key],
        )
        .map_err(|e| format!("failed to launch the enclave app: {:?}", e))?;
        debug!("waiting for recover");
        let sealed_key = runner
            .get_init_response()
            .map_err(|e| format!("failed to recover key: {:?}", e))?;
        let (sealed_key_data, _) = sealed_key
            .get_gen_response()
            .ok_or("failed to recover key".to_owned())?;

        if recover_consensus_key {
            config::write_sealed_file(config.sealed_consensus_key_path, &sealed_key_data)
                .map_err(|e| format!("failed to write consensus key: {:?}", e))?;
            let public_key =
                ed25519_dalek::PublicKey::from_bytes(&sealed_key_data.seal_key_request.keyid)
                    .map_err(|e| format!("ivalid keyid: {:?}", e))?;
            println!("recovered key");
            print_pubkey(bech32_prefix, pubkey_display, public_key);
        } else {
            // checked above after config parsing
            let id_path = config.sealed_id_key_path.unwrap();
            config::write_sealed_file(id_path, &sealed_key_data)
                .map_err(|e| format!("failed to write id key: {:?}", e))?;
        }
        Ok(())
    }
}
