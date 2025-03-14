use serde::Deserialize;
use bitcoin::Network;

pub const DEFAULT_WOTS_SECRET_FILE: &str = "data/private/wots_sec.json";
pub const DEFAULT_WOTS_PUBKEY_FILE: &str = "data/public/wots_pub.json";

pub const DEFAULT_VKEY_FILE: &str = "data/public/groth16/vkey.bin";
pub const DEFAULT_PROOF_FILE: &str = "data/public/groth16/proof.bin";
pub const DEFAULT_PUBIN_FILE: &str = "data/public/groth16/pubin.bin";

pub const DEFAULT_PARTIAL_SCRIPTS_FILE: &str = "data/public/partial_scripts.json";
pub const DEFAULT_DISPROVE_SCRIPTS_FILE: &str = "data/public/disprove_scripts.json";
pub const DEFAULT_SIGNED_ASSERTION_FILE: &str = "data/public/signed_assertions.json";

pub const DFFAULT_DISPROVE_WITNESS_FILE: &str = "data/public/disprove_witness.json";

pub const DEFAULT_TXNS_DIR: &str = "data/public/txns/";
pub const PEGIN_DEPOSIT_FILE_NAME: &str = "pegin-deposit.json";
pub const PEGIN_REFUND_FILE_NAME: &str = "pegin-refund.json";
pub const PEGIN_CONFIRM_FILE_NAME: &str = "pegin-confirm.json";
pub const PRE_KICKOFF_FILE_NAME: &str = "pre-kickoff.json";

#[derive(Deserialize, Debug)]
pub struct Config {
    #[serde(default)] 
    pub general: GeneralConfig,
    #[serde(default)] 
    pub depositor: DepositorConfig,
    #[serde(default)] 
    pub operator: OperatorConfig,
    #[serde(default)] 
    pub federation: FederationConfig,
    #[serde(default)] 
    pub challenger: ChallengerConfig,
}

#[derive(Deserialize, Debug)]
pub struct GeneralConfig {    
    #[serde(default = "default_network")]
    pub network: String,

    pub federation_pubkeys: Option<Vec<String>>,
    pub federation_taproot_pubkeys: Option<String>,
    pub operator_pubkey: Option<String>,
    pub operator_taproot_pubkey: Option<String>,

    #[serde(default = "default_txns_dir")]
    pub txns_dir: String,

    #[serde(default = "default_operator_wots_pubkey_file")]
    pub operator_wots_pubkey_file: String,

    #[serde(default = "default_vkey_file")]
    pub vkey_file: String,
    #[serde(default = "default_proof_file")]
    pub proof_file: String,
    #[serde(default = "default_pubin_file")]
    pub pubin_file: String,

    #[serde(default = "default_partial_scripts_file")]
    pub partial_scripts_file: String,
    #[serde(default = "default_disprove_scripts_file")]
    pub disprove_scripts_file: String,
    #[serde(default = "default_signed_assertions_file")]
    pub signed_assertions_file: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct DepositorConfig {    
    pub depositor_evm_address: Option<String>,
    pub depositor_taproot_public_key: Option<String>,
    pub depositor_public_key: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct OperatorConfig {   
    #[serde(default = "default_operator_wots_secret_file")]
    pub operator_wots_seckey_file: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct FederationConfig {    
}

#[derive(Deserialize, Debug)]
pub struct ChallengerConfig {   
    #[serde(default = "default_disprove_witness_file")]
    pub disprove_witness_file: String, 
}

pub fn load_config(file: &str) -> Config {
    let config_str = std::fs::read_to_string(file).expect("fail to read config file");
    toml::from_str(&config_str).expect("fail to decode toml")
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            network: "mainnet".to_string(),
            federation_pubkeys: None,
            federation_taproot_pubkeys: None,
            operator_pubkey: None,
            operator_taproot_pubkey: None,
            txns_dir: default_txns_dir(),
            operator_wots_pubkey_file: default_operator_wots_pubkey_file(),
            vkey_file: default_vkey_file(),
            proof_file: default_proof_file(),
            pubin_file: default_pubin_file(),
            partial_scripts_file: default_partial_scripts_file(),
            disprove_scripts_file: default_disprove_scripts_file(),
            signed_assertions_file: default_signed_assertions_file(),
        }
    }
}
impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            operator_wots_seckey_file: default_operator_wots_secret_file(),
        }
    }
}
impl Default for ChallengerConfig {
    fn default() -> Self {
        Self {
            disprove_witness_file: default_disprove_witness_file(),
        }
    }
}

pub(crate) fn match_network(network: &str) -> Result<Network, String> {
    match network {
        "Mainnet" => Ok(Network::Bitcoin),
        "Bitcoin" => Ok(Network::Bitcoin),
        "Tesnet" => Ok(Network::Testnet),
        "Tesnet4" => Ok(Network::Testnet4),
        "Regtest" => Ok(Network::Regtest),
        "Signet" => Ok(Network::Signet),

        "mainnet" => Ok(Network::Bitcoin),
        "bitcoin" => Ok(Network::Bitcoin),
        "tesnet" => Ok(Network::Testnet),
        "tesnet4" => Ok(Network::Testnet4),
        "regtest" => Ok(Network::Regtest),
        "signet" => Ok(Network::Signet),

        _ => Err("unknow network: {network}, please choose from: Mainnet, Tesnet, Tesnet4, Regtest, Signet".to_string()),
    }
}
fn default_network() -> String {
    "Mainnet".to_string()
}
fn default_txns_dir() -> String {
    DEFAULT_TXNS_DIR.to_string()
}
fn default_operator_wots_secret_file() -> String {
    DEFAULT_WOTS_SECRET_FILE.to_string()
}
fn default_operator_wots_pubkey_file() -> String {
    DEFAULT_WOTS_PUBKEY_FILE.to_string()
}
fn default_vkey_file() -> String {
    DEFAULT_VKEY_FILE.to_string()
}
fn default_proof_file() -> String {
    DEFAULT_PROOF_FILE.to_string()
}
fn default_pubin_file() -> String {
    DEFAULT_PUBIN_FILE.to_string()
}
fn default_partial_scripts_file() -> String {
    DEFAULT_PARTIAL_SCRIPTS_FILE.to_string()
}
fn default_disprove_scripts_file() -> String {
    DEFAULT_DISPROVE_SCRIPTS_FILE.to_string()
}
fn default_signed_assertions_file() -> String {
    DEFAULT_SIGNED_ASSERTION_FILE.to_string()
}
fn default_disprove_witness_file() -> String {
    DFFAULT_DISPROVE_WITNESS_FILE.to_string()
}

#[test]
fn test_load_config() {
    use bitcoin::{PublicKey, XOnlyPublicKey};
    use core::str::FromStr;
    let conf = dbg!(load_config("src/bin/goat-bridge/example.config.toml"));

    let federation_taproot_pubkeys = &conf.general.federation_taproot_pubkeys.expect("federation_taproot_pubkeys is not provided in the configuration file");
    let federation_taproot_pubkeys = XOnlyPublicKey::from_str(federation_taproot_pubkeys).expect("invalid federation_taproot_pubkeys");
    
    let depositor_taproot_public_key = &conf.depositor.depositor_taproot_public_key.expect("depositor_taproot_public_key is not provided in the configuration file");
    let depositor_taproot_public_key = XOnlyPublicKey::from_str(depositor_taproot_public_key).expect("invalid depositor_taproot_public_key");
    
    let federation_pubkeys = conf.general.federation_pubkeys.expect("federation_pubkeys is not provided in the configuration file");
    let federation_pubkeys: Vec<PublicKey> = federation_pubkeys.into_iter()
        .map(|str| PublicKey::from_str(&str).expect("invalid depositor_public_key {str}"))
        .collect();

    let depositor_public_key = &conf.depositor.depositor_public_key.expect("depositor_public_key is not provided in the configuration file");
    let depositor_public_key = PublicKey::from_str(depositor_public_key).expect("invalid depositor_public_key");
    
    dbg!(federation_taproot_pubkeys);
    dbg!(depositor_taproot_public_key);
    dbg!(depositor_public_key);
    dbg!(federation_pubkeys);
}

#[test]
fn test_keys() {
    use goat_bridge::contexts::{
        base::generate_keys_from_secret,
        depositor::DepositorContext,
        operator::OperatorContext,
        verifier::VerifierContext,
    };
    use bitcoin::PublicKey;

    let source_network = Network::Regtest;
    const OPERATOR_SECRET: &str = "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac";
    const VERIFIER_0_SECRET: &str = "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2";
    const VERIFIER_1_SECRET: &str = "fc294c70faf210d4d0807ea7a3dba8f7e41700d90c119e1ae82a0687d89d297f";
    const DEPOSITOR_SECRET: &str = "b8f17ea979be24199e7c3fec71ee88914d92fd4ca508443f765d56ce024ef1d7";
    // const DEPOSITOR_EVM_ADDRESS: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"; 

    let (_, verifier_0_public_key) = generate_keys_from_secret(source_network, VERIFIER_0_SECRET);
    let (_, verifier_1_public_key) = generate_keys_from_secret(source_network, VERIFIER_1_SECRET);
    let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
    n_of_n_public_keys.push(verifier_0_public_key);
    n_of_n_public_keys.push(verifier_1_public_key);

    let depositor_context =
        DepositorContext::new(source_network, DEPOSITOR_SECRET, &n_of_n_public_keys);
    let operator_context =
        OperatorContext::new(source_network, OPERATOR_SECRET, &n_of_n_public_keys);
    let verifier_0_context =
        VerifierContext::new(source_network, VERIFIER_0_SECRET, &n_of_n_public_keys);
    let verifier_1_context =
        VerifierContext::new(source_network, VERIFIER_1_SECRET, &n_of_n_public_keys);

    dbg!(depositor_context.depositor_taproot_public_key.to_string());
    dbg!(depositor_context.depositor_public_key.to_string());

    dbg!(operator_context.operator_taproot_public_key.to_string());
    dbg!(operator_context.operator_public_key.to_string());

    dbg!(verifier_0_context.n_of_n_taproot_public_key.to_string());
    dbg!(verifier_0_context.n_of_n_public_key.to_string());

    dbg!(verifier_1_context.n_of_n_public_keys[0].to_string());
    dbg!(verifier_1_context.n_of_n_public_keys[1].to_string());


    // dbg!(depositor_context);
    // dbg!(operator_context);
    // dbg!(verifier_0_context);
    // dbg!(verifier_1_context);

}


