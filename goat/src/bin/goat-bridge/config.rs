use serde::Deserialize;
use bitcoin::{PublicKey, XOnlyPublicKey};

pub const DEFAULT_WOTS_SECRET_FILE: &str = "data/private/wots_sec.json";
pub const DEFAULT_WOTS_PUBKEY_FILE: &str = "data/public/wots_pub.json";

pub const DEFAULT_VKEY_FILE: &str = "data/public/groth16/vkey.bin";
pub const DEFAULT_PROOF_FILE: &str = "data/public/groth16/proof.bin";
pub const DEFAULT_PUBIN_FILE: &str = "data/public/groth16/pubin.bin";

pub const DEFAULT_PARTIAL_SCRIPTS_FILE: &str = "data/public/partial_scripts.json";
pub const DEFAULT_DISPROVE_SCRIPTS_FILE: &str = "data/public/disprove_scripts.json";
pub const DEFAULT_SIGNED_ASSERTION_FILE: &str = "data/public/signed_assertions.json";

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
    #[serde(default)] 
    pub federation_pubkeys: Option<Vec<PublicKey>>,
    #[serde(default)] 
    pub federation_taproot_pubkeys: Option<Vec<XOnlyPublicKey>>,

    #[serde(default)] 
    pub operator_pubkey: Option<PublicKey>,
    #[serde(default)] 
    pub operator_taproot_pubkey: Option<XOnlyPublicKey>,

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
}

#[derive(Deserialize, Debug)]
pub struct OperatorConfig {   
    #[serde(default = "default_operator_wots_secret_file")]
    pub operator_wots_seckey_file: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct FederationConfig {    
}

#[derive(Deserialize, Debug, Default)]
pub struct ChallengerConfig {    
}

pub fn load_config(file: &str) -> Config {
    let config_str = std::fs::read_to_string(file).expect("fail to read config file");
    toml::from_str(&config_str).expect("fail to decode toml")
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            federation_pubkeys: None,
            federation_taproot_pubkeys: None,
            operator_pubkey: None,
            operator_taproot_pubkey: None,
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

