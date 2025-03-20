pub mod commands;
pub mod config;
pub mod files;
pub mod handles;

use core::str::FromStr;
use bitcoin::{OutPoint, Txid, Amount, Sequence};
use clap::{arg, command, Parser};
use commands::Commands;
use config::load_config;
use handles::{
    handle_federation_presign, handle_generate_bitvm_instance, handle_generate_disprove_scripts, handle_generate_pegin_txns, handle_generate_prekickoff_tx, handle_generate_wots_keys, handle_operator_presign, handle_sign_proof, handle_verify_proof
};

#[derive(Parser)]
#[command(about = "goat bitvm cli-tools", long_about = None)]
struct Cli {
    /// config file path
    #[arg(short = 'c', long = "conf")]
    config_file: String,

    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateDisproveScripts{} => { 
            let conf = load_config(&cli.config_file);
            handle_generate_disprove_scripts(conf);
        },
        Commands::GenerateWotsKeys {secret_seed} => {
            let conf = load_config(&cli.config_file);
            handle_generate_wots_keys(conf, secret_seed);
        },
        Commands::SignProof {skip_validation} => {
            let conf = load_config(&cli.config_file);
            handle_sign_proof(conf, *skip_validation);
        },
        Commands::VerifyProof{} => {
            let conf = load_config(&cli.config_file);
            handle_verify_proof(conf);
        },
        Commands::GeneratePeginTxns {fund_txid, fund_vout, sequence, amount} => {
            let conf = load_config(&cli.config_file);
            let fund_outpoint = OutPoint {
                txid: Txid::from_str(fund_txid).expect("fail to decode txid"),
                vout: *fund_vout,
            };
            let sequence = Sequence::from_hex(sequence).unwrap();
            let amount = Amount::from_sat(*amount);
            handle_generate_pegin_txns(conf, fund_outpoint, sequence, amount);
        },
        Commands::GeneratePrekickoffTx {fund_txid, fund_vout, sequence, amount} => {
            let conf = load_config(&cli.config_file);
            let fund_outpoint = OutPoint {
                txid: Txid::from_str(fund_txid).expect("fail to decode txid"),
                vout: *fund_vout,
            };
            let sequence = Sequence::from_hex(sequence).unwrap();
            let amount = Amount::from_sat(*amount);
            handle_generate_prekickoff_tx(conf, fund_outpoint, sequence, amount);
        },
        Commands::GenerateBitvmInstanace {} => {
            let conf = load_config(&cli.config_file);
            handle_generate_bitvm_instance(conf);
        },
        Commands::FederationPresign { } => {
            let conf = load_config(&cli.config_file);
            handle_federation_presign(conf);
        },
        Commands::OperatorPresign { } => {
            let conf = load_config(&cli.config_file);
            handle_operator_presign(conf);
        },
        
        _ => {}
    }
}

#[test]
fn generate_test_keys() {
    use goat_bridge::contexts::{
        base::generate_keys_from_secret,
        depositor::DepositorContext,
        operator::OperatorContext,
        verifier::VerifierContext,
    };
    use bitcoin::{PublicKey, Network};

    let source_network = Network::Regtest;
    const OPERATOR_SECRET: &str = "3076ca1dfc1e383be26d5dd3c0c427340f96139fa8c2520862cf551ec2d670ac";
    const VERIFIER_0_SECRET: &str = "ee0817eac0c13aa8ee2dd3256304041f09f0499d1089b56495310ae8093583e2";
    const VERIFIER_1_SECRET: &str = "fc294c70faf210d4d0807ea7a3dba8f7e41700d90c119e1ae82a0687d89d297f";
    const DEPOSITOR_SECRET: &str = "b8f17ea979be24199e7c3fec71ee88914d92fd4ca508443f765d56ce024ef1d7";

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
    // let verifier_1_context =
    //     VerifierContext::new(source_network, VERIFIER_1_SECRET, &n_of_n_public_keys);

    dbg!(depositor_context.depositor_taproot_public_key.to_string());
    dbg!(depositor_context.depositor_public_key.to_string());
    dbg!(DEPOSITOR_SECRET);
    dbg!("");
    dbg!(operator_context.operator_taproot_public_key.to_string());
    dbg!(operator_context.operator_public_key.to_string());
    dbg!(OPERATOR_SECRET);
    dbg!("");
    dbg!(verifier_0_context.n_of_n_taproot_public_key.to_string());
    dbg!(verifier_0_context.n_of_n_public_key.to_string());
    dbg!(verifier_0_context.n_of_n_public_keys[0].to_string());
    dbg!(verifier_0_context.n_of_n_public_keys[1].to_string());
    dbg!(VERIFIER_0_SECRET);
    dbg!(VERIFIER_1_SECRET);
    // dbg!("");
    // dbg!(verifier_1_context.n_of_n_taproot_public_key.to_string());
    // dbg!(verifier_1_context.n_of_n_public_key.to_string());
    // dbg!(verifier_1_context.n_of_n_public_keys[0].to_string());
    // dbg!(verifier_1_context.n_of_n_public_keys[1].to_string());
    // dbg!(VERIFIER_1_SECRET);

}


