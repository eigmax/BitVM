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
    handle_generate_disprove_scripts, handle_generate_wots_keys,
    handle_sign_proof, handle_verify_proof, handle_generate_pegin_txns,
    handle_generate_prekickoff_tx,
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

        },
        _ => {}
    }
}

#[test]
fn generate_test_pegin_input_data() {
    use bitcoin::{Network, PublicKey, Sequence};

    let txid = Txid::from_str("180eb81bb6273fda422e4b3410341da2fde71c2a1b20fb8c8b6256a5064ff1ac").unwrap();
    let vout: u32 = 0;
    let network = Network::Regtest;
    let sequence = Sequence(0xFFFFFFFF);
    let amount = Amount::from_sat(1000000);
}


