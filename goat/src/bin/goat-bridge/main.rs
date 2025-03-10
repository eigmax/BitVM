pub mod commands;
pub mod config;
pub mod files;
pub mod handles;

use clap::{arg, command, Parser};
use commands::Commands;
use config::load_config;
use handles::{
    handle_generate_disprove_scripts, handle_generate_wots_keys
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
        Commands::GenerateWotsKeys { secret_seed } => {
            let conf = load_config(&cli.config_file);
            handle_generate_wots_keys(conf, secret_seed);
        }
        _ => {}
    }
}