use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// -GENERAL----: generate disprove scripts 
    GenerateDisproveScripts{
    },

    /// -GENERAL----: generate all necessary bitvm2 transactions (unsigned)
    GenerateBitvmInstanace {
    },

    /// -DEPOSITOR--: generate pegin-prepare, pegin-comfirm & pegin-refund txns
    GeneratePeginTxns {
        /// (hex String) txid of input utxo
        // #[arg(long)]
        fund_txid: String,

        /// (u32) vout of input utxo
        // #[arg(long)]
        fund_vout: u32,

        /// (hex String) sequence of input utxo
        // #[arg(long)]
        sequence: String, 

        /// (sats)  amount of input utxo
        // #[arg(long)]
        amount: u64,
    },

    // /// -FEDERATION-: generate psbt for federation members
    // GenerateFederationPsbt {
    //     /// (hex String) federation member's public-key
    //     // #[arg(long)]
    //     pubkey: String,
    // },

    /// -FEDERATION-: push federation members' pre-signature for necessary txns, include: pegin_comfirm, take_1, take_2, assert_final, disprove
    FederationPresign {
    },

    /// -OPERATOR---: generate pre-kickoff(pegout-confirm) tx
    GeneratePrekickoffTx {
        /// (hex String) txid of input utxo
        // #[arg(long)]
        fund_txid: String,

        /// (u32) vout of input utxo
        // #[arg(long)]
        fund_vout: u32,

        /// (hex String) sequence of input utxo
        // #[arg(long)]
        sequence: String, 

        /// (sats)  amount of input utxo
        // #[arg(long)]
        amount: u64,
    },

    // /// -OPERATOR---: generate psbt for operator
    // GenerateOperatorPsbt {
    //     // #[arg(long)]
    //     presign: bool,

    //     // #[arg(long)]
    //     kickoff: bool,

    //     // #[arg(long)]
    //     take1: bool,

    //     // #[arg(long)]
    //     take2: bool,
    // },

    /// -OPERATOR---: push operator's pre-signature necessary txns, include: challenge
    OperatorPresign {
    },

    /// -OPERATOR---: generate winternitz public-keys & secret-keys 
    /// (⚠ Warning: This feature is for testing and development purposes only. It may not be secure enough for production use.)
    GenerateWotsKeys {
        /// (String) a random seed used to generate wots keypairs
        // #[arg(short = 's', long = "seed")]
        secret_seed: String,
    }, 

    /// -OPERATOR---: generate winternitz signatures for groth16-proof & intermediate-values 
    SignProof {
        /// skip verifying the correctness of generated sigs
        #[arg(long)]
        skip_validation: bool,
    },

    // /// -CHALLENGER-: check if kickoff-tx is valid
    // ValidateKickoff {
    // },

    // /// -CHALLENGER-: check if the groth16-proof(bitcommitments) submitted by operator in assert-tx is valid 
    // ValidateAssert {
    // },

    /// -CHALLENGER-: check if the groth16-proof(bitcommitments) is valid 
    VerifyProof {
    }
}