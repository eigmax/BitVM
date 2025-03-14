use crate::config::{
    match_network, Config, PEGIN_DEPOSIT_FILE_NAME, 
    PEGIN_REFUND_FILE_NAME, PEGIN_CONFIRM_FILE_NAME,
    PRE_KICKOFF_FILE_NAME,
};
use crate::files::{
    file_exists, load_groth16_proof, load_groth16_pubin, 
    load_groth16_vk, load_scripts_from_file, load_signed_assertions_from_file, 
    load_wots_pubkeys, load_wots_seckeys, write_disprove_witness, 
    write_scripts_to_file, write_signed_assertions_to_file, 
    write_wots_pubkeys, write_wots_seckeys, create_necessary_dir,
};
use crate::files::{WotsSecretKeys, WotsPublicKeys};
use bitvm::chunk::api::{
    api_generate_full_tapscripts, api_generate_partial_script, 
    generate_signatures, generate_signatures_lit, validate_assertions, 
    NUM_PUBS, NUM_U160, NUM_U256, PublicKeys as Groth16WotsPublicKeys,
};
use bitvm::signatures::{
    wots_api::{wots256, wots160},
    signing_winternitz::{WinternitzPublicKey, WinternitzSecret, LOG_D},
    winternitz::Parameters,
};
use goat_bridge::commitments::{NUM_KICKOFF, KICKOFF_MSG_SIZE, CommitmentMessageId};
use goat_bridge::transactions::{
    base::{Input, BaseTransaction}, 
    peg_in::{
        peg_in_deposit::PegInDepositTransactionGeneral,
        peg_in_refund::PegInRefundTransaction,
        peg_in_confirm::PegInConfirmTransaction,
    },
    peg_out_confirm::PreKickoffTransaction,
};
use goat_bridge::connectors::{
    connector_0::Connector0,
    connector_6::Connector6,
    connector_z::ConnectorZ,
};
use std::fs::File;
use std::io::{Write, BufReader};
use sha2::{Sha256, Digest};
use bitcoin::{Amount, OutPoint, PublicKey, Sequence, XOnlyPublicKey};
use core::str::FromStr;

pub(crate) fn handle_generate_disprove_scripts(conf: Config) {
    println!("\nloading vkey ...");
    assert!(file_exists(&conf.general.vkey_file), "vkey is not provided");
    let ark_vkey = load_groth16_vk(&conf.general.vkey_file);

    println!("\nloading operator wots public-key...");
    assert!(file_exists(&conf.general.operator_wots_pubkey_file), "operator wots public key is not provided");
    let pubkeys = load_wots_pubkeys(&conf.general.operator_wots_pubkey_file);

    let partial_scripts = if file_exists(&conf.general.partial_scripts_file) {
        println!("\nloading existing partial scripts from {}...", &conf.general.partial_scripts_file);
        load_scripts_from_file(&conf.general.partial_scripts_file)
    } else {
        println!("\ngenerating partial scripts...");
        let scrs = api_generate_partial_script(&ark_vkey);
        write_scripts_to_file(&conf.general.partial_scripts_file, scrs.clone());
        println!("\npartial scripts was written to {}", &conf.general.partial_scripts_file);
        scrs
    };

    println!("\ngenerating disprove scripts...");
    let disprove_scripts = api_generate_full_tapscripts(pubkeys.1, &partial_scripts);
    write_scripts_to_file(&conf.general.disprove_scripts_file, disprove_scripts);
    println!("\ndisprove scripts was written to {}", &conf.general.disprove_scripts_file);
} 

pub(crate) fn handle_generate_wots_keys(conf: Config, seed: &str) {
    let secrets = seed_to_secrets(seed);
    let pubkeys = secrets_to_pubkeys(&secrets);
    write_wots_seckeys(&conf.operator.operator_wots_seckey_file, secrets);
    write_wots_pubkeys(&conf.general.operator_wots_pubkey_file, pubkeys);
    println!(
        "public keys was written to {}\nsecret was keys written to {}",
        &conf.general.operator_wots_pubkey_file,
        &conf.operator.operator_wots_seckey_file,
    )
}

pub(crate) fn handle_sign_proof(conf: Config, skip_validation: bool) {
    println!("\nloading vkey ...");
    assert!(file_exists(&conf.general.vkey_file), "vkey not provided");
    let ark_vkey = load_groth16_vk(&conf.general.vkey_file);

    println!("\nloading groth16 proof ...");
    assert!(file_exists(&conf.general.vkey_file), "proof not provided");
    let ark_proof = load_groth16_proof(&conf.general.proof_file);

    println!("\nloading public-inputs ...");
    assert!(file_exists(&conf.general.vkey_file), "public-inputs not provided");
    let ark_pubin = load_groth16_pubin(&conf.general.pubin_file);

    println!("\nloading operator wots secret keys ...");
    assert!(file_exists(&conf.general.vkey_file), "public-inputs not provided");
    let wots_sec = load_wots_seckeys(&conf.operator.operator_wots_seckey_file);

    let proof_sigs = if skip_validation {
        generate_signatures_lit(ark_proof, ark_pubin, &ark_vkey, wots_sec.1.to_vec()).unwrap()
    } else {
        generate_signatures(ark_proof, ark_pubin, &ark_vkey, wots_sec.1.to_vec()).unwrap()
    };
    write_signed_assertions_to_file(&conf.general.signed_assertions_file, proof_sigs);
    println!("signed assertions was written to {}", &conf.general.signed_assertions_file);
}   

pub(crate) fn handle_verify_proof(conf: Config) {
    println!("\nloading vkey ...");
    assert!(file_exists(&conf.general.vkey_file), "vkey not provided");
    let ark_vkey = load_groth16_vk(&conf.general.vkey_file);

    println!("\nloading proof signatures ...");
    assert!(file_exists(&conf.general.vkey_file), "proof-sigs not provided");
    let proof_sigs = load_signed_assertions_from_file(&conf.general.signed_assertions_file);
    
    println!("\nloading operator wots public-key...");
    assert!(file_exists(&conf.general.operator_wots_pubkey_file), "operator wots public key is not provided");
    let pubkey = load_wots_pubkeys(&conf.general.operator_wots_pubkey_file);

    println!("\nloading disprove scripts...");
    assert!(file_exists(&conf.general.disprove_scripts_file), "disprove scripts is not provided");
    let disprove_scripts = load_scripts_from_file(&conf.general.disprove_scripts_file).try_into().unwrap();

    let res = validate_assertions(&ark_vkey, proof_sigs, pubkey.1, &disprove_scripts);
    match res {
        Some((index,witness)) => {
            write_disprove_witness(&conf.challenger.disprove_witness_file, index, witness);
            println!("\nProof is invalid! Disprove witness is written to: {}", &conf.challenger.disprove_witness_file);
        },
        _ => {
            println!("\nProof is Ok.");
        }
    };
}

pub(crate) fn handle_generate_pegin_txns(conf: Config, input_oupoint: OutPoint, input_sequence: Sequence, amount: Amount) {
    println!("\nloading config...");
    let network = match_network(&conf.general.network).unwrap();

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
    
    let connector_z = ConnectorZ::new(
        network,
        &conf.depositor.depositor_evm_address.expect("depositor_evm_address is not provided in the configuration file"),
        &depositor_taproot_public_key,
        &federation_taproot_pubkeys,
    );
    let connector_0 = Connector0::new(
        network,
        &federation_taproot_pubkeys,
    );

    // pegin deposit
    let fund_input = Input {
        outpoint: input_oupoint,
        amount,
    };
    let pegin_deposit_tx = PegInDepositTransactionGeneral::new_unsigned(
        &connector_z, 
        fund_input,
        input_sequence,
    );
    let pegin_deposit_txid = pegin_deposit_tx.finalize().compute_txid();

    // pegin refund
    let refund_output_index = 0;
    let refund_input = Input {
        outpoint: OutPoint {
            txid: pegin_deposit_txid,
            vout: refund_output_index,
        },
        amount: pegin_deposit_tx.finalize().output[refund_output_index as usize].value,
    };
    let pegin_refund_tx = PegInRefundTransaction::new_for_validation(
        network, 
        &depositor_public_key, 
        &connector_z, 
        refund_input,
    );

    // pegin confirm
    let confirm_output_index = 0;
    let confirm_input = Input {
        outpoint: OutPoint {
            txid: pegin_deposit_txid,
            vout: confirm_output_index,
        },
        amount: pegin_deposit_tx.finalize().output[confirm_output_index as usize].value,
    };
    let pegin_confirm_tx = PegInConfirmTransaction::new_for_validation(
        &connector_0, 
        &connector_z, 
        confirm_input, 
        federation_pubkeys,
    );

    let pegin_deposit_tx_bytes = serde_json::to_vec_pretty(&pegin_deposit_tx).unwrap();
    let pegin_deposit_tx_file = format!("{}{}", &conf.general.txns_dir, PEGIN_DEPOSIT_FILE_NAME);
    create_necessary_dir(&pegin_deposit_tx_file);
    let mut file = File::create(pegin_deposit_tx_file.clone()).unwrap();
    file.write_all(&pegin_deposit_tx_bytes).unwrap();

    let pegin_refund_tx_bytes = serde_json::to_vec_pretty(&pegin_refund_tx).unwrap();
    let pegin_refund_tx_file = format!("{}{}", &conf.general.txns_dir, PEGIN_REFUND_FILE_NAME);
    let mut file = File::create(pegin_refund_tx_file.clone()).unwrap();
    file.write_all(&pegin_refund_tx_bytes).unwrap();

    let pegin_confirm_tx_bytes = serde_json::to_vec_pretty(&pegin_confirm_tx).unwrap();
    let pegin_confirm_tx_file = format!("{}{}", &conf.general.txns_dir, PEGIN_CONFIRM_FILE_NAME);
    let mut file = File::create(pegin_confirm_tx_file.clone()).unwrap();
    file.write_all(&pegin_confirm_tx_bytes).unwrap();

    println!(
        "pegin_deposit_tx was written to {}\npegin_refund_tx written to {}\npegin_confirm_tx written to {}",
        pegin_deposit_tx_file, pegin_refund_tx_file, pegin_confirm_tx_file,
    )
}

pub(crate) fn handle_generate_prekickoff_tx(conf: Config, input_oupoint: OutPoint, input_sequence: Sequence, amount: Amount) {
    println!("\nloading config...");
    let network = match_network(&conf.general.network).unwrap();

    let operator_taproot_pubkey = &conf.general.operator_taproot_pubkey.expect("operator_taproot_pubkey is not provided in the configuration file");
    let operator_taproot_pubkey = XOnlyPublicKey::from_str(operator_taproot_pubkey).expect("invalid operator_taproot_pubkey");

    println!("\nloading operator wots public-key...");
    assert!(file_exists(&conf.general.operator_wots_pubkey_file), "operator wots public key not provided");
    let operator_wots_pubkey = load_wots_pubkeys(&conf.general.operator_wots_pubkey_file);
    let kickoff_wots_commitment_keys = CommitmentMessageId::pubkey_map_for_kickoff(operator_wots_pubkey.0);
    let connector_6 = Connector6::new(
        network, 
        &operator_taproot_pubkey, 
        &kickoff_wots_commitment_keys
    );

    let fund_input = Input {
        outpoint: input_oupoint,
        amount,
    };
    let prekickoff_tx = PreKickoffTransaction::new_unsigned(
        &connector_6, 
        fund_input,
        input_sequence,
    );

    let prekickoff_tx_bytes = serde_json::to_vec_pretty(&prekickoff_tx).unwrap();
    let prekickoff_tx_file = format!("{}{}", &conf.general.txns_dir, PRE_KICKOFF_FILE_NAME);
    create_necessary_dir(&prekickoff_tx_file);
    let mut file = File::create(prekickoff_tx_file.clone()).unwrap();
    file.write_all(&prekickoff_tx_bytes).unwrap();

    println!("\npre_kickoff_tx was written to {}", prekickoff_tx_file)
}

pub(crate) fn handle_generate_bitvm_instance(conf: Config) {
    println!("\nloading config...");
    let network = match_network(&conf.general.network).unwrap();

    let federation_taproot_pubkeys = &conf.general.federation_taproot_pubkeys.expect("federation_taproot_pubkeys is not provided in the configuration file");
    let federation_taproot_pubkeys = XOnlyPublicKey::from_str(federation_taproot_pubkeys).expect("invalid federation_taproot_pubkeys");
        
    let federation_pubkeys = conf.general.federation_pubkeys.expect("federation_pubkeys is not provided in the configuration file");
    let federation_pubkeys: Vec<PublicKey> = federation_pubkeys.into_iter()
        .map(|str| PublicKey::from_str(&str).expect("invalid depositor_public_key {str}"))
        .collect();

    let operator_taproot_pubkey = &conf.general.operator_taproot_pubkey.expect("operator_taproot_pubkey is not provided in the configuration file");
    let operator_taproot_pubkey = XOnlyPublicKey::from_str(operator_taproot_pubkey).expect("invalid operator_taproot_pubkey");

    let operator_pubkey = &conf.general.operator_pubkey.expect("operator_pubkey is not provided in the configuration file");
    let operator_pubkey = PublicKey::from_str(operator_pubkey).expect("invalid operator_pubkey");
    
    println!("\nloading pegin-confirm-tx...");
    let pegin_confirm_file = format!("{}{}", &conf.general.txns_dir, PEGIN_CONFIRM_FILE_NAME);
    assert!(file_exists(&pegin_confirm_file), "pegin-confirm tx not provided");
    let file = File::open(pegin_confirm_file.clone()).expect(&format!("fail to open {:?}", pegin_confirm_file));
    let reader = BufReader::new(file);
    let pegin_confirm_tx: PegInConfirmTransaction = serde_json::from_reader(reader).unwrap();

    println!("\nloading pre-kickoff-tx...");
    let pre_kickoff_file = format!("{}{}", &conf.general.txns_dir, PRE_KICKOFF_FILE_NAME);
    assert!(file_exists(&pre_kickoff_file), "pre-kickoff tx not provided");
    let file = File::open(pre_kickoff_file.clone()).expect(&format!("fail to open {:?}", pre_kickoff_file));
    let reader = BufReader::new(file);
    let pre_kickoff_tx: PreKickoffTransaction = serde_json::from_reader(reader).unwrap();

    println!("\nloading operator wots public-keys...");
    assert!(file_exists(&conf.general.operator_wots_pubkey_file), "operator wots public key not provided");
    let operator_wots_pubkeys = load_wots_pubkeys(&conf.general.operator_wots_pubkey_file);

    println!("\nloading disprove scripts...");
    assert!(file_exists(&conf.general.disprove_scripts_file), "disprove scripts not provided");
    // let disprove_scripts = load_scripts_from_file(&conf.general.disprove_scripts_file).try_into().unwrap();

    // kickoff
    


}

pub(crate) fn secrets_to_pubkeys(secrets: &WotsSecretKeys) -> WotsPublicKeys {
    let mut pubins = vec![];
    for i in 0..NUM_PUBS {
        pubins.push(wots256::generate_public_key(&secrets.1[i]));
    }
    let mut fq_arr = vec![];
    for i in 0..NUM_U256 {
        let p256 = wots256::generate_public_key(&secrets.1[i+NUM_PUBS]);
        fq_arr.push(p256);
    }
    let mut h_arr = vec![];
    for i in 0..NUM_U160 {
        let p160 = wots160::generate_public_key(&secrets.1[i+NUM_PUBS+NUM_U256]);
        h_arr.push(p160);
    }
    let g16_wotspubkey: Groth16WotsPublicKeys = (
        pubins.try_into().unwrap(),
        fq_arr.try_into().unwrap(),
        h_arr.try_into().unwrap(),
    );

    let mut kickoff_wotspubkey = vec![];
    for i in 0..NUM_KICKOFF {
        kickoff_wotspubkey.push(WinternitzPublicKey::from(&secrets.0[i]));
    }

    (
        kickoff_wotspubkey.try_into().unwrap_or_else(|_e| panic!("kickoff bitcom key number not match")), 
        g16_wotspubkey,
    )
}
pub(crate) fn seed_to_secrets(seed: &str) -> WotsSecretKeys {
    let seed_hash = sha256(seed);
    let g16_wotsseckey = (0..NUM_PUBS+NUM_U256+NUM_U160)
        .map(|idx| {
            let sec_i = sha256_with_id(&seed_hash, 1);
            let sec_i = sha256_with_id(&sec_i, idx);
            format!("{sec_i}{:04x}{:04x}", 1, idx)
        })
        .collect::<Vec<String>>()
        .try_into().unwrap();
    
    let kickoff_wotsseckey = (0..NUM_KICKOFF)
        .map(|idx| {
            let sec_i = sha256_with_id(&seed_hash, 0);
            let sec_i = sha256_with_id(&sec_i, idx);
            let sec_str = format!("{sec_i}{:04x}{:04x}", 0, idx);
            let parameters = Parameters::new_by_bit_length(KICKOFF_MSG_SIZE[idx] as u32 * 8, LOG_D);
            WinternitzSecret::from_string(&sec_str, &parameters)
        })
        .collect::<Vec<WinternitzSecret>>()
        .try_into().unwrap_or_else(|_e| panic!("kickoff bitcom key number not match"));
    (kickoff_wotsseckey, g16_wotsseckey)
}
fn sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}
fn sha256_with_id(input: &str, idx: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    sha256(&format!("{:x}{:04x}", hasher.finalize(), idx))
}

