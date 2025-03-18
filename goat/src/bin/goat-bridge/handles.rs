use crate::config::{
    match_network, Config, PEGIN_DEPOSIT_FILE_NAME, 
    PEGIN_REFUND_FILE_NAME, PEGIN_CONFIRM_FILE_NAME,
    PRE_KICKOFF_FILE_NAME, KICKOFF_FILE_NAME, TAKE1_FILE_NAME,
    CHALLENGE_FILE_NAME, ASSERT_INIT_FILE_NAME, ASSERT_COMMIT_1_FILE_NAME,
    ASSERT_COMMIT_2_FILE_NAME, ASSERT_FINAL_FILE_NAME, 
    TAKE2_FILE_NAME, DISPROVE_FILE_NAME,
};
use crate::files::{
    file_exists, load_groth16_proof, load_groth16_pubin, 
    load_groth16_vk, load_scripts_from_file, load_signed_assertions_from_file, 
    load_wots_pubkeys, load_wots_seckeys, write_disprove_witness, 
    write_scripts_to_file, write_signed_assertions_to_file, 
    write_wots_pubkeys, write_wots_seckeys, write_bytes_to_file, 
    load_scripts_bytes_from_file, 
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
use goat_bridge::contexts::operator::OperatorContext;
use goat_bridge::transactions::{
    base::{Input, CROWDFUNDING_AMOUNT}, 
    pre_signed::PreSignedTransaction,
    pre_signed_musig2::PreSignedMusig2Transaction,
    peg_in::{
        peg_in_deposit::PegInDepositTransactionGeneral,
        peg_in_refund::PegInRefundTransaction,
        peg_in_confirm::PegInConfirmTransaction,
    },
    peg_out_confirm::PreKickoffTransaction,
    kick_off::KickOffTransaction,
    take_1::Take1Transaction,
    challenge::ChallengeTransaction,
    assert::utils::{
        split_pubkeys, merge_to_connector_c_commits_public_key, 
        AssertCommit1ConnectorsE, AssertCommit2ConnectorsE, AssertCommitConnectorsF,
    },
    assert::assert_initial::AssertInitialTransaction,
    assert::assert_commit_1::AssertCommit1Transaction,
    assert::assert_commit_2::AssertCommit2Transaction,
    assert::assert_final::AssertFinalTransaction,
    take_2::Take2Transaction,
    disprove::DisproveTransaction,
};
use goat_bridge::connectors::{
    connector_0::Connector0,
    connector_3::Connector3,
    connector_4::Connector4,
    connector_5::Connector5,
    connector_6::Connector6,
    connector_a::ConnectorA,
    connector_b::ConnectorB,
    connector_c::ConnectorC,
    connector_d::ConnectorD,
    connector_e::ConnectorE,
    connector_f_1::ConnectorF1,
    connector_f_2::ConnectorF2,
    connector_z::ConnectorZ,
};
use goat_bridge::contexts::{
    base::{generate_n_of_n_public_key, generate_keys_from_secret},
    verifier::VerifierContext,
};
use sha2::{Sha256, Digest};
use bitcoin::{
    Amount, OutPoint, PublicKey, Sequence, Witness, XOnlyPublicKey 
};
use musig2::SecNonce;
use std::collections::HashMap;
use std::str::FromStr;
use std::fs::File;
use std::io::BufReader;

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

    let federation_taproot_pubkey = &conf.general.federation_taproot_pubkey.expect("federation_taproot_pubkey is not provided in the configuration file");
    let federation_taproot_pubkey = XOnlyPublicKey::from_str(federation_taproot_pubkey).expect("invalid federation_taproot_pubkey");

    let federation_pubkeys = conf.general.federation_pubkeys.expect("federation_pubkeys is not provided in the configuration file");
    let federation_pubkeys: Vec<PublicKey> = federation_pubkeys.into_iter()
        .map(|str| PublicKey::from_str(&str).expect("invalid depositor_public_key {str}"))
        .collect();

    let depositor_public_key = &conf.depositor.depositor_public_key.expect("depositor_public_key is not provided in the configuration file");
    let depositor_public_key = PublicKey::from_str(depositor_public_key).expect("invalid depositor_public_key");
    let depositor_taproot_public_key = XOnlyPublicKey::from(depositor_public_key);

    let (_,aggregated_federation_taproot_pubkey) = generate_n_of_n_public_key(&federation_pubkeys);
    assert_eq!(aggregated_federation_taproot_pubkey, federation_taproot_pubkey, "federation_taproot_pubkey is not aggregated from federation_pubkeys");

    let connector_z = ConnectorZ::new(
        network,
        &conf.depositor.depositor_evm_address.expect("depositor_evm_address is not provided in the configuration file"),
        &depositor_taproot_public_key,
        &federation_taproot_pubkey,
    );
    let connector_0 = Connector0::new(
        network,
        &federation_taproot_pubkey,
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
    let pegin_deposit_txid = pegin_deposit_tx.tx().compute_txid();

    // pegin refund
    let refund_output_index = 0;
    let refund_input = Input {
        outpoint: OutPoint {
            txid: pegin_deposit_txid,
            vout: refund_output_index,
        },
        amount: pegin_deposit_tx.tx().output[refund_output_index as usize].value,
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
        amount: pegin_deposit_tx.tx().output[confirm_output_index as usize].value,
    };
    let pegin_confirm_tx = PegInConfirmTransaction::new_for_validation(
        &connector_0, 
        &connector_z, 
        confirm_input, 
        federation_pubkeys,
    );

    let pegin_deposit_tx_bytes = serde_json::to_vec_pretty(&pegin_deposit_tx).unwrap();
    let pegin_deposit_tx_file = format!("{}{}", &conf.general.txns_dir, PEGIN_DEPOSIT_FILE_NAME);
    write_bytes_to_file(&pegin_deposit_tx_bytes, &pegin_deposit_tx_file);

    let pegin_refund_tx_bytes = serde_json::to_vec_pretty(&pegin_refund_tx).unwrap();
    let pegin_refund_tx_file = format!("{}{}", &conf.general.txns_dir, PEGIN_REFUND_FILE_NAME);
    write_bytes_to_file(&pegin_refund_tx_bytes, &pegin_refund_tx_file);

    let pegin_confirm_tx_bytes = serde_json::to_vec_pretty(&pegin_confirm_tx).unwrap();
    let pegin_confirm_tx_file = format!("{}{}", &conf.general.txns_dir, PEGIN_CONFIRM_FILE_NAME);
    write_bytes_to_file(&pegin_confirm_tx_bytes, &pegin_confirm_tx_file);

    println!(
        "pegin_deposit_tx was written to {}\npegin_refund_tx written to {}\npegin_confirm_tx written to {}",
        pegin_deposit_tx_file, pegin_refund_tx_file, pegin_confirm_tx_file,
    )
}

pub(crate) fn handle_generate_prekickoff_tx(conf: Config, input_oupoint: OutPoint, input_sequence: Sequence, amount: Amount) {
    println!("\nloading config...");
    let network = match_network(&conf.general.network).unwrap();

    let operator_pubkey = &conf.general.operator_pubkey.expect("operator_pubkey is not provided in the configuration file");
    let operator_pubkey = PublicKey::from_str(operator_pubkey).expect("invalid operator_pubkey");
    let operator_taproot_pubkey = XOnlyPublicKey::from(operator_pubkey);

    println!("\nloading operator wots public-key...");
    assert!(file_exists(&conf.general.operator_wots_pubkey_file), "operator wots public key not provided");
    let operator_wots_pubkey = load_wots_pubkeys(&conf.general.operator_wots_pubkey_file);
    let kickoff_wots_commitment_keys = CommitmentMessageId::pubkey_map_for_kickoff(&operator_wots_pubkey.0);
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
    write_bytes_to_file(&prekickoff_tx_bytes, &prekickoff_tx_file);

    println!("\npre_kickoff_tx was written to {}", prekickoff_tx_file)
}

pub(crate) fn handle_generate_bitvm_instance(conf: Config) {
    println!("\nloading config...");
    let network = match_network(&conf.general.network).unwrap();

    let federation_taproot_pubkey = &conf.general.federation_taproot_pubkey.expect("federation_taproot_pubkey is not provided in the configuration file");
    let federation_taproot_pubkey = XOnlyPublicKey::from_str(federation_taproot_pubkey).expect("invalid federation_taproot_pubkey");
        
    // let federation_pubkeys = conf.general.federation_pubkeys.expect("federation_pubkeys is not provided in the configuration file");
    // let federation_pubkeys: Vec<PublicKey> = federation_pubkeys.into_iter()
    //     .map(|str| PublicKey::from_str(&str).expect("invalid depositor_public_key {str}"))
    //     .collect();

    let operator_pubkey = &conf.general.operator_pubkey.expect("operator_pubkey is not provided in the configuration file");
    let operator_pubkey = PublicKey::from_str(operator_pubkey).expect("invalid operator_pubkey");
    let operator_taproot_pubkey = XOnlyPublicKey::from(operator_pubkey);

    println!("\nloading pegin-confirm-tx...");
    let pegin_confirm_file = format!("{}{}", &conf.general.txns_dir, PEGIN_CONFIRM_FILE_NAME);
    assert!(file_exists(&pegin_confirm_file), "pegin-confirm tx not provided");
    let file = File::open(pegin_confirm_file.clone()).expect(&format!("fail to open {:?}", pegin_confirm_file));
    let reader = BufReader::new(file);
    let pegin_confirm_tx: PegInConfirmTransaction = serde_json::from_reader(reader).unwrap();
    let pegin_confirm_txid = pegin_confirm_tx.tx().compute_txid();

    println!("\nloading pre-kickoff-tx...");
    let pre_kickoff_file = format!("{}{}", &conf.general.txns_dir, PRE_KICKOFF_FILE_NAME);
    assert!(file_exists(&pre_kickoff_file), "pre-kickoff tx not provided");
    let file = File::open(pre_kickoff_file.clone()).expect(&format!("fail to open {:?}", pre_kickoff_file));
    let reader = BufReader::new(file);
    let pre_kickoff_tx: PreKickoffTransaction = serde_json::from_reader(reader).unwrap();
    let pre_kickoff_txid = pre_kickoff_tx.tx().compute_txid();

    println!("\nloading operator wots public-keys...");
    assert!(file_exists(&conf.general.operator_wots_pubkey_file), "operator wots public key not provided");
    let operator_wots_pubkeys = load_wots_pubkeys(&conf.general.operator_wots_pubkey_file);
    let kickoff_wots_commitment_keys = CommitmentMessageId::pubkey_map_for_kickoff(&operator_wots_pubkeys.0);
    let (connector_e1_commitment_public_keys, connector_e2_commitment_public_keys) = split_pubkeys(&operator_wots_pubkeys.1);
    let assert_commitment_public_keys = merge_to_connector_c_commits_public_key(
        &connector_e1_commitment_public_keys,
        &connector_e2_commitment_public_keys,
    );

    println!("\nloading disprove scripts...");
    assert!(file_exists(&conf.general.disprove_scripts_file), "disprove scripts not provided");
    let disprove_scripts_bytes = load_scripts_bytes_from_file(&conf.general.disprove_scripts_file);

    // kickoff
    println!("\ngenerating kickoff tx...");
    let connector_3 = Connector3::new(
        network,
        &operator_pubkey,
    );
    let connector_6 = Connector6::new(
        network,
        &operator_taproot_pubkey,
        &kickoff_wots_commitment_keys,
    );
    let connector_a = ConnectorA::new(
        network,
        &operator_taproot_pubkey,
        &federation_taproot_pubkey,
    );
    let connector_b = ConnectorB::new(
        network,
        &operator_taproot_pubkey,
    );
    let kickoff_input_0_vout: usize = 0;
    let kickoff_input_0 = Input {
        outpoint: OutPoint {
            txid: pre_kickoff_txid,
            vout: kickoff_input_0_vout as u32,
        },
        amount: pre_kickoff_tx.tx().output[kickoff_input_0_vout].value,
    };
    let kickoff_tx = KickOffTransaction::new_for_validation(
        &connector_3,
        &connector_6,
        &connector_a,
        &connector_b,
        kickoff_input_0,
    );
    let kickoff_tx_bytes = serde_json::to_vec_pretty(&kickoff_tx).unwrap();
    let kickoff_tx_file = format!("{}{}", &conf.general.txns_dir, KICKOFF_FILE_NAME);
    write_bytes_to_file(&kickoff_tx_bytes, &kickoff_tx_file);
    println!("kickoff_tx was written to {}", kickoff_tx_file);
    let kickoff_txid = kickoff_tx.tx().compute_txid();

    // take-1
    println!("\ngenerating take_1 tx...");
    let connector_0 = Connector0::new(
        network,
        &federation_taproot_pubkey,
    );
    let take1_input_0_vout: usize = 0;
    let take1_input_0 = Input {
        outpoint: OutPoint {
            txid: pegin_confirm_txid,
            vout: take1_input_0_vout as u32,
        },
        amount: pegin_confirm_tx.tx().output[take1_input_0_vout].value,
    };
    let take1_input_1_vout: usize = 0;
    let take1_input_1 = Input {
        outpoint: OutPoint {
            txid: kickoff_txid,
            vout: take1_input_1_vout as u32,
        },
        amount: kickoff_tx.tx().output[take1_input_1_vout].value,
    };
    let take1_input_2_vout: usize = 1;
    let take1_input_2 = Input {
        outpoint: OutPoint {
            txid: kickoff_txid,
            vout: take1_input_2_vout as u32,
        },
        amount: kickoff_tx.tx().output[take1_input_2_vout].value,
    };
    let take1_tx = Take1Transaction::new_for_validation(
        network,
        &operator_pubkey,
        &connector_0,
        &connector_3,
        &connector_a,
        take1_input_0,
        take1_input_1,
        take1_input_2,
    );
    let take1_tx_bytes = serde_json::to_vec_pretty(&take1_tx).unwrap();
    let take1_tx_file = format!("{}{}", &conf.general.txns_dir, TAKE1_FILE_NAME);
    write_bytes_to_file(&take1_tx_bytes, &take1_tx_file);
    println!("take1_tx was written to {}", take1_tx_file);

    // challenge
    println!("\ngenerating challenge tx...");
    let challenge_input_0_vout: usize = 1;
    let challenge_input_0 = Input {
        outpoint: OutPoint {
            txid: kickoff_txid,
            vout: challenge_input_0_vout as u32,
        },
        amount: kickoff_tx.tx().output[challenge_input_0_vout].value,
    };
    let challenge_tx = ChallengeTransaction::new_for_validation(
        network, 
        &operator_pubkey, 
        &connector_a, 
        challenge_input_0, 
        Amount::from_sat(CROWDFUNDING_AMOUNT),
    );
    let challenge_tx_bytes = serde_json::to_vec_pretty(&challenge_tx).unwrap();
    let challenge_tx_file = format!("{}{}", &conf.general.txns_dir, CHALLENGE_FILE_NAME);
    write_bytes_to_file(&challenge_tx_bytes, &challenge_tx_file);
    println!("challenge_tx was written to {}", challenge_tx_file);

    // assert-initial
    println!("\ngenerating assert-initial tx...");
    let connector_d = ConnectorD::new(
        network,
        &federation_taproot_pubkey,
    );
    let assert_commit1_connectors_e = AssertCommit1ConnectorsE {
        connectors_e: connector_e1_commitment_public_keys
            .iter()
            .map(|x| {
                ConnectorE::new(
                    network,
                    &operator_pubkey,
                    x,
                )
            })
            .collect(),
    };
    let assert_commit2_connectors_e = AssertCommit2ConnectorsE {
        connectors_e: connector_e2_commitment_public_keys
            .iter()
            .map(|x| {
                ConnectorE::new(
                    network,
                    &operator_pubkey,
                    x,
                )
            })
            .collect(),
    };
    let assert_init_input_0_vout: usize = 2;
    let assert_init_input_0 = Input {
        outpoint: OutPoint {
            txid: kickoff_txid,
            vout: assert_init_input_0_vout as u32,
        },
        amount: kickoff_tx.tx().output[assert_init_input_0_vout].value,
    };
    let assert_init_tx = AssertInitialTransaction::new_for_validation(
        &connector_b, 
        &connector_d, 
        &assert_commit1_connectors_e, 
        &assert_commit2_connectors_e, 
        assert_init_input_0,
    );
    let assert_init_tx_bytes = serde_json::to_vec_pretty(&assert_init_tx).unwrap();
    let assert_init_tx_file = format!("{}{}", &conf.general.txns_dir, ASSERT_INIT_FILE_NAME);
    write_bytes_to_file(&assert_init_tx_bytes, &assert_init_tx_file);
    println!("assert_init_tx was written to {}", assert_init_tx_file);
    let assert_init_txid = assert_init_tx.tx().compute_txid();

    // assert-commit1
    println!("\ngenerating assert-commit-1 tx...");
    let connector_f_1 = ConnectorF1::new(
        network,
        &operator_pubkey,
    );
    let vout_base: usize = 1;
    let assert_commit1_inputs = (0..assert_commit1_connectors_e.connectors_num())
        .map(|idx| Input {
            outpoint: OutPoint {
                txid: assert_init_txid,
                vout: (idx + vout_base) as u32,
            },
            amount: assert_init_tx.tx().output[idx + vout_base].value,
        })
        .collect();
    let assert_commit1_tx = AssertCommit1Transaction::new_for_validation(
        &assert_commit1_connectors_e, 
        &connector_f_1, 
        assert_commit1_inputs,
    );
    let assert_commit1_tx_bytes = serde_json::to_vec_pretty(&assert_commit1_tx).unwrap();
    let assert_commit1_tx_file = format!("{}{}", &conf.general.txns_dir, ASSERT_COMMIT_1_FILE_NAME);
    write_bytes_to_file(&assert_commit1_tx_bytes, &assert_commit1_tx_file);
    println!("assert_commit1_tx was written to {}", assert_commit1_tx_file);
    let assert_commit1_txid = assert_commit1_tx.tx().compute_txid();

    // assert-commit2
    println!("\ngenerating assert-commit-2 tx...");
    let connector_f_2 = ConnectorF2::new(
        network,
        &operator_pubkey,
    );
    let vout_base: usize = 1 + assert_commit1_connectors_e.connectors_num();
    let assert_commit2_inputs = (0..assert_commit2_connectors_e.connectors_num())
        .map(|idx| Input {
            outpoint: OutPoint {
                txid: assert_init_txid,
                vout: (idx + vout_base) as u32,
            },
            amount: assert_init_tx.tx().output[idx + vout_base].value,
        })
        .collect();
    let assert_commit2_tx = AssertCommit2Transaction::new_for_validation(
        &assert_commit2_connectors_e, 
        &connector_f_2, 
        assert_commit2_inputs,
    );
    let assert_commit2_tx_bytes = serde_json::to_vec_pretty(&assert_commit2_tx).unwrap();
    let assert_commit2_tx_file = format!("{}{}", &conf.general.txns_dir, ASSERT_COMMIT_2_FILE_NAME);
    write_bytes_to_file(&assert_commit2_tx_bytes, &assert_commit2_tx_file);
    println!("assert_commit2_tx was written to {}", assert_commit2_tx_file);
    let assert_commit2_txid = assert_commit2_tx.tx().compute_txid();

    // assert-final
    println!("\ngenerating assert-final tx...");
    let assert_commit_connectors_f = AssertCommitConnectorsF {connector_f_1,connector_f_2};
    let connector_4 = Connector4::new(
        network,
        &operator_pubkey,
    );
    let connector_5 = Connector5::new(
        network,
        &federation_taproot_pubkey,
    );
    let connector_c = ConnectorC::new_from_scripts(
        network,
        &operator_taproot_pubkey,
        assert_commitment_public_keys,
        disprove_scripts_bytes,
    );
    let assert_final_input_0_vout: usize = 0;
    let assert_final_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_init_txid,
            vout: assert_final_input_0_vout as u32,
        },
        amount: assert_init_tx.tx().output[assert_final_input_0_vout].value,
    };
    let assert_final_input_1_vout: usize = 0;
    let assert_final_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_commit1_txid,
            vout: assert_final_input_1_vout as u32,
        },
        amount: assert_commit1_tx.tx().output[assert_final_input_1_vout].value,
    };
    let assert_final_input_2_vout: usize = 0;
    let assert_final_input_2 = Input {
        outpoint: OutPoint {
            txid: assert_commit2_txid,
            vout: assert_final_input_2_vout as u32,
        },
        amount: assert_commit2_tx.tx().output[assert_final_input_2_vout].value,
    };
    let assert_final_tx = AssertFinalTransaction::new_for_validation(
        &connector_4, 
        &connector_5, 
        &connector_c, 
        &connector_d, 
        &assert_commit_connectors_f, 
        assert_final_input_0, 
        assert_final_input_1, 
        assert_final_input_2,
    );
    let assert_final_tx_bytes = serde_json::to_vec_pretty(&assert_final_tx).unwrap();
    let assert_final_tx_file = format!("{}{}", &conf.general.txns_dir, ASSERT_FINAL_FILE_NAME);
    write_bytes_to_file(&assert_final_tx_bytes, &assert_final_tx_file);
    println!("assert_final_tx was written to {}", assert_final_tx_file);
    let assert_final_txid = assert_final_tx.tx().compute_txid();

    // take-2
    println!("\ngenerating take-2 tx...");
    let take2_input_0_vout: usize = 0;
    let take2_input_0 = Input {
        outpoint: OutPoint {
            txid: pegin_confirm_txid,
            vout: take2_input_0_vout as u32,
        },
        amount: pegin_confirm_tx.tx().output[take2_input_0_vout].value,
    };
    let take2_input_1_vout: usize = 0;
    let take2_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout: take2_input_1_vout as u32,
        },
        amount: assert_final_tx.tx().output[take2_input_1_vout].value,
    };
    let take2_input_2_vout: usize = 1;
    let take2_input_2 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout: take2_input_2_vout as u32,
        },
        amount: assert_final_tx.tx().output[take2_input_2_vout].value,
    };
    let take2_input_3_vout: usize = 2;
    let take2_input_3 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout: take2_input_3_vout as u32,
        },
        amount: assert_final_tx.tx().output[take2_input_3_vout].value,
    };
    let take2_tx = Take2Transaction::new_for_validation(
        network, 
        &operator_pubkey, 
        &connector_0, 
        &connector_4, 
        &connector_5, 
        &connector_c, 
        take2_input_0, 
        take2_input_1, 
        take2_input_2, 
        take2_input_3,
    );
    let take2_tx_bytes = serde_json::to_vec_pretty(&take2_tx).unwrap();
    let take2_tx_file = format!("{}{}", &conf.general.txns_dir, TAKE2_FILE_NAME);
    write_bytes_to_file(&take2_tx_bytes, &take2_tx_file);
    println!("take2_tx was written to {}", take2_tx_file);

    // disprove
    println!("\ngenerating disprove tx...");
    let disprove_input_0_vout: usize = 1;
    let disprove_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout: disprove_input_0_vout as u32,
        },
        amount: assert_final_tx.tx().output[disprove_input_0_vout].value,
    };
    let disprove_input_1_vout: usize = 2;
    let disprove_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout: disprove_input_1_vout as u32,
        },
        amount: assert_final_tx.tx().output[disprove_input_1_vout].value,
    };
    let disprove_tx = DisproveTransaction::new_for_validation(
        network, 
        &connector_5, 
        &connector_c, 
        disprove_input_0, 
        disprove_input_1,
    );
    let disprove_tx_bytes = serde_json::to_vec_pretty(&disprove_tx).unwrap();
    let disprove_tx_file = format!("{}{}", &conf.general.txns_dir, DISPROVE_FILE_NAME);
    write_bytes_to_file(&disprove_tx_bytes, &disprove_tx_file);
    println!("disprove_tx was written to {}", disprove_tx_file);


}

pub(crate) fn handle_federation_presign(conf: Config) {
    println!("\nloading config...");
    let network = match_network(&conf.general.network).unwrap();

    let federation_taproot_pubkey = &conf.general.federation_taproot_pubkey.expect("federation_taproot_pubkey is not provided in the configuration file");
    let federation_taproot_pubkey = XOnlyPublicKey::from_str(federation_taproot_pubkey).expect("invalid federation_taproot_pubkey");
      
    let depositor_public_key = &conf.depositor.depositor_public_key.expect("depositor_public_key is not provided in the configuration file");
    let depositor_public_key = PublicKey::from_str(depositor_public_key).expect("invalid depositor_public_key");
    let depositor_taproot_public_key = XOnlyPublicKey::from(depositor_public_key);

    let federation_seckeys = &conf.federation.federation_seckeys.expect("federation_seckeys not provided");
    let federation_pubkeys: Vec<PublicKey> = federation_seckeys.iter()
        .map(|sec| {
            let (_,pubkey) = generate_keys_from_secret(network, sec);
            pubkey
        })
        .collect();

    let (_,aggregated_federation_taproot_pubkey) = generate_n_of_n_public_key(&federation_pubkeys);
    assert_eq!(aggregated_federation_taproot_pubkey, federation_taproot_pubkey, "federation_taproot_pubkey is not aggregated from federation_seckeys");
    
    let signer_contexts: Vec<VerifierContext> = federation_seckeys.iter()
        .map(|sec| {
            VerifierContext::new(network, sec, &federation_pubkeys)  
        })
        .collect();

    'pegin_confirm: {   // pegin-confirm pre-sign
        println!("\nloading pegin-confirm-tx...");
        let pegin_confirm_file = format!("{}{}", &conf.general.txns_dir, PEGIN_CONFIRM_FILE_NAME);
        assert!(file_exists(&pegin_confirm_file), "pegin-confirm tx not provided");
        let file = File::open(pegin_confirm_file.clone()).expect(&format!("fail to open {:?}", pegin_confirm_file));
        let reader = BufReader::new(file);
        let mut pegin_confirm_tx: PegInConfirmTransaction = serde_json::from_reader(reader).unwrap();
        if pegin_confirm_tx.musig2_signatures().len() != 0 {
            println!("pegin-confirm already pre-signed");
            break 'pegin_confirm;
        }
        println!("pre-signing pegin-confirm-tx...");
        let connector_z = ConnectorZ::new(
            network,
            &conf.depositor.depositor_evm_address.expect("depositor_evm_address is not provided in the configuration file"),
            &depositor_taproot_public_key,
            &federation_taproot_pubkey,
        );
        let pegin_confirm_sec_nonces: Vec<(&VerifierContext, HashMap<usize, SecNonce>)> = signer_contexts.iter()
            .map(|context| {
                (context, pegin_confirm_tx.push_nonces(&context))
            }).collect();
        for (context, sec_nonce_map) in pegin_confirm_sec_nonces {
            pegin_confirm_tx.pre_sign(context, &connector_z, &sec_nonce_map);
        };
        let pegin_confirm_tx_bytes = serde_json::to_vec_pretty(&pegin_confirm_tx).unwrap();
        write_bytes_to_file(&pegin_confirm_tx_bytes, &pegin_confirm_file);
        println!("pre-signed pegin_confirm_tx was written back to {}", pegin_confirm_file);
    }

    'take_1: {   // take-1 pre-sign
        println!("\nloading take1-tx...");
        let take1_file = format!("{}{}", &conf.general.txns_dir, TAKE1_FILE_NAME);
        assert!(file_exists(&take1_file), "take-1 tx not provided");
        let file = File::open(take1_file.clone()).expect(&format!("fail to open {:?}", take1_file));
        let reader = BufReader::new(file);
        let mut take1_tx: Take1Transaction = serde_json::from_reader(reader).unwrap();
        if take1_tx.musig2_signatures().len() != 0 {
            println!("take-1 already pre-signed");
            break 'take_1;
        }
        println!("pre-signing take1-tx...");
        let connector_0 = Connector0::new(
            network,
            &federation_taproot_pubkey,
        );
        let take1_sec_nonces: Vec<(&VerifierContext, HashMap<usize, SecNonce>)> = signer_contexts.iter()
            .map(|context| {
                (context, take1_tx.push_nonces(&context))
            }).collect();
        for (context, sec_nonce_map) in take1_sec_nonces {
            take1_tx.pre_sign(context, &connector_0, &sec_nonce_map);
        };
        let take1_tx_bytes = serde_json::to_vec_pretty(&take1_tx).unwrap();
        write_bytes_to_file(&take1_tx_bytes, &take1_file);
        println!("pre-signed take-1_tx was written back to {}", take1_file);
    }

    'assert_final: {   // assert-final pre-sign
        println!("\nloading assert-final-tx...");
        let assert_final_file = format!("{}{}", &conf.general.txns_dir, ASSERT_FINAL_FILE_NAME);
        assert!(file_exists(&assert_final_file), "assert-final tx not provided");
        let file = File::open(assert_final_file.clone()).expect(&format!("fail to open {:?}", assert_final_file));
        let reader = BufReader::new(file);
        let mut assert_final_tx: AssertFinalTransaction = serde_json::from_reader(reader).unwrap();
        if assert_final_tx.musig2_signatures().len() != 0 {
            println!("assert_final_tx already pre-signed");
            break 'assert_final;
        }
        println!("pre-signing assert-final-tx...");
        let connector_d = ConnectorD::new(
            network,
            &federation_taproot_pubkey,
        );
        let assert_final_sec_nonces: Vec<(&VerifierContext, HashMap<usize, SecNonce>)> = signer_contexts.iter()
            .map(|context| {
                (context, assert_final_tx.push_nonces(&context))
            }).collect();
        for (context, sec_nonce_map) in assert_final_sec_nonces {
            assert_final_tx.pre_sign(context, &connector_d, &sec_nonce_map);
        };
        let assert_final_tx_bytes = serde_json::to_vec_pretty(&assert_final_tx).unwrap();
        write_bytes_to_file(&assert_final_tx_bytes, &assert_final_file);
        println!("pre-signed assert-final-tx was written back to {}", assert_final_file);
    }

    'take_2: {   // take-2 pre-sign
        println!("\nloading take2-tx...");
        let take2_file = format!("{}{}", &conf.general.txns_dir, TAKE2_FILE_NAME);
        assert!(file_exists(&take2_file), "take-2 tx not provided");
        let file = File::open(take2_file.clone()).expect(&format!("fail to open {:?}", take2_file));
        let reader = BufReader::new(file);
        let mut take2_tx: Take2Transaction = serde_json::from_reader(reader).unwrap();
        if take2_tx.musig2_signatures().len() != 0 {
            println!("take2_tx already pre-signed");
            break 'take_2;
        }
        println!("pre-signing take2-tx...");
        let connector_0 = Connector0::new(
            network,
            &federation_taproot_pubkey,
        );
        let connector_5 = Connector5::new(
            network,
            &federation_taproot_pubkey,
        );
        let take2_sec_nonces: Vec<(&VerifierContext, HashMap<usize, SecNonce>)> = signer_contexts.iter()
            .map(|context| {
                (context, take2_tx.push_nonces(&context))
            }).collect();
        for (context, sec_nonce_map) in take2_sec_nonces {
            take2_tx.pre_sign(context, &connector_0, &connector_5, &sec_nonce_map);
        };
        let take2_tx_bytes = serde_json::to_vec_pretty(&take2_tx).unwrap();
        write_bytes_to_file(&take2_tx_bytes, &take2_file);
        println!("pre-signed take-2-tx was written back to {}", take2_file);
    }
}

pub(crate) fn handle_operator_presign(conf: Config) {
    println!("\nloading config...");
    let network = match_network(&conf.general.network).unwrap();
       
    let federation_taproot_pubkey = &conf.general.federation_taproot_pubkey.expect("federation_taproot_pubkey is not provided in the configuration file");
    let federation_taproot_pubkey = XOnlyPublicKey::from_str(federation_taproot_pubkey).expect("invalid federation_taproot_pubkey");
        
    let federation_pubkeys = conf.general.federation_pubkeys.expect("federation_pubkeys is not provided in the configuration file");
    let federation_pubkeys: Vec<PublicKey> = federation_pubkeys.into_iter()
        .map(|str| PublicKey::from_str(&str).expect("invalid depositor_public_key {str}"))
        .collect();

    let operator_seckey = &conf.operator.operator_seckey.expect("operator_seckey not provided");
    let operator_pubkey = &conf.general.operator_pubkey.expect("operator_pubkey is not provided in the configuration file");
    let operator_pubkey = PublicKey::from_str(operator_pubkey).expect("invalid operator_pubkey");
    let operator_taproot_pubkey = XOnlyPublicKey::from(operator_pubkey);
    let (_,pubkey_from_sec) = generate_keys_from_secret(network, operator_seckey);
    assert_eq!(pubkey_from_sec, operator_pubkey, "operatot_seckey & operator_pubkey not match");
    let operator_context = OperatorContext::new(network, operator_seckey, &federation_pubkeys);
    assert_eq!(operator_context.n_of_n_taproot_public_key, federation_taproot_pubkey, "federation_taproot_pubkey not aggregated from federation_pubkeys");

    'challenge: {   // challenge pre-sign
        println!("\nloading challenge-tx...");
        let challenge_file = format!("{}{}", &conf.general.txns_dir, CHALLENGE_FILE_NAME);
        assert!(file_exists(&challenge_file), "challenge tx not provided");
        let file = File::open(challenge_file.clone()).expect(&format!("fail to open {:?}", challenge_file));
        let reader = BufReader::new(file);
        let mut challenge_tx: ChallengeTransaction = serde_json::from_reader(reader).unwrap();
        if challenge_tx.tx().input[0].witness != Witness::default() {
            println!("challenge already pre-signed");
            break 'challenge;
        }
        println!("pre-signing challenge-tx...");
        let connector_a = ConnectorA::new(
            network,
            &operator_taproot_pubkey,
            &federation_taproot_pubkey,
        );
        challenge_tx.pre_sign(&operator_context, &connector_a);
        let challenge_tx_bytes = serde_json::to_vec_pretty(&challenge_tx).unwrap();
        write_bytes_to_file(&challenge_tx_bytes, &challenge_file);
        println!("challenge_tx was written to {}", challenge_file);
    }
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

