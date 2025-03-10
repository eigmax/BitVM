use crate::config::Config;
use crate::files::{
    file_exists, load_groth16_vk, 
    load_wots_pubkeys, load_scripts_from_file, write_scripts_to_file,
    write_wots_seckeys, write_wots_pubkeys,
};
use crate::files::WotsSecretKeys;
use bitvm::chunk::api::{
    NUM_U256, NUM_U160, NUM_PUBS, PublicKeys as WotsPublicKeys,
    api_generate_partial_script, api_generate_full_tapscripts,
};
use bitvm::signatures::wots_api::{wots256, wots160};
use sha2::{Sha256, Digest};

pub(crate) fn handle_generate_disprove_scripts(conf: Config) {
    let ark_vkey = load_groth16_vk(&conf.general.vkey_file);
    let pubkeys = load_wots_pubkeys(&conf.general.operator_wots_pubkey_file);

    let partial_scripts = if file_exists(&conf.general.partial_scripts_file) {
        println!("use existing partial scripts from {:?}", &conf.general.partial_scripts_file);
        load_scripts_from_file(&conf.general.partial_scripts_file)
    } else {
        let scrs = api_generate_partial_script(&ark_vkey);
        write_scripts_to_file(&conf.general.partial_scripts_file, scrs.clone());
        println!("partial scripts was written to {:?}", &conf.general.partial_scripts_file);
        scrs
    };

    let disprove_scripts = api_generate_full_tapscripts(pubkeys, &partial_scripts);
    write_scripts_to_file(&conf.general.disprove_scripts_file, disprove_scripts);
    println!("disprove scripts was written to {:?}", &conf.general.disprove_scripts_file);
} 

pub(crate) fn handle_generate_wots_keys(conf: Config, seed: &str) {
    let secrets = seed_to_secrets(seed);
    let pubkeys = secrets_to_pubkeys(&secrets);
    write_wots_seckeys(&conf.operator.operator_wots_seckey_file, secrets);
    write_wots_pubkeys(&conf.general.operator_wots_pubkey_file, pubkeys);
    println!(
        "public keys was written to {:?}\nsecret was keys written to {:?}",
        &conf.general.operator_wots_pubkey_file,
        &conf.operator.operator_wots_seckey_file,
    )
}

pub(crate) fn secrets_to_pubkeys(secrets: &WotsSecretKeys) -> WotsPublicKeys {
    let mut pubins = vec![];
        for i in 0..NUM_PUBS {
            pubins.push(wots256::generate_public_key(&secrets[i]));
        }
        let mut fq_arr = vec![];
        for i in 0..NUM_U256 {
            let p256 = wots256::generate_public_key(&secrets[i+NUM_PUBS]);
            fq_arr.push(p256);
        }
        let mut h_arr = vec![];
        for i in 0..NUM_U160 {
            let p160 = wots160::generate_public_key(&secrets[i+NUM_PUBS+NUM_U256]);
            h_arr.push(p160);
        }
        let wotspubkey: WotsPublicKeys = (
            pubins.try_into().unwrap(),
            fq_arr.try_into().unwrap(),
            h_arr.try_into().unwrap(),
        );
        wotspubkey
}
pub(crate) fn seed_to_secrets(seed: &str) -> WotsSecretKeys {
    let seed_hash = sha256(seed);
    (0..NUM_PUBS+NUM_U256+NUM_U160)
        .map(|idx| {
            let sec_i = sha256_with_id(&seed_hash, idx);
            format!("{sec_i}{:04x}", idx)
        })
        .collect::<Vec<String>>()
        .try_into().unwrap()
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


