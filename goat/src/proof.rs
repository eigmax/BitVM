use bitvm::chunk::api::type_conversion_utils::RawProof;
use ark_bn254::Bn254;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};

// TODO
pub fn get_proof() -> RawProof { 
    RawProof::default()
}

pub fn serialize_proof(proof: ark_groth16::Proof<Bn254>) -> Vec<u8> {
    let mut proof_sered = vec![0; proof.serialized_size(Compress::Yes)];
    proof.serialize_with_mode(&mut proof_sered[..], Compress::Yes).expect("fail to serialize proof");
    proof_sered
}
pub fn serialize_vk(vk: ark_groth16::VerifyingKey<Bn254>) -> Vec<u8> {
    let mut vk_sered = vec![0; vk.serialized_size(Compress::Yes)];
    vk.serialize_with_mode(&mut vk_sered[..], Compress::Yes).expect("fail to serialize vk");
    vk_sered
}
pub fn serialize_pubin(pubin: Vec<ark_bn254::Fr>) -> Vec<u8> {
    fn tmp_fr_serialization(f: ark_bn254::Fr) -> Vec<u8> {
        use ark_ff::PrimeField;
        use ark_ff::BigInt;
    
        let f_big = match f.into_bigint() { BigInt(x) => x };
        let mut res = Vec::with_capacity(f_big.len() * 8);
        for &num in f_big.iter() {
            res.extend_from_slice(&num.to_le_bytes());
        }
        res
    }  

    let mut public_inputs_sered = Vec::new();
    for f in pubin {
        let f_sered = tmp_fr_serialization(f);
        public_inputs_sered.push(f_sered);
    }

    bincode::serialize(&public_inputs_sered).unwrap()
}
pub fn deserialize_proof(buffer: Vec<u8>) -> ark_groth16::Proof<Bn254> {
    ark_groth16::Proof::<Bn254>::deserialize_with_mode(buffer.as_slice(), Compress::Yes, Validate::Yes).unwrap()
}
pub fn deserialize_vk(buffer: Vec<u8>) -> ark_groth16::VerifyingKey<Bn254> {
    ark_groth16::VerifyingKey::<Bn254>::deserialize_with_mode(buffer.as_slice(), Compress::Yes, Validate::Yes).unwrap()
}
pub fn deserialize_pubin(buffer: Vec<u8>) -> Vec<ark_bn254::Fr> {
    fn tmp_fr_deserialization(v: Vec<u8>) -> ark_bn254::Fr {
        use ark_ff::PrimeField;
        use ark_ff::BigInt;
    
        let mut arr = [0u64; 4];
        for (i, chunk) in v.chunks(8).enumerate() {
            arr[i] = u64::from_le_bytes(chunk.try_into().expect("Invalid fr length"));
        }
        ark_bn254::Fr::from_bigint(BigInt(arr)).unwrap()
    }

    let buffer: Vec<Vec<u8>> = bincode::deserialize(&buffer).unwrap();
    let mut pubin= vec![];
    for i in 0..buffer.len() {
        let f = tmp_fr_deserialization(buffer[i].clone());
        pubin.push(f);
    }
    pubin
}


#[test]
fn read_bin() {
    let proof_file = "ark-bin/proof.bin";
    let vk_file = "ark-bin/vkey.bin";
    let pubin_file = "ark-bin/pubin.bin";

    let proof_bin = std::fs::read(proof_file).unwrap();
    let vk_bin = std::fs::read(vk_file).unwrap();
    let pubin_bin = std::fs::read(pubin_file).unwrap();

    let ark_proof = deserialize_proof(proof_bin);
    let ark_vkey = deserialize_vk(vk_bin);
    let ark_public_inputs = deserialize_pubin(pubin_bin);

    dbg!(&ark_proof);
    dbg!(&ark_vkey);
    dbg!(&ark_public_inputs);

    use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
    let ok = Groth16::<Bn254, LibsnarkReduction>::verify_proof(&ark_vkey.into(), &ark_proof, &ark_public_inputs)
    .unwrap();
    assert!(ok);
}