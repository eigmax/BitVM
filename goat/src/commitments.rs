use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, IntoEnumIterator};

use bitvm::{chunker::assigner::BridgeAssigner, signatures::signing_winternitz::WinternitzSecret};

use super::constants::EVM_TXID_LENGTH;

#[derive(
    Serialize, Deserialize, Eq, PartialEq, Hash, Clone, PartialOrd, Ord, Display, Debug, EnumIter,
)]
#[serde(into = "String", try_from = "String")]
pub enum CommitmentMessageId {
    EvmWithdrawTxid,
    // name of intermediate value and length of message
    Groth16IntermediateValues((String, usize)),
}

const VAL_SEPARATOR: char = '|';

impl From<CommitmentMessageId> for String {
    fn from(id: CommitmentMessageId) -> String {
        match id {
            CommitmentMessageId::Groth16IntermediateValues((variable_name, size)) => {
                format!(
                    "Groth16IntermediateValues{}{}{}{}",
                    VAL_SEPARATOR, variable_name, VAL_SEPARATOR, size
                )
            }
            _ => id.to_string(),
        }
    }
}

impl TryFrom<String> for CommitmentMessageId {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        for variant in CommitmentMessageId::iter() {
            if s == variant.to_string() {
                return Ok(variant);
            } else if s.starts_with(&format!("Groth16IntermediateValues{}", VAL_SEPARATOR)) {
                let parts: Vec<_> = s.split(VAL_SEPARATOR).collect();
                if parts.len() != 3 {
                    return Err(format!("Invalid Groth16IntermediateValues format: {}", s));
                }
                let variable_name = parts[1].to_string();
                let size = parts[2]
                    .parse::<usize>()
                    .map_err(|e| format!("Invalid size in Groth16IntermediateValues: {}", e))?;

                return Ok(CommitmentMessageId::Groth16IntermediateValues((
                    variable_name,
                    size,
                )));
            }
        }

        Err(format!("Unknown CommitmentMessageId: {}", s))
    }
}

impl CommitmentMessageId {
    // btree map is a copy of chunker related commitments
    pub fn generate_commitment_secrets() -> HashMap<CommitmentMessageId, WinternitzSecret> {
        let mut commitment_map = HashMap::from([
            (
                CommitmentMessageId::EvmWithdrawTxid,
                WinternitzSecret::new(EVM_TXID_LENGTH),
            ),
        ]);

        // maybe variable cache is more efficient
        let all_variables = BridgeAssigner::default().all_intermediate_variables();

        // split variable to different connectors
        for (v, size) in all_variables {
            commitment_map.insert(
                CommitmentMessageId::Groth16IntermediateValues((v, size)),
                WinternitzSecret::new(size),
            );
        }

        commitment_map
    }
}

