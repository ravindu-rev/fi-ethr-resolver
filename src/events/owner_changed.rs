use super::DiDEthrChangeEvent;
use crate::did::DidDoc;
use ethers::{
    contract::EthEvent,
    types::{Log, H160, H256, U256},
    utils::keccak256,
};
use fi_common::error::Error;

#[allow(dead_code)]
const EVENT_NAME: &str = "DIDOwnerChanged";

pub const DID_OWNER_CHANGED_TOPIC: &str = "DIDOwnerChanged(address,address,uint256)";

#[derive(Debug, Clone, EthEvent)]
#[ethevent(
    name = "DIDOwnerChanged",
    abi = "DIDOwnerChanged(address indexed identity, address owner, uint256 previousChange)"
)]
pub struct DIDOwnerChanged {
    pub identity: H160,
    pub owner: H160,
    pub previous_change: U256,
}

impl DiDEthrChangeEvent for DIDOwnerChanged {
    fn apply(&self, did_doc: &mut DidDoc) -> Result<(), Error> {
        let controller = format!("0x{}", hex::encode(self.owner.0));
        did_doc.delegate_count = did_doc.delegate_count + 1;
        did_doc.controller = Some(controller);
        Ok(())
    }

    fn is_event_of(topics: &Vec<H256>) -> bool {
        let hashed: H256 = keccak256(DID_OWNER_CHANGED_TOPIC).into();
        topics.iter().any(|topic| topic.eq(&hashed))
    }
}

impl From<Log> for DIDOwnerChanged {
    fn from(value: Log) -> Self {
        let event = DIDOwnerChanged::decode_log(&value.into());
        event.unwrap()
    }
}
