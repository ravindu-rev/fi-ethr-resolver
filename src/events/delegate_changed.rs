use super::DiDEthrChangeEvent;
use crate::{did::DidDoc, verification::ECDSA_SECP256K1_RECOVERY_METHOD2020};
use ethers::{
    contract::EthEvent,
    types::{Log, H160, H256, U256},
    utils::keccak256,
};
use fi_common::{error::Error, keys::KeyPair};

const EVENT_NAME: &str = "DIDDelegateChanged";

pub const DID_DELEGATE_CHANGED_TOPIC: &str =
    "DIDDelegateChanged(address,bytes32,bytes32,address,uint256,uint256)";

#[derive(Debug, Clone, EthEvent)]
#[ethevent(
    name = "DIDDelegateChanged",
    abi = "DIDDelegateChanged(address indexed identity, bytes32 delegateType, bytes32 name, address delegate, uint256 validTo, uint256 previousChange)"
)]
pub struct DIDDelegateChanged {
    pub identity: H160,
    pub delegate_type: [u8; 32],
    pub name: [u8; 32],
    pub delegate: H160,
    pub valid_to: U256,
    pub previous_change: U256,
}

impl DiDEthrChangeEvent for DIDDelegateChanged {
    fn apply(&self, did_doc: &mut DidDoc) -> Result<(), Error> {
        did_doc.delegate_count = did_doc.delegate_count + 1;

        let delegate_type =
            match String::from_utf8(self.delegate_type.into_iter().filter(|x| *x != 0).collect()) {
                Ok(val) => val,
                Err(error) => {
                    return Err(Error::new(error.to_string().as_str()));
                }
            };

        let delegate =
            match String::from_utf8(self.delegate.0.into_iter().filter(|x| *x != 0).collect()) {
                Ok(val) => val,
                Err(error) => {
                    return Err(Error::new(error.to_string().as_str()));
                }
            };

        let event_index = format!("{}-{}-{}", EVENT_NAME, delegate_type, delegate);

        let did = did_doc.doc.id.clone();

        let del_str = format!("{}#delegate-{}", did, did_doc.delegate_count);

        match delegate_type.as_str() {
            "sigAuth" => {
                did_doc.auth.insert(event_index.clone(), del_str.clone());
                did_doc.signing_refs.insert(event_index, del_str);
            }
            "veriKey" => {
                did_doc.pks.insert(
                    event_index.clone(),
                    KeyPair {
                        _type: String::from(ECDSA_SECP256K1_RECOVERY_METHOD2020),
                        controller: Some(did.clone()),
                        id: Some(del_str.clone()),
                        blockchain_account_id: Some(format!(
                            "eip155:{}:{}",
                            did_doc.chain_id.unwrap(),
                            delegate
                        )),
                        public_key_base58: None,
                        public_key_base64: None,
                        public_key_hex: None,
                        public_key_pem: None,
                        value: None,
                        private_key_base58: None,
                        context: None,
                        private_key_base64: None,
                        private_key_hex: None,
                        private_key_multibase: None,
                        private_key_pem: None,
                        public_key_multibase: None,
                        revoked: Some(false),
                        ethereum_address: None,
                        public_key_jwk: None,
                    },
                );
                did_doc.signing_refs.insert(event_index, del_str);
            }
            _ => {}
        };

        Ok(())
    }

    fn is_event_of(topics: &Vec<H256>) -> bool {
        let hashed: H256 = keccak256(DID_DELEGATE_CHANGED_TOPIC).into();
        topics.iter().any(|topic| topic.eq(&hashed))
    }
}

impl From<Log> for DIDDelegateChanged {
    fn from(value: Log) -> Self {
        let event = DIDDelegateChanged::decode_log(&value.into());
        event.unwrap()
    }
}
