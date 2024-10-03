use std::str::FromStr;

use super::DiDEthrChangeEvent;
use crate::{
    did::DidDoc,
    util::{encode_base58, encode_base64, remove_zero_bytes, strip0x},
    verification::LEGACY_ALGO_MAP,
};
use ethers::{
    contract::EthEvent,
    types::{Log, H160, H256, U256},
    utils::keccak256,
};
use fi_common::{did::Service, error::Error, keys::KeyPair};
use regex::Regex;
use serde_json::Value;

const EVENT_NAME: &str = "DIDAttributeChanged";

pub const DID_ATTRIBUTE_CHANGED_TOPIC: &str =
    "DIDAttributeChanged(address,bytes32,bytes,uint256,uint256)";

#[derive(Debug, Clone, EthEvent)]
#[ethevent(
    name = "DIDAttributeChanged",
    abi = "DIDAttributeChanged(address indexed identity, bytes32 name, bytes value, uint256 validTo, uint256 previousChange)"
)]
pub struct DIDAttributeChanged {
    pub identity: H160,
    pub name: [u8; 32],
    pub value: Vec<u8>,
    pub valid_to: U256,
    pub previous_change: U256,
}

impl DiDEthrChangeEvent for DIDAttributeChanged {
    fn apply(&self, did_doc: &mut DidDoc) -> Result<(), Error> {
        let name_iter: Vec<u8> = self.name.into_iter().filter(|x| *x != 0).collect();

        let name = String::from_utf8_lossy(&name_iter);

        let value = String::from_utf8_lossy(&self.value);

        let event_index = format!("{}-{}-{}", EVENT_NAME, name, value);

        let regex = match Regex::new("^did\\/(pub|svc)\\/(\\w+)(\\/(\\w+))?(\\/(\\w+))?$") {
            Ok(val) => val,
            Err(error) => {
                return Err(Error::new(error.to_string().as_str()));
            }
        };

        if regex.is_match(&name) {
            let matched = name.split("/").collect::<Vec<&str>>();

            let section = matched[1];
            let algorithm = matched[2];

            let did = did_doc.doc.id.clone();

            match section {
                "pub" => {
                    let _type = match matched[3] {
                        "sigAuth" => "SignatureAuthentication2018",
                        "veriKey" => "VerificationKey2018",
                        "enc" => "KeyAgreementKey2019",
                        _ => "",
                    };

                    did_doc.delegate_count = did_doc.delegate_count + 1;
                    let mut pk = KeyPair {
                        id: Some(format!("{}#delegate-{}", did, did_doc.delegate_count)),
                        _type: format!("{}{}", algorithm, _type),
                        controller: Some(did),
                        blockchain_account_id: None,
                        public_key_base58: None,
                        public_key_base64: None,
                        public_key_hex: None,
                        public_key_pem: None,
                        value: None,
                        context: None,
                        private_key_base58: None,
                        private_key_base64: None,
                        private_key_hex: None,
                        private_key_multibase: None,
                        private_key_pem: None,
                        public_key_multibase: None,
                        revoked: Some(false),
                    };

                    pk._type = match LEGACY_ALGO_MAP.contains_key(&pk._type) {
                        true => String::from(*LEGACY_ALGO_MAP.get(&pk._type).unwrap()),
                        false => String::from(algorithm),
                    };

                    let encoding = matched[4];
                    match encoding {
                        "hex" => pk.public_key_hex = Some(hex::encode(strip0x(value.to_string()))),
                        "base64" => pk.public_key_base64 = Some(encode_base64(value.to_string())),
                        "base58" => pk.public_key_base58 = Some(encode_base58(value.to_string())),
                        "pem" => {
                            pk.public_key_pem = Some(match remove_zero_bytes(value.to_string()) {
                                Ok(val) => val,
                                Err(error) => return Err(Error::new(error.to_string().as_str())),
                            })
                        }
                        _ => pk.value = Some(strip0x(value.to_string())),
                    }

                    did_doc.pks.insert(event_index.clone(), pk.clone());

                    match matched[4] {
                        "sigAuth" => {
                            did_doc
                                .auth
                                .insert(event_index.clone(), pk.id.clone().unwrap());
                            did_doc.signing_refs.insert(event_index, pk.id.unwrap());
                        }
                        "veriKey" => {
                            did_doc.key_agreement_refs.insert(event_index, pk);
                        }
                        _ => {
                            did_doc.signing_refs.insert(event_index, pk.id.unwrap());
                        }
                    }
                }
                "svc" => {
                    did_doc.service_count = did_doc.service_count + 1;

                    let value = match String::from_utf8(self.value.clone()) {
                        Ok(val) => val,
                        Err(error) => {
                            return Err(Error::new(error.to_string().as_str()));
                        }
                    };

                    let service_endpoint_result = Value::from_str(value.as_str());

                    let service = Service {
                        id: format!("{}#service-{}", did, did_doc.service_count),
                        _type: String::from(algorithm),
                        service_endpoint: match service_endpoint_result.is_ok() {
                            true => service_endpoint_result.unwrap(),
                            false => serde_json::Value::String(value),
                        },
                    };

                    did_doc.services.insert(event_index, service);
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn is_event_of(topics: &Vec<H256>) -> bool {
        let hashed: H256 = keccak256(DID_ATTRIBUTE_CHANGED_TOPIC).into();
        topics.iter().any(|topic| topic.eq(&hashed))
    }
}

impl From<Log> for DIDAttributeChanged {
    fn from(value: Log) -> Self {
        let event = DIDAttributeChanged::decode_log(&value.into());
        event.unwrap()
    }
}
