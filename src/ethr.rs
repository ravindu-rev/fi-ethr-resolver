use ethers::providers::{Http, Middleware, Provider};
use ethers::types::{Address, BlockNumber, Filter, Log};
use fi_common::did::DidDocument;
use fi_common::error::Error;
use std::{sync::Arc, time::Duration};

use crate::did::DidDoc;
use crate::events::attribute_changed::{DIDAttributeChanged, DID_ATTRIBUTE_CHANGED_TOPIC};
use crate::events::delegate_changed::{DIDDelegateChanged, DID_DELEGATE_CHANGED_TOPIC};
use crate::events::owner_changed::{DIDOwnerChanged, DID_OWNER_CHANGED_TOPIC};
use crate::events::DiDEthrChangeEvent;

pub async fn build_did_doc_from_logs(
    provider_url: &str,
    contract_address: &str,
    did_doc: &mut DidDocument,
) -> Result<(DidDocument, bool, Option<u64>), Error> {
    let provider_result = Provider::<Http>::try_from(provider_url);
    let provider = match provider_result {
        Ok(val) => val.interval(Duration::from_secs(2)),
        Err(error) => {
            return Err(Error::new(error.to_string().as_str()));
        }
    };

    let client: Arc<Provider<Http>> = Arc::new(provider);

    let contract_address = contract_address.parse::<Address>().unwrap();

    let mut block = BlockNumber::Earliest;
    let end_block = match client.get_block_number().await {
        Ok(val) => BlockNumber::from(val),
        Err(error) => return Err(Error::new(error.to_string().as_str())),
    };
    let block_range = 10000000;

    let mut did = DidDoc::new(did_doc, false, None);

    let event_topics = [
        DID_ATTRIBUTE_CHANGED_TOPIC,
        DID_DELEGATE_CHANGED_TOPIC,
        DID_OWNER_CHANGED_TOPIC,
    ];

    match did.chain_id_add(&client).await {
        Ok(_val) => {}
        Err(error) => return Err(error),
    }

    while block.is_earliest() || block.as_number().unwrap() < end_block.as_number().unwrap() {
        println!("1 {:#?}", block);
        let range_end_block = match block.is_earliest() {
            true => BlockNumber::from(block_range),
            false => BlockNumber::from(block.as_number().unwrap() + block_range),
        };

        let filter = Filter::new()
            .address(ethers::types::ValueOrArray::Value(contract_address))
            .events(event_topics)
            .from_block(block)
            .to_block(range_end_block);

        let logs = match client.get_logs(&filter).await {
            Ok(val) => val,
            Err(error) => {
                return Err(Error::new(error.to_string().as_str()));
            }
        };

        if block.is_earliest() && logs.is_empty() {
            block = BlockNumber::from(block_range);
        }

        let prev_block = block.clone();
        println!("len {}", logs.len());

        for log in logs {
            did.version_id = match log.block_number {
                Some(val) => Some(val.0[0]),
                None => None,
            };

            match apply_change_to_did(&mut did, log) {
                Ok(_val) => {}
                Err(error) => return Err(error),
            };

            match did.version_id {
                Some(val) => {
                    block = BlockNumber::from(val);
                }
                None => {}
            }
        }

        block = match prev_block.eq(&block) {
            true => BlockNumber::from(block.as_number().unwrap() + block_range),
            false => BlockNumber::from(block.as_number().unwrap() + 1),
        };
    }

    println!("{:#?}", block);
    println!("latest {:#?}", end_block);

    did.finalize()
}

fn apply_change_to_did(did_doc: &mut DidDoc, log: Log) -> Result<(), Error> {
    let topics = log.topics.clone();

    let event: Box<dyn DiDEthrChangeEvent>;

    if DIDAttributeChanged::is_event_of(&topics) {
        let val = DIDAttributeChanged::from(log);
        event = Box::new(val);
    } else if DIDDelegateChanged::is_event_of(&topics) {
        let val = DIDDelegateChanged::from(log);
        event = Box::new(val);
    } else if DIDOwnerChanged::is_event_of(&topics) {
        let val = DIDOwnerChanged::from(log);
        event = Box::new(val);
    } else {
        return Err(Error::new("Topic can't be identified"));
    }

    event.apply(did_doc)
}
