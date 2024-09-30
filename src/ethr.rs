use ethers::abi::Abi;
use ethers::contract::Contract;
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::{Address, BlockNumber, Filter, Log, H160, U256, U64};
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
    address: &str,
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

    let contract_address = address.parse::<Address>().unwrap();

    let mut did = DidDoc::new(did_doc, false, Some(format!("0x{}", address)));

    match did.chain_id_add(&client).await {
        Ok(_val) => {}
        Err(error) => return Err(error),
    }

    let contract_abi = include_bytes!("contract-abi.json");
    let contract: ethers::contract::ContractInstance<Arc<Provider<Http>>, Provider<Http>> =
        Contract::new(
            contract_address,
            Abi::load(&contract_abi[..]).unwrap(),
            client.clone(),
        );

    let logs = match get_logs(contract, contract_address, client).await {
        Ok(val) => val,
        Err(error) => return Err(error),
    };

    for log in logs {
        did.version_id = match log.block_number {
            Some(val) => Some(val.0[0]),
            None => None,
        };

        if !log.address.eq(&contract_address) {
            continue;
        }

        match apply_change_to_did(&mut did, log) {
            Ok(_val) => {}
            Err(error) => return Err(error),
        };
    }

    did.finalize()
}

async fn get_logs(
    contract: ethers::contract::ContractInstance<Arc<Provider<Http>>, Provider<Http>>,
    contract_address: H160,
    client: Arc<Provider<Http>>,
) -> Result<Vec<Log>, Error> {
    let block_tag: Option<BlockNumber> = None;
    let mut event_log = Vec::<Log>::new();

    let mut previous_change_option =
        match get_previous_change(contract, contract_address, block_tag).await {
            Ok(val) => Some(val),
            Err(error) => return Err(error),
        };

    let event_topics = [
        DID_ATTRIBUTE_CHANGED_TOPIC,
        DID_DELEGATE_CHANGED_TOPIC,
        DID_OWNER_CHANGED_TOPIC,
    ];

    while previous_change_option.is_some() {
        let previous_change = previous_change_option.unwrap();

        let filter = Filter::new()
            .address(ethers::types::ValueOrArray::Value(contract_address))
            .events(event_topics)
            .from_block(BlockNumber::Number(previous_change.as_u64().into()))
            .to_block(BlockNumber::Number(previous_change.as_u64().into()));

        let mut logs = match client.get_logs(&filter).await {
            Ok(val) => val,
            Err(error) => {
                return Err(Error::new(error.to_string().as_str()));
            }
        };

        logs.reverse();
        previous_change_option = None;

        logs.iter().for_each(|log| {
            event_log.insert(0, log.clone());
            if log
                .block_number
                .is_some_and(|block_number| block_number.as_u64() < previous_change.as_u64())
            {
                previous_change_option = Some(log.block_number.unwrap().into());
            }
        });
    }

    Ok(event_log)
}

async fn get_previous_change(
    contract: ethers::contract::ContractInstance<Arc<Provider<Http>>, Provider<Http>>,
    address: H160,
    block_tag: Option<BlockNumber>,
) -> Result<U64, Error> {
    let call = match contract.method::<_, U256>("changed", address) {
        Ok(val) => {
            val.block(match block_tag {
                Some(val) => val,
                None => BlockNumber::Latest,
            })
            .call()
            .await
        }
        Err(error) => return Err(Error::new(error.to_string().as_str())),
    };

    match call {
        Ok(val) => Ok(val.as_u64().into()),
        Err(error) => return Err(Error::new(error.to_string().as_str())),
    }
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
