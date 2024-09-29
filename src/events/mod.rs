use crate::did::DidDoc;
use ethers::types::H256;
use fi_common::error::Error;

pub mod attribute_changed;
pub mod delegate_changed;
pub mod owner_changed;

pub trait DiDEthrChangeEvent {
    fn apply(&self, did_doc: &mut DidDoc) -> Result<(), Error>;
    fn is_event_of(topics: &Vec<H256>) -> bool
    where
        Self: Sized;
}
