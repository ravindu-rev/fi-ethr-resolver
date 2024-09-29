use ethr::build_did_doc_from_logs;
use fi_common::{did::DidDocument, error::Error};
use regex::Regex;
use util::strip0x;

mod did;
mod ethr;
mod events;
mod util;
mod verification;

pub async fn resolve(did: &str, provider: &str, accept: &str) -> Result<DidDocument, Error> {
    let context: Vec<String> = match accept {
        "application/did+json" => Vec::new(),
        "application/did+ld+json" => Vec::from([
            String::from("https://www.w3.org/ns/did/v1"),
            String::from("https://w3id.org/security/suites/secp256k1recovery-2020/v2"),
            String::from("https://w3id.org/security/v3-unstable"),
        ]),
        _ => {
            return Err(Error::new(
                format!(
                    "The DID resolver does not support the requested 'accept' format: {}",
                    accept
                )
                .as_str(),
            ))
        }
    };

    let regex = match Regex::new("^(.*)?(0x[0-9a-fA-F]{40}|0x[0-9a-fA-F]{66})$") {
        Ok(val) => val,
        Err(error) => return Err(Error::new(error.to_string().as_str())),
    };

    if !regex.is_match(did) {
        return Err(Error::new(
            format!("Not a valid did:ethr: {}", did).as_str(),
        ));
    }

    let did_components = did.split(":").collect::<Vec<&str>>();
    /*
    let network = match did_components.len() >= 4 {
        true => did_components[2..did_components.len() - 1].join(":"),
        false => String::from(""),
    };
    */

    let contract_address = strip0x(String::from(*did_components.last().unwrap()));

    let mut did_doc = DidDocument {
        context,
        id: String::from(did),
        verification_method: Vec::new(),
        authentication: Vec::new(),
        assertion_method: Vec::new(),
        capability_delegation: Vec::new(),
        capability_invocation: Vec::new(),
        key_agreement: Vec::new(),
        services: Vec::new(),
    };

    let (created_did_doc, _deactivated, _version_id) =
        match build_did_doc_from_logs(provider, contract_address.as_str(), &mut did_doc).await {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

    Ok(created_did_doc)
}
