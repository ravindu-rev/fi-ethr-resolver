use ethers::providers::{Http, Middleware, Provider};
use ethers::types::U256;
use fi_common::did::Service;
use fi_common::error::Error;
use fi_common::{did::DidDocument, keys::KeyPair};
use std::collections::HashMap;
use std::sync::Arc;

use crate::verification::ECDSA_SECP256K1_RECOVERY_METHOD2020;

pub struct DidDoc {
    pub doc: DidDocument,
    pub deactivated: bool,
    pub controller: Option<String>,
    pub version_id: Option<u64>,
    pub delegate_count: u32,
    pub service_count: u32,
    pub auth: HashMap<String, String>,
    pub key_agreement_refs: HashMap<String, KeyPair>,
    pub signing_refs: HashMap<String, String>,
    pub pks: HashMap<String, KeyPair>,
    pub services: HashMap<String, Service>,
    pub chain_id: Option<U256>,
}

impl DidDoc {
    pub fn new(doc: &DidDocument, deactivated: bool, controller: Option<String>) -> DidDoc {
        DidDoc {
            doc: doc.clone(),
            deactivated,
            controller,
            version_id: None,
            delegate_count: 0,
            service_count: 0,
            auth: HashMap::new(),
            key_agreement_refs: HashMap::new(),
            signing_refs: HashMap::new(),
            pks: HashMap::new(),
            services: HashMap::new(),
            chain_id: None,
        }
    }

    pub fn finalize(&mut self) -> Result<(DidDocument, bool, Option<u64>), Error> {
        let mut public_keys = vec![KeyPair {
            _type: String::from(ECDSA_SECP256K1_RECOVERY_METHOD2020),
            blockchain_account_id: Some(format!(
                "eip155:{}:{}",
                match self.chain_id.clone() {
                    Some(val) => val.to_string(),
                    None => String::from(""),
                },
                match self.controller.clone() {
                    Some(val) => val,
                    None => String::from(""),
                }
            )),
            id: Some(format!("{}#controller", self.doc.id.clone())),
            context: None,
            public_key_base58: None,
            private_key_base58: None,
            public_key_multibase: None,
            private_key_multibase: None,
            revoked: false,
            controller: Some(self.doc.id.clone()),
            public_key_hex: None,
            public_key_base64: None,
            public_key_pem: None,
            private_key_hex: None,
            private_key_base64: None,
            private_key_pem: None,
            value: None,
        }];

        self.doc
            .authentication
            .push(format!("{}#controller", self.doc.id.clone()));
        self.doc
            .assertion_method
            .push(format!("{}#controller", self.doc.id.clone()));

        // Add controller key

        let mut signing_refs = self
            .signing_refs
            .clone()
            .into_values()
            .collect::<Vec<String>>();
        self.doc.assertion_method.append(&mut signing_refs);

        let mut authentication = self.auth.clone().into_values().collect::<Vec<String>>();
        self.doc.authentication.append(&mut authentication);

        let mut verification_method = self.pks.clone().into_values().collect::<Vec<KeyPair>>();
        self.doc.verification_method.append(&mut public_keys);
        self.doc
            .verification_method
            .append(&mut verification_method);

        if self.services.len() > 0 {
            let mut services = self
                .services
                .clone()
                .into_values()
                .collect::<Vec<Service>>();
            self.doc.services.append(&mut services);
        }

        if self.key_agreement_refs.len() > 0 {
            let mut key_agreement_refs = self
                .key_agreement_refs
                .clone()
                .into_values()
                .collect::<Vec<KeyPair>>();
            self.doc.key_agreement.append(&mut key_agreement_refs);
        }

        Ok((
            match self.deactivated {
                true => DidDocument {
                    context: Vec::new(),
                    id: self.doc.id.clone(),
                    verification_method,
                    authentication,
                    assertion_method: Vec::new(),
                    capability_delegation: Vec::new(),
                    capability_invocation: Vec::new(),
                    key_agreement: Vec::new(),
                    services: Vec::new(),
                },
                false => self.doc.clone(),
            },
            self.deactivated,
            self.version_id,
        ))
    }

    pub async fn chain_id_add(&mut self, client: &Arc<Provider<Http>>) -> Result<(), Error> {
        if self.chain_id.is_none() {
            let chain_id_result = client.get_chainid().await;

            let chain_id = match chain_id_result {
                Ok(val) => val,
                Err(error) => return Err(Error::new(error.to_string().as_str())),
            };

            self.chain_id = Some(chain_id);
        }
        Ok(())
    }
}
