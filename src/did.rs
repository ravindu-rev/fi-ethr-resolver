use ethers::providers::{Http, Middleware, Provider};
use ethers::types::U256;
use fi_common::did::Service;
use fi_common::error::Error;
use fi_common::{did::DidDocument, keys::KeyPair};
use std::collections::HashMap;
use std::sync::Arc;

use crate::util::{get_public_key, strip0x};
use crate::verification::{
    ECDSA_SECP256K1_RECOVERY_METHOD2020, ECDSA_SECP256K1_VERIFICATION_KEY2019,
};

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

        match get_public_key(self.doc.id.clone()) {
            Some(controller_key_val) => {
                let did = String::from(self.doc.id.clone().split("?").collect::<Vec<&str>>()[0]);

                let components = did.split(":").collect::<Vec<&str>>();
                let address: String = String::from(components[components.len() - 1]);
                if self
                    .controller
                    .clone()
                    .is_some_and(|controller| controller.eq(&address))
                {
                    let controller_key = KeyPair {
                        _type: String::from(ECDSA_SECP256K1_VERIFICATION_KEY2019),
                        blockchain_account_id: None,
                        id: Some(format!("{}#controllerKey", self.doc.id.clone())),
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
                        private_key_hex: Some(strip0x(controller_key_val)),
                        private_key_base64: None,
                        private_key_pem: None,
                        value: None,
                    };

                    public_keys.push(controller_key);
                    self.doc
                        .authentication
                        .push(format!("{}#controllerKey", self.doc.id.clone()));
                    self.doc
                        .assertion_method
                        .push(format!("{}#controllerKey", self.doc.id.clone()));
                }
            }
            None => {}
        };

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
