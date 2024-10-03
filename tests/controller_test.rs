use fi_common::did::DidDocument;
use fi_ethr_resolver::resolve;
use serde_json::json;

#[tokio::test]
pub async fn d() {
    let did = "did:ethr:mainnet:0xdca7ef03e98e0dc2b855be647c39abe984fcf21b";
    let did_doc = match resolve(
        did,
        "https://mainnet.infura.io/v3/f2bba3f37f194541b054b2a14d6719ef",
        "application/did+ld+json",
    )
    .await
    {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    let expected_value = match serde_json::from_value::<DidDocument>(json!({
      "id": "did:ethr:mainnet:0xdca7ef03e98e0dc2b855be647c39abe984fcf21b",
      "verificationMethod": [
        {
          "id": "did:ethr:mainnet:0xdca7ef03e98e0dc2b855be647c39abe984fcf21b#controller",
          "type": "EcdsaSecp256k1RecoveryMethod2020",
          "controller": "did:ethr:mainnet:0xdca7ef03e98e0dc2b855be647c39abe984fcf21b",
          "blockchainAccountId": "eip155:1:0xdca7ef03e98e0dc2b855be647c39abe984fcf21b",
          "revoked": false
        }
      ],
      "authentication": [
        "did:ethr:mainnet:0xdca7ef03e98e0dc2b855be647c39abe984fcf21b#controller"
      ],
      "assertionMethod": [
        "did:ethr:mainnet:0xdca7ef03e98e0dc2b855be647c39abe984fcf21b#controller"
      ],
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/secp256k1recovery-2020/v2",
        "https://w3id.org/security/v3-unstable"
      ],
      "keyAgreement":[],
      "services":[]
    })) {
        Ok(val) => match serde_json::to_value(&val) {
            Ok(v) => v,
            Err(error) => {
                eprintln!("{}", error);
                assert!(false);
                return;
            }
        },
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    let did_doc_value = match serde_json::to_value(&did_doc) {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    assert_eq!(expected_value, did_doc_value);
}
