use std::collections::HashMap;

pub const ECDSA_SECP256K1_RECOVERY_METHOD2020: &str = "EcdsaSecp256k1RecoveryMethod2020";
pub const ECDSA_SECP256K1_VERIFICATION_KEY2019: &str = "EcdsaSecp256k1VerificationKey2019";
pub const ED25519_VERIFICATION_KEY2018: &str = "Ed25519VerificationKey2018";
pub const RSA_VERIFICATION_KEY2018: &str = "RSAVerificationKey2018";
pub const X25519_KEY_AGREEMENT_KEY2019: &str = "X25519KeyAgreementKey2019";

pub fn get_legacy_algo() -> HashMap<&'static str, &'static str> {
    let mut map: HashMap<&str, &str> = HashMap::new();
    map.insert(
        "Secp256k1VerificationKey2018",
        ECDSA_SECP256K1_VERIFICATION_KEY2019,
    );
    map.insert(
        "Ed25519SignatureAuthentication2018",
        ED25519_VERIFICATION_KEY2018,
    );
    map.insert(
        "Secp256k1SignatureAuthentication2018",
        ECDSA_SECP256K1_VERIFICATION_KEY2019,
    );
    map.insert("RSAVerificationKey2018", RSA_VERIFICATION_KEY2018);
    map.insert("Ed25519VerificationKey2018", ED25519_VERIFICATION_KEY2018);
    map.insert("X25519KeyAgreementKey2019", X25519_KEY_AGREEMENT_KEY2019);

    map
}
