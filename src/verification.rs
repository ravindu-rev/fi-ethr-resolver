use phf::{phf_map, Map};

pub const ECDSA_SECP256K1_RECOVERY_METHOD2020: &str = "EcdsaSecp256k1RecoveryMethod2020";
pub const ECDSA_SECP256K1_VERIFICATION_KEY2019: &str = "EcdsaSecp256k1VerificationKey2019";
pub const ED25519_VERIFICATION_KEY2018: &str = "Ed25519VerificationKey2018";
pub const RSA_VERIFICATION_KEY2018: &str = "RSAVerificationKey2018";
pub const X25519_KEY_AGREEMENT_KEY2019: &str = "X25519KeyAgreementKey2019";

pub const LEGACY_ALGO_MAP: Map<&str, &str> = phf_map! {
    "Secp256k1VerificationKey2018"=>
    ECDSA_SECP256K1_VERIFICATION_KEY2019,
    "Ed25519SignatureAuthentication2018"=>
    ED25519_VERIFICATION_KEY2018,
    "Secp256k1SignatureAuthentication2018"=>
    ECDSA_SECP256K1_VERIFICATION_KEY2019,
    "RSAVerificationKey2018"=>
    RSA_VERIFICATION_KEY2018 ,
    "Ed25519VerificationKey2018"=>
    ED25519_VERIFICATION_KEY2018 ,
    "X25519KeyAgreementKey2019"=>
    X25519_KEY_AGREEMENT_KEY2019 ,
};
