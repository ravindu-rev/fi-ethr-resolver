use base64::Engine;

pub fn strip0x(value: String) -> String {
    if value.starts_with("0x") {
        String::from(&value[2..])
    } else {
        value
    }
}

pub fn remove_zero_bytes(value: String) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(
        value
            .as_bytes()
            .to_vec()
            .into_iter()
            .filter(|b| *b != 0)
            .collect::<Vec<u8>>(),
    )
}

pub fn encode_base64(value: String) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

pub fn encode_base58(value: String) -> String {
    bs58::encode(value).into_string()
}

pub fn get_public_key(identifier: String) -> Option<String> {
    if identifier.starts_with("did:ethr") {
        let did = String::from(identifier.split("?").collect::<Vec<&str>>()[0]);

        let components = did.split(":").collect::<Vec<&str>>();
        let id: String = String::from(components[components.len() - 1]);

        if id.len() > 42 {
            return Some(id);
        } else {
            return None;
        }
    }

    None
}
