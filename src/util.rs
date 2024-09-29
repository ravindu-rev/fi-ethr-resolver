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
