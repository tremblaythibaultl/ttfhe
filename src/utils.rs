pub fn encode(msg: u8) -> u64 {
    (msg as u64) << 60
}

pub fn decode(mu: u64) -> u8 {
    ((((mu >> 59) + 1) >> 1) % 16) as u8
}

pub fn decode_bootstrapped(mu: u64) -> u8 {
    if (mu >> 63) == 1 {
        decode(!mu) % 8
    } else {
        decode(mu) % 8
    }
}

pub fn round_value(val: u64) -> u64 {
    let mut rounded_val = val >> 47;
    rounded_val += rounded_val & 1;
    rounded_val >>= 1;
    rounded_val
}
