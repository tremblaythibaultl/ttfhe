pub fn encode(msg: u8) -> u32 {
    (msg as u32) << 28
}

pub fn decode(mu: u32) -> u8 {
    ((((mu >> 27) + 1) >> 1) % 16) as u8
}

pub fn decode_bootstrapped(mu: u32) -> u8 {
    if (mu >> 31) == 1 {
        decode(!mu) % 8
    } else {
        decode(mu) % 8
    }
}

pub fn round_value(val: u32) -> u32 {
    let mut rounded_val = val >> 19; // this should affect bootstrapping.
    rounded_val += rounded_val & 1;
    rounded_val >>= 1;
    rounded_val
}
