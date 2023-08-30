pub mod ggsw;
pub mod glwe;
pub mod gsw;
pub mod lwe;
pub mod poly;

use rand::Rng;
pub const N: usize = 1024; // degree of irreducible polynomial P = X^N + 1
#[allow(non_upper_case_globals)]
pub const k: usize = 1;
pub const KEY_SIZE: usize = N / 8;
pub const ELL: u8 = 2;
pub const P: u8 = 16;
pub const Q: u8 = 64; // erroneous - used for testing purposes.
pub const SIGMA: f64 = 0.000000049029381729;

pub fn keygen() -> [u8; KEY_SIZE] {
    let mut sk = [0u8; KEY_SIZE];
    rand::thread_rng().fill(&mut sk);
    sk
}

pub fn encode(msg: u8) -> u8 {
    assert!(msg < P, "message out of plaintext space");
    msg * (Q / P)
}

pub fn decode(mu: u8) -> u8 {
    assert!(mu < Q, "invalid encoding");
    ((mu as u16 * P as u16) / Q as u16) as u8
}
