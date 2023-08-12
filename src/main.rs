mod gsw;
mod lwe;

use rand::Rng;
pub const N: usize = 512;
pub const KEY_SIZE: usize = N / 8;
pub const P: u8 = 16;
pub const Q: u8 = 64;
pub const ELL: u8 = 2;
pub const SIGMA: f64 = 0.000000049029381729;

fn main() {
    let sk = keygen();
    let msg1 = 3;
    let msg2 = 3;
    let c1 = crate::gsw::encrypt(msg1, sk);
    let c2 = crate::lwe::encrypt(msg2, sk);
    let c3 = c1.external_product(c2);
    let c4 = c3.add(c2);
    let pt = decode(c4.decrypt(sk));
    println!("pt: {pt}");
}

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

#[test]
fn test_codec() {
    for i in 0..16 {
        assert!(i == decode(encode(i)));
    }
}

#[test]
fn test_approx_dec() {
    assert!(decode(17) == 4);
}

#[test]
fn test_add() {
    let sk: [u8; KEY_SIZE] = keygen();
    let pt1 = 2;
    let pt2 = 15;
    let c1 = lwe::encrypt(encode(pt1), sk);
    let c2 = lwe::encrypt(encode(pt2), sk);
    let c3 = c1.add(c2);
    let pt = decode(c3.decrypt(sk));
    assert!(pt == (pt1 + pt2) % P);
}
