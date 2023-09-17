use std::num::Wrapping;

use crate::LWE_DIM;
use rand::{thread_rng, Rng};
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct LweCiphertext {
    #[serde(with = "BigArray")]
    pub mask: [u64; LWE_DIM],
    pub body: u64,
}

pub type LweSecretKey = [u64; LWE_DIM];

impl LweCiphertext {
    pub fn encrypt(mu: u64, sk: LweSecretKey) -> LweCiphertext {
        let sigma = f64::powf(2.0, 49.0);
        let normal = Normal::new(0.0, sigma).unwrap();

        let e = normal.sample(&mut rand::thread_rng()).round() as i64;
        let mu_star = mu.wrapping_add_signed(e);

        let mut mask = [0u64; LWE_DIM];
        for i in 0..LWE_DIM {
            mask[i] = rand::random::<u64>();
        }

        let mut body = mask
            .iter()
            .zip(sk.iter())
            .map(|(a_j, s_j)| a_j * s_j)
            .map(Wrapping)
            .sum::<Wrapping<u64>>();

        body += mu_star;

        LweCiphertext { mask, body: body.0 }
    }

    pub fn decrypt(self, sk: LweSecretKey) -> u64 {
        let body = self
            .mask
            .iter()
            .zip(sk.iter())
            .map(|(a_j, s_j)| a_j * s_j)
            .map(Wrapping)
            .sum::<Wrapping<u64>>();

        let mu_star = self.body.wrapping_sub(body.0);
        mu_star
    }

    pub fn add(self, rhs: Self) -> Self {
        let mut mask = [0u64; LWE_DIM];
        for i in 0..LWE_DIM {
            mask[i] = self.mask[i].wrapping_add(rhs.mask[i]);
        }

        let body = self.body.wrapping_add(rhs.body);

        LweCiphertext { mask, body }
    }

    pub fn sub(self, rhs: Self) -> Self {
        let mut mask = [0u64; LWE_DIM];
        for i in 0..LWE_DIM {
            mask[i] = self.mask[i].wrapping_sub(rhs.mask[i]);
        }

        let body = self.body.wrapping_sub(rhs.body);

        LweCiphertext { mask, body }
    }

    // switch from modulus 2^64 to 2N, with 2N = 2^11 when N = 1024
    pub fn modswitch(&self) -> Self {
        let mut mask = [0u64; LWE_DIM];
        for i in 0..LWE_DIM {
            mask[i] = ((self.mask[i] >> 52) + 1) >> 1;
        }

        let body = ((self.body >> 52) + 1) >> 1;

        LweCiphertext { mask, body }
    }
}

pub fn lwe_keygen() -> LweSecretKey {
    let mut sk = [0u64; LWE_DIM];
    for i in 0..LWE_DIM {
        sk[i] = thread_rng().gen_range(0..=1);
    }
    sk
}

pub fn encode(msg: u8) -> u64 {
    (msg as u64) << 60
}

pub fn decode(mu: u64) -> u8 {
    ((((mu >> 59) + 1) >> 1) % 16) as u8
}

pub fn decode_modswitched(mu: u64) -> u8 {
    ((((mu >> 6) + 1) >> 1) % 16) as u8
}

#[test]
fn test_keygen_enc_dec() {
    let sk = lwe_keygen();
    for _ in 0..100 {
        let msg = thread_rng().gen_range(0..16);
        let ct = LweCiphertext::encrypt(encode(msg), sk);
        let pt = decode(ct.decrypt(sk));
        assert_eq!(pt, msg);
    }
}

#[test]
fn test_add() {
    let sk = lwe_keygen();
    for _ in 0..100 {
        let msg1 = thread_rng().gen_range(0..16);
        let msg2 = thread_rng().gen_range(0..16);
        let ct1 = LweCiphertext::encrypt(encode(msg1), sk);
        let ct2 = LweCiphertext::encrypt(encode(msg2), sk);
        let res = ct1.add(ct2);
        let pt = decode(res.decrypt(sk));
        assert_eq!(pt, (msg1 + msg2) % 16);
    }
}

#[test]
fn test_sub() {
    let sk = lwe_keygen();
    for _ in 0..100 {
        let msg1 = thread_rng().gen_range(0..16);
        let msg2 = thread_rng().gen_range(0..16);
        let ct1 = LweCiphertext::encrypt(encode(msg1), sk);
        let ct2 = LweCiphertext::encrypt(encode(msg2), sk);
        let res = ct1.sub(ct2);
        let pt = decode(res.decrypt(sk));
        assert_eq!(pt, (msg1.wrapping_sub(msg2)) % 16);
    }
}

#[test]
fn test_modswitch() {
    for _ in 0..100 {
        let sk = lwe_keygen();
        let msg = thread_rng().gen_range(0..16);
        let ct = LweCiphertext::encrypt(encode(msg), sk);
        let modswitched = ct.modswitch();
        let pt = decode_modswitched(modswitched.decrypt(sk));
        assert_eq!(pt, msg);
    }
}
