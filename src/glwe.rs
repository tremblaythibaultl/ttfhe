use crate::{k, poly::ResiduePoly, KEY_SIZE, N};
use rand::{random, thread_rng, Rng};
use rand_distr::{Distribution, Normal};

#[derive(Clone, Copy)]
pub struct GlweCiphertext {
    pub mask: [ResiduePoly; k], //todo: use Vec here
    pub body: ResiduePoly,
}

impl GlweCiphertext {
    pub fn encrypt(mu: u64, sk: [u8; KEY_SIZE]) -> GlweCiphertext {
        let sigma = f64::powf(2.0, 39.0);
        let normal = Normal::new(0.0, sigma).unwrap();

        let e = normal.sample(&mut rand::thread_rng()).round() as i64;
        let mu_star = mu.wrapping_add_signed(e);

        // mask
        let mut mask: [ResiduePoly; k] = Default::default();
        for i in 0..k {
            for j in 0..N {
                mask[i].coefs[j] = rand::random::<u64>();
            }
        }

        // optimized computation of the dot product for when k = 1
        let mut dot_prod = ResiduePoly::default();
        for i in 0..N / 8 {
            for j in 0..8 {
                if ((sk[i] >> j) & 1) == 1 {
                    dot_prod.coefs[i * 8 + j] += mask[0].coefs[i * 8 + j];
                }
            }
        }

        let body = dot_prod.add_constant(mu_star as u64);

        GlweCiphertext { mask, body }
    }

    pub fn decrypt(self, sk: [u8; KEY_SIZE]) -> u64 {
        // optimized computation of the dot product for when k = 1
        let mut dot_prod = ResiduePoly::default();
        for i in 0..N / 8 {
            for j in 0..8 {
                if ((sk[i] >> j) & 1) == 1 {
                    dot_prod.coefs[i * 8 + j] += self.mask[0].coefs[i * 8 + j];
                }
            }
        }

        let mu_star = self.body.sub(&dot_prod);
        mu_star.coefs[0]
    }

    fn add(self, rhs: Self) -> Self {
        let mut res = GlweCiphertext::default();
        for i in 0..k {
            res.mask[i] = self.mask[i].add(&rhs.mask[i]);
        }
        res.body = self.body.add(&rhs.body);
        res
    }
}

impl Default for GlweCiphertext {
    fn default() -> Self {
        GlweCiphertext {
            mask: [ResiduePoly::default()], // only works with k = 1
            body: ResiduePoly::default(),
        }
    }
}

pub fn encode(msg: u8) -> u64 {
    ((msg as u64) << 1) + 1 << 59 // msg * 2^59.5
}

pub fn decode(mu: u64) -> u8 {
    (mu >> 60) as u8
}

#[test]
fn test_keygen_enc_dec() {
    let sk = crate::keygen();
    for _ in 0..1000 {
        let msg = thread_rng().gen_range(0..15);
        let ct = GlweCiphertext::encrypt(encode(msg), sk);
        let pt = decode(ct.decrypt(sk));
        assert!(pt == msg);
    }
}

#[test]
fn test_add() {
    let sk = crate::keygen();
    let msg1 = 2;
    let msg2 = 9;
    let ct1 = GlweCiphertext::encrypt(encode(msg1), sk);
    let ct2 = GlweCiphertext::encrypt(encode(msg2), sk);
    let res = ct1.add(ct2);
    let pt = decode(res.decrypt(sk));
    assert!(pt == msg1 + msg2);
}
