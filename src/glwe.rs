#[cfg(test)]
use crate::lwe::{decode, encode};
use crate::{k, poly::ResiduePoly, N};
use rand::{thread_rng, Rng};
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct GlweCiphertext {
    pub mask: [ResiduePoly; k],
    pub body: ResiduePoly,
}

// SecretKey is an array of `k` polynomials in {0, 1}[X]/X^N + 1 (i.e., of degree `N - 1` and with coefficients in {0, 1}).
#[derive(Clone, Copy)]
pub struct SecretKey {
    // TODO: use Vec
    pub polys: [ResiduePoly; k],
}

impl GlweCiphertext {
    pub fn encrypt(mu: u64, sk: SecretKey) -> GlweCiphertext {
        let sigma = f64::powf(2.0, 39.0);
        let normal = Normal::new(0.0, sigma).unwrap();

        let e = normal.sample(&mut rand::thread_rng()).round() as i64;
        let mu_star = mu.wrapping_add_signed(e);

        let mut mask: [ResiduePoly; k] = Default::default();
        for i in 0..k {
            for j in 0..N {
                mask[i].coefs[j] = rand::random::<u64>();
            }
        }

        let mut body = ResiduePoly::default();
        for i in 0..k {
            body.add_assign(&mask[i].mul(&sk.polys[i]));
        }

        body.add_constant_assign(mu_star as u64);

        GlweCiphertext { mask, body }
    }

    pub fn decrypt(self, sk: SecretKey) -> u64 {
        let mut body = ResiduePoly::default();
        for i in 0..k {
            body.add_assign(&self.mask[i].mul(&sk.polys[i]));
        }

        let mu_star = self.body.sub(&body);
        mu_star.coefs[0]
    }

    pub fn add(self, rhs: Self) -> Self {
        let mut res = GlweCiphertext::default();
        for i in 0..k {
            res.mask[i] = self.mask[i].add(&rhs.mask[i]);
        }
        res.body = self.body.add(&rhs.body);
        res
    }

    pub fn sub(self, rhs: Self) -> Self {
        let mut res = GlweCiphertext::default();
        for i in 0..k {
            res.mask[i] = self.mask[i].sub(&rhs.mask[i]);
        }
        res.body = self.body.sub(&rhs.body);
        res
    }
}

impl Default for GlweCiphertext {
    fn default() -> Self {
        GlweCiphertext {
            mask: [ResiduePoly::default(); k],
            body: ResiduePoly::default(),
        }
    }
}

pub fn keygen() -> SecretKey {
    let mut polys = [ResiduePoly::default(); k];
    for i in 0..k {
        for j in 0..N {
            polys[i].coefs[j] = thread_rng().gen_range(0..=1);
        }
    }
    SecretKey { polys }
}

#[test]
fn test_keygen_enc_dec() {
    let sk = keygen();
    for _ in 0..100 {
        let msg = thread_rng().gen_range(0..16);
        let ct = GlweCiphertext::encrypt(encode(msg), sk);
        let pt = decode(ct.decrypt(sk));
        assert_eq!(pt, msg);
    }
}

#[test]
fn test_add() {
    let sk = keygen();
    for _ in 0..100 {
        let msg1 = thread_rng().gen_range(0..16);
        let msg2 = thread_rng().gen_range(0..16);
        let ct1 = GlweCiphertext::encrypt(encode(msg1), sk);
        let ct2 = GlweCiphertext::encrypt(encode(msg2), sk);
        let res = ct1.add(ct2);
        let pt = decode(res.decrypt(sk));
        assert_eq!(pt, (msg1 + msg2) % 16);
    }
}

#[test]
fn test_sub() {
    let sk = keygen();
    for _ in 0..100 {
        let msg1 = thread_rng().gen_range(0..16);
        let msg2 = thread_rng().gen_range(0..16);
        let ct1 = GlweCiphertext::encrypt(encode(msg1), sk);
        let ct2 = GlweCiphertext::encrypt(encode(msg2), sk);
        let res = ct1.sub(ct2);
        let pt = decode(res.decrypt(sk));
        assert_eq!(pt, (msg1.wrapping_sub(msg2)) % 16);
    }
}
