use crate::{ggsw::decomposition, ELL, LWE_DIM};
use rand::{thread_rng, Rng};
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct LweCiphertext {
    pub mask: Vec<u64>,
    pub body: u64,
}

pub type LweSecretKey = Vec<u64>;
pub type KeySwitchingKey = Vec<LweCiphertext>;

impl LweCiphertext {
    pub fn encrypt(mu: u64, sk: &LweSecretKey) -> LweCiphertext {
        let sigma = f64::powf(2.0, 29.0);
        let normal = Normal::new(0.0, sigma).unwrap();

        let e = normal.sample(&mut rand::thread_rng()).round() as i64;
        let mu_star = mu.wrapping_add_signed(e);

        let mask: Vec<u64> = (0..LWE_DIM).map(|_| rand::random::<u64>()).collect();

        let mut body = 0u64;
        for i in 0..LWE_DIM {
            if sk[i] == 1 {
                body = body.wrapping_add(mask[i]);
            }
        }

        body = body.wrapping_add(mu_star);

        LweCiphertext { mask, body }
    }

    pub fn decrypt(self, sk: &LweSecretKey) -> u64 {
        let mut body: u64 = 0u64;
        for i in 0..LWE_DIM {
            if sk[i] == 1 {
                body = body.wrapping_add(self.mask[i]);
            }
        }

        self.body.wrapping_sub(body) // mu_star
    }

    pub fn decrypt_modswitched(self, sk: &LweSecretKey) -> u64 {
        let mut dot_prod = 0u64;
        for i in 0..LWE_DIM {
            if sk[i] == 1 {
                dot_prod = (dot_prod + self.mask[i]) % (2 * LWE_DIM as u64);
            }
        }

        self.body.wrapping_sub(dot_prod) % (2 * LWE_DIM as u64) // mu_star
    }

    pub fn add(self, rhs: Self) -> Self {
        let mask = self
            .mask
            .iter()
            .zip(rhs.mask)
            .map(|(a, b)| a.wrapping_add(b))
            .collect();

        let body = self.body.wrapping_add(rhs.body);

        LweCiphertext { mask, body }
    }

    pub fn sub(self, rhs: &Self) -> Self {
        let mask = self
            .mask
            .iter()
            .zip(&rhs.mask)
            .map(|(a, b)| a.wrapping_sub(*b))
            .collect();

        let body = self.body.wrapping_sub(rhs.body);

        LweCiphertext { mask, body }
    }

    pub fn multiply_constant_assign(&mut self, constant: u64) -> &mut Self {
        self.mask = self.mask.iter().map(|a| a.wrapping_mul(constant)).collect();

        self.body = self.body.wrapping_mul(constant);

        self
    }

    /// Switch from modulus 2^64 to 2N, with 2N = 2^11.
    pub fn modswitch(&self) -> Self {
        let mask = self.mask.iter().map(|a| ((a >> 52) + 1) >> 1).collect();

        let body = ((self.body >> 52) + 1) >> 1;

        LweCiphertext { mask, body }
    }

    /// Switch to the key encrypted by `ksk`.
    // TODO: generalize for k > 1
    pub fn keyswitch(&self, ksk: &mut KeySwitchingKey) -> Self {
        let mut keyswitched = LweCiphertext {
            body: self.body,
            ..Default::default()
        };

        for i in 0..LWE_DIM {
            let (decomp_mask_1, decomp_mask_2) = decomposition(self.mask[i]);
            keyswitched = keyswitched
                .sub(ksk[ELL * i].multiply_constant_assign(decomp_mask_1 as u64))
                .sub(ksk[(ELL * i) + 1].multiply_constant_assign(decomp_mask_2 as u64));
        }

        keyswitched
    }
}

impl Default for LweCiphertext {
    fn default() -> Self {
        LweCiphertext {
            mask: vec![0u64; LWE_DIM],
            body: 0u64,
        }
    }
}

pub fn lwe_keygen() -> LweSecretKey {
    let mut sk = Vec::<u64>::with_capacity(LWE_DIM);
    for _ in 0..LWE_DIM {
        sk.push(thread_rng().gen_range(0..=1));
    }

    sk
}

/// Encrypts `sk1` under `sk2`.
// TODO: generalize for k > 1
pub fn compute_ksk(sk1: &LweSecretKey, sk2: &LweSecretKey) -> KeySwitchingKey {
    let mut ksk = vec![];

    for bit in sk1.iter().take(LWE_DIM) {
        for j in 0..ELL {
            let mu = bit << (40 + (8 * (j + 1))); // lg(B) = 8
            ksk.push(LweCiphertext::encrypt(mu, sk2));
        }
    }
    ksk
}

#[cfg(test)]
mod tests {
    use crate::lwe::{compute_ksk, lwe_keygen, LweCiphertext};
    use crate::utils::{decode, decode_modswitched, encode};
    use rand::{thread_rng, Rng};

    #[test]
    fn test_keyswitch() {
        let sk1 = lwe_keygen();
        let sk2 = lwe_keygen();
        let ksk = compute_ksk(&sk1, &sk2); //encrypt sk1 under sk2

        for _ in 0..100 {
            let msg = thread_rng().gen_range(0..16);

            let ct1 = LweCiphertext::encrypt(encode(msg), &sk1);

            let res = ct1.keyswitch(&mut ksk.clone()).decrypt(&sk2);

            let pt = decode(res);

            assert_eq!(msg, pt);
        }
    }

    #[test]
    fn test_keygen_enc_dec() {
        let sk = lwe_keygen();
        for _ in 0..100 {
            let msg = thread_rng().gen_range(0..16);
            let ct = LweCiphertext::encrypt(encode(msg), &sk);
            let pt = decode(ct.decrypt(&sk));
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn test_add() {
        let sk = lwe_keygen();
        for _ in 0..100 {
            let msg1 = thread_rng().gen_range(0..16);
            let msg2 = thread_rng().gen_range(0..16);
            let ct1 = LweCiphertext::encrypt(encode(msg1), &sk);
            let ct2 = LweCiphertext::encrypt(encode(msg2), &sk);
            let res = ct1.add(ct2);
            let pt = decode(res.decrypt(&sk));
            assert_eq!(pt, (msg1 + msg2) % 16);
        }
    }

    #[test]
    fn test_sub() {
        let sk = lwe_keygen();
        for _ in 0..100 {
            let msg1 = thread_rng().gen_range(0..16);
            let msg2 = thread_rng().gen_range(0..16);
            let ct1 = LweCiphertext::encrypt(encode(msg1), &sk);
            let ct2 = LweCiphertext::encrypt(encode(msg2), &sk);
            let res = ct1.sub(&ct2);
            let pt = decode(res.decrypt(&sk));
            assert_eq!(pt, (msg1.wrapping_sub(msg2)) % 16);
        }
    }

    #[test]
    fn test_modswitch() {
        for _ in 0..100 {
            let sk = lwe_keygen();
            let msg = thread_rng().gen_range(0..16);
            let ct = LweCiphertext::encrypt(encode(msg), &sk);
            let modswitched = ct.modswitch();
            let pt = decode_modswitched(modswitched.decrypt_modswitched(&sk));
            assert_eq!(pt, msg);
        }
    }
}
