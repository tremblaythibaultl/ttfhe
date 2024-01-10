use crate::{utils::round_value, LWE_DIM, N};
use rand::{thread_rng, Rng};
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct LweCiphertext {
    pub mask: Vec<u32>,
    pub body: u32,
}

pub type LweSecretKey = Vec<u32>;
pub type KeySwitchingKey = Vec<LweCiphertext>;

impl LweCiphertext {
    pub fn encrypt(mu: u32, sk: &LweSecretKey) -> LweCiphertext {
        let sigma = f64::powf(2.0, 17.0);
        let normal = Normal::new(0.0, sigma).unwrap();

        let e = normal.sample(&mut rand::thread_rng()).round() as i32;
        let mu_star = mu.wrapping_add_signed(e);

        let mask: Vec<u32> = (0..LWE_DIM).map(|_| rand::random::<u32>()).collect();

        let mut body = 0u32;
        for i in 0..LWE_DIM {
            if sk[i] == 1 {
                body = body.wrapping_add(mask[i]);
            }
        }

        body = body.wrapping_add(mu_star);

        LweCiphertext { mask, body }
    }

    pub fn decrypt(self, sk: &LweSecretKey) -> u32 {
        let mut body: u32 = 0u32;
        for i in 0..sk.len() {
            if sk[i] == 1 {
                body = body.wrapping_add(self.mask[i]);
            }
        }

        self.body.wrapping_sub(body) // mu_star
    }

    pub fn decrypt_modswitched(self, sk: &LweSecretKey) -> u32 {
        let mut dot_prod = 0u32;
        for i in 0..LWE_DIM {
            if sk[i] == 1 {
                dot_prod = (dot_prod + self.mask[i]) % (2 * LWE_DIM as u32);
            }
        }

        self.body.wrapping_sub(dot_prod) % (2 * LWE_DIM as u32) // mu_star
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

    pub fn multiply_constant_assign(&mut self, constant: u32) -> &mut Self {
        self.mask = self.mask.iter().map(|a| a.wrapping_mul(constant)).collect();

        self.body = self.body.wrapping_mul(constant);

        self
    }

    /// Switch from ciphertext modulus `2^32` to `2N` (implicit `N = 1024`).
    pub fn modswitch(&self) -> Self {
        let mask = self.mask.iter().map(|a| ((a >> 20) + 1) >> 1).collect();

        let body = ((self.body >> 20) + 1) >> 1;

        LweCiphertext { mask, body }
    }

    /// Switch to the key encrypted by `ksk`.
    /// This reduces the dimension of the ciphertext.
    // TODO: generalize for k > 1
    pub fn keyswitch(&self, ksk: &mut KeySwitchingKey) -> Self {
        let mut keyswitched = LweCiphertext {
            body: self.body,
            ..Default::default()
        };

        for i in (0..7 * N).step_by(7) {
            let decomp = decomposition_4_7(self.mask[i / 7]);
            keyswitched = keyswitched
                .sub(ksk[i].multiply_constant_assign(decomp[0]))
                .sub(ksk[i + 1].multiply_constant_assign(decomp[1]))
                .sub(ksk[i + 2].multiply_constant_assign(decomp[2]))
                .sub(ksk[i + 3].multiply_constant_assign(decomp[3]))
                .sub(ksk[i + 4].multiply_constant_assign(decomp[4]))
                .sub(ksk[i + 5].multiply_constant_assign(decomp[5]))
                .sub(ksk[i + 6].multiply_constant_assign(decomp[6]))
        }

        keyswitched
    }
}

impl Default for LweCiphertext {
    fn default() -> Self {
        LweCiphertext {
            mask: vec![0u32; LWE_DIM],
            body: 0u32,
        }
    }
}

/// Approximate decomposition with lg(B) = 4 and ell = 7.
pub fn decomposition_4_7(val: u32) -> [u32; 7] {
    let mut ret = [0u32; 7];
    let rounded_val = round_value(val);

    let mut carry = 0u32;
    for i in 0..7 {
        let mut res = ((rounded_val >> (4 * i)) & 0x0F) + carry;

        let carry_bit = res & 8;

        res = res.wrapping_sub(carry_bit << 1);
        ret[i] = res;

        carry = carry_bit >> 3;
    }

    ret
}

/// Approximate decomposition with lg(B) = 4 and ell = 4.
/// Takes a polynomial coefficient in Z_{2^32} and decomposes its 16 MSBs in 4 integers in `[-8, 7] as u32`.
pub fn decomposition_4_4(val: u32) -> [u32; 4] {
    let mut ret = [0u32; 4];
    let rounded_val = round_value(val);

    let mut carry = 0u32;
    for i in 0..4 {
        let mut res = ((rounded_val >> (4 * i)) & 0x0F) + carry;

        let carry_bit = res & 8;

        res = res.wrapping_sub(carry_bit << 1);
        ret[i] = res;

        carry = carry_bit >> 3;
    }

    ret
}

pub fn lwe_keygen() -> LweSecretKey {
    let mut sk = Vec::<u32>::with_capacity(LWE_DIM);
    for _ in 0..LWE_DIM {
        sk.push(thread_rng().gen_range(0..=1));
    }

    sk
}

/// Encrypts `sk1` under `sk2`.
// TODO: generalize for k > 1
pub fn compute_ksk(sk1: &LweSecretKey, sk2: &LweSecretKey) -> KeySwitchingKey {
    let mut ksk = Vec::<LweCiphertext>::with_capacity(7 * N);

    for bit in sk1.iter().take(N) {
        // 7 layers in the decomposition for the KSK
        for j in 0..7 {
            let mu = bit << (4 + (4 * j)); // lg(B) = 4
            ksk.push(LweCiphertext::encrypt(mu, sk2));
        }
    }
    ksk
}

#[cfg(test)]
mod tests {
    use crate::lwe::{lwe_keygen, LweCiphertext};
    use crate::utils::{decode, encode};
    use rand::{thread_rng, Rng};

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
}
