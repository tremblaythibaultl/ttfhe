use crate::glwe::SecretKey;
#[cfg(test)]
use crate::glwe::{decode, encode, keygen};
use crate::{glwe::GlweCiphertext, k, poly::ResiduePoly, ELL, N};
#[cfg(test)]
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GgswCiphertext {
    z_m_gt: [GlweCiphertext; (k + 1) * ELL],
}

impl GgswCiphertext {
    pub fn encrypt(msg: u8, sk: SecretKey) -> Self {
        // initialize Z
        let mut z_m_gt = [GlweCiphertext::default(); (k + 1) * ELL];

        for i in 0..z_m_gt.len() {
            z_m_gt[i] = GlweCiphertext::encrypt(0, sk);
        }

        // m * g, g being [q/B, ..., q/B^l]
        let mut mg = [0u64; ELL];
        mg[0] = (msg as u64) << 56;
        mg[1] = (msg as u64) << 48;

        // add m * G^t to Z
        for i in 0..z_m_gt.len() {
            if i < k * ELL {
                for j in 0..z_m_gt[i].mask.len() {
                    z_m_gt[i].mask[j].add_constant_assign(mg[i % ELL]);
                }
            } else {
                z_m_gt[i].body.add_constant_assign(mg[i % ELL]);
            }
        }

        GgswCiphertext { z_m_gt }
    }

    // The last `GlweCiphertext` of `z_m_gt` is an encryption of msg * q/B^l
    pub fn decrypt(self, sk: SecretKey) -> u8 {
        ((((self.z_m_gt[self.z_m_gt.len() - 1].decrypt(sk) >> 47) + 1) >> 1) % 16) as u8
    }

    pub fn external_product(self, ct: GlweCiphertext) -> GlweCiphertext {
        let g_inverse_ct = apply_g_inverse(ct);

        let mut res = GlweCiphertext::default();
        for i in 0..(k + 1) * ELL {
            for j in 0..k {
                res.mask[j].add_assign(&g_inverse_ct[i].mul(&self.z_m_gt[i].mask[j]));
            }
            res.body
                .add_assign(&g_inverse_ct[i].mul(&self.z_m_gt[i].body));
        }
        res
    }
}

fn apply_g_inverse(ct: GlweCiphertext) -> [ResiduePoly; (k + 1) * ELL] {
    let mut res = [ResiduePoly::default(); (k + 1) * ELL];
    for i in 0..N {
        // mask decomposition
        for j in 0..k {
            let (nu_2, nu_1) = decomposition(ct.mask[j].coefs[i]);
            res[j * ELL].coefs[i] = nu_1 as u64;
            res[j * ELL + 1].coefs[i] = nu_2 as u64;
        }

        // body decomposition
        let (nu_2, nu_1) = decomposition(ct.body.coefs[i]);
        res[(k + 1) * ELL - 2].coefs[i] = nu_1 as u64;
        res[(k + 1) * ELL - 1].coefs[i] = nu_2 as u64;
    }
    res
}

// Approximate decomposition with B = 256 and ell = 2.
// Takes a polynomial coefficient in Z_2^64 and decomposes its 16 MSBs in two signed 8-bit integers.
fn decomposition(val: u64) -> (i8, i8) {
    let mut rounded_val = val >> 47;
    rounded_val += rounded_val & 1;
    rounded_val = rounded_val >> 1;
    if rounded_val & 128 == 128 {
        (rounded_val as i8, ((rounded_val >> 8) + 1) as i8)
    } else {
        (rounded_val as i8, (rounded_val >> 8) as i8)
    }
}

#[test]
fn test_keygen_enc_dec() {
    let sk = keygen();
    for _ in 0..100 {
        let msg = thread_rng().gen_range(0..16);
        let ct = GgswCiphertext::encrypt(msg, sk);
        let pt = ct.decrypt(sk);
        assert!(msg == pt as u8);
    }
}

#[test]
fn test_external_product() {
    let sk = keygen();
    for _ in 0..100 {
        let msg1 = thread_rng().gen_range(0..16);
        let msg2 = thread_rng().gen_range(0..16);
        let ct1 = GgswCiphertext::encrypt(msg1, sk);
        let ct2 = GlweCiphertext::encrypt(encode(msg2), sk);
        let res = ct1.external_product(ct2);
        let pt = decode(res.decrypt(sk));
        let expected: u8 = msg1 * msg2 % 16;
        assert_eq!(expected, pt);
    }
}

#[test]
fn test_cmux() {
    for _ in 0..100 {
        let sk = keygen();
        let msg1 = thread_rng().gen_range(0..16);
        let msg2 = thread_rng().gen_range(0..16);
        let b = thread_rng().gen_range(0..2);
        let ct1 = GlweCiphertext::encrypt(encode(msg1), sk);
        let ct2 = GlweCiphertext::encrypt(encode(msg2), sk);
        let ctb = GgswCiphertext::encrypt(b, sk);
        let temp = ct2.sub(ct1);
        let temp = ctb.external_product(temp);
        let res = temp.add(ct1);
        let pt = decode(res.decrypt(sk));
        assert_eq!(pt, (1 - b) * msg1 + b * msg2);
    }
}
