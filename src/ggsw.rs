use crate::glwe::{decode, encode, keygen, SecretKey};
use crate::{glwe::GlweCiphertext, k, poly::ResiduePoly, ELL, KEY_SIZE, N, P};
use rand::{random, thread_rng, Rng};

struct GgswCiphertext {
    z_m_gt: [GlweCiphertext; (k + 1) * ELL as usize],
}

impl GgswCiphertext {
    pub fn encrypt(msg: u8, sk: SecretKey) -> Self {
        // init Z
        let mut z_m_gt = [GlweCiphertext::default(); (k + 1) * ELL as usize];

        for i in 0..z_m_gt.len() {
            z_m_gt[i] = GlweCiphertext::encrypt(0, sk);
        }

        // m * g, g being [q/B, ..., q/B^l]
        let mut mg = [0u64; ELL as usize];
        mg[0] = (msg as u64) << 56;
        mg[1] = (msg as u64) << 48;

        // TODO: need to fix this
        // add m * G^t to Z
        // for i in 0..z_m_gt.len() {
        //     if i < k * ELL as usize {
        //         for j in 0..z_m_gt[i].mask.len() {
        //             z_m_gt[i].mask[j].add_constant(mg[i % ELL as usize]);
        //         }
        //     } else {
        //         z_m_gt[i].body.add_constant(mg[i % ELL as usize]);
        //     }
        // }

        z_m_gt[0].mask[0].add_constant_assign(mg[0]);
        z_m_gt[1].mask[0].add_constant_assign(mg[1]);
        z_m_gt[2].body.add_constant_assign(mg[0]);
        z_m_gt[3].body.add_constant_assign(mg[1]);

        GgswCiphertext { z_m_gt }
    }

    pub fn decrypt(self, sk: SecretKey) -> u8 {
        ((((self.z_m_gt[self.z_m_gt.len() - 1].decrypt(sk) >> 47).wrapping_add(1)) >> 1) % 16) as u8
    }

    pub fn external_product(self, ct: GlweCiphertext) -> GlweCiphertext {
        let g_inverse_ct = apply_g_inverse(ct);

        let mut mask = ResiduePoly::default();
        mask.add_assign(&g_inverse_ct[0].mul(&self.z_m_gt[0].mask[0]));
        mask.add_assign(&g_inverse_ct[1].mul(&self.z_m_gt[1].mask[0]));
        mask.add_assign(&g_inverse_ct[2].mul(&self.z_m_gt[2].mask[0]));
        mask.add_assign(&g_inverse_ct[3].mul(&self.z_m_gt[3].mask[0]));

        let mut body = ResiduePoly::default();
        body.add_assign(&g_inverse_ct[0].mul(&self.z_m_gt[0].body));
        body.add_assign(&g_inverse_ct[1].mul(&self.z_m_gt[1].body));
        body.add_assign(&g_inverse_ct[2].mul(&self.z_m_gt[2].body));
        body.add_assign(&g_inverse_ct[3].mul(&self.z_m_gt[3].body));

        GlweCiphertext { mask: [mask], body }
    }
}

// correct only for k = 1
fn apply_g_inverse(ct: GlweCiphertext) -> [ResiduePoly; (k + 1) * ELL as usize] {
    let mut res = [ResiduePoly::default(); (k + 1) * ELL as usize];

    for i in 0..N {
        let (nu_2, nu_1) = decomposition(ct.mask[0].coefs[i]);
        res[0].coefs[i] = nu_1 as u64; // mask decomposition B
        res[1].coefs[i] = nu_2 as u64; // mask decomposition B^l

        // println!("body.coefs[i]: {}", ct.body.coefs[i]);
        let (nu_2, nu_1) = decomposition(ct.body.coefs[i]);
        // println!("ct.body.coefs[i]: {}", ct.body.coefs[i]);
        res[2].coefs[i] = nu_1 as u64; // body decomposition B
        res[3].coefs[i] = nu_2 as u64; // body decomposition B^l
    }
    res
}

//TODO: do decomposition with B=256
// => need to decompose the 16 MSBs of the 64b coefficient into two signed 8-bit integers
fn decomposition(val: u64) -> (i8, i8) {
    let mut rounded_val = val >> 47;
    rounded_val += val & 1;
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
    let msg = thread_rng().gen_range(0..16);
    let ct = GgswCiphertext::encrypt(msg, sk);
    let pt = ct.decrypt(sk);
    assert!(msg == pt as u8);
}

// The following test fails from time to time - the noise does not "stay small" enough for a correct decryption.
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
        let expected = msg1 * msg2 % 16;
        assert_eq!(expected, pt);
    }
}
