use crate::glwe::{decode, encode};
use crate::{glwe::GlweCiphertext, k, poly::ResiduePoly, ELL, KEY_SIZE, N};
use rand::{random, thread_rng, Rng};

struct GgswCiphertext {
    z_m_gt: [GlweCiphertext; (k + 1) * ELL as usize],
}

impl GgswCiphertext {
    pub fn encrypt(msg: u8, sk: [u8; KEY_SIZE]) -> Self {
        // init Z
        let mut z_m_gt = [GlweCiphertext::default(); (k + 1) * ELL as usize];

        for i in 0..z_m_gt.len() {
            z_m_gt[i] = GlweCiphertext::encrypt(0, sk);
        }

        // m * g, g being [q/B, ..., q/B^l] but with .5 shift to accomodate for error
        let mut mg = [0u64; ELL as usize];
        mg[0] = ((msg as u64) << 1) + 1 << 61;
        mg[1] = ((msg as u64) << 1) + 1 << 59;

        // add m * G^t to Z
        for i in 0..z_m_gt.len() {
            if i < k * ELL as usize {
                for j in 0..z_m_gt[i].mask.len() {
                    z_m_gt[i].mask[j].add_constant(mg[i % ELL as usize]);
                }
            } else {
                z_m_gt[i].body.add_constant(mg[i % ELL as usize]);
            }
        }

        // z_m_gt[0].mask[0].add_constant_assign(mg[0]);
        // z_m_gt[1].mask[0].add_constant_assign(mg[1]);
        // z_m_gt[2].body.add_constant_assign(mg[0]);
        // z_m_gt[3].body.add_constant_assign(mg[1]);

        GgswCiphertext { z_m_gt }
    }

    pub fn decrypt(self, sk: [u8; KEY_SIZE]) -> u64 {
        self.z_m_gt[self.z_m_gt.len() - 1].decrypt(sk)
    }
}

#[test]
fn test_keygen_enc_dec() {
    let sk = crate::keygen();
    for _ in 0..1000 {
        let msg = thread_rng().gen_range(0..15);
        let msg = 2;
        let ct = GgswCiphertext::encrypt(msg, sk);
        let pt = decode(ct.decrypt(sk));
        assert!(pt == msg);
    }
}
