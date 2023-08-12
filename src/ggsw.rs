use crate::{glwe::GlweCiphertext, k, poly::ResiduePoly, ELL, KEY_SIZE, N};

struct GgswCiphertext {
    z_m_gt: [GlweCiphertext; (k + 1) * ELL as usize],
}

impl GgswCiphertext {
    pub fn encrypt(msg: u8, sk: [u8; KEY_SIZE]) {
        // init Z
        let mut z = [GlweCiphertext::default(); (k + 1) * ELL as usize];

        for i in 0..z.len() {
            z[i] = GlweCiphertext::encrypt(0, sk);
        }

        //compute z_m_gt but with the good scaling factors in gt (e.g. 2^59.5 and 2^61.5)
    }
}
