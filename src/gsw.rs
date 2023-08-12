use core::panic;

use crate::lwe::LweCiphertext;
use crate::{ELL, KEY_SIZE, N, P, Q};

pub struct GswCiphertext {
    pub z_m_gt: [LweCiphertext; (N + 1) * ELL as usize],
}

impl GswCiphertext {
    pub fn external_product(&self, ct: LweCiphertext) -> LweCiphertext {
        let g_inverse_ct = apply_g_inverse(ct);
        let mut res = [0u8; N];

        // G^-1(c_2) * C_1
        for i in 0..N {
            let mut temp = 0i8;
            for j in 0..(N + 1) * ELL as usize {
                temp = ((temp as i16 + g_inverse_ct[j] as i16 * self.z_m_gt[j].mask[i] as i16)
                    % Q as i16) as i8;
            }
            res[i] = temp as u8;
        }

        let mut temp = 0i8;
        for i in 0..(N + 1) * ELL as usize {
            temp = ((temp as i16 + g_inverse_ct[i] as i16 * self.z_m_gt[i].body as i16) % Q as i16)
                as i8;
        }
        let body = temp as u8;

        LweCiphertext {
            mask: res,
            body: body,
        }
    }
}

pub fn encrypt(mu: u8, sk: [u8; KEY_SIZE]) -> GswCiphertext {
    // init Z
    let mut z = [LweCiphertext::default(); (N + 1) * ELL as usize];
    for i in 0..z.len() {
        z[i] = crate::lwe::encrypt(0, sk);
    }

    // add m * Gt to Z
    for i in 0..N {
        z[i * 2].mask[i] = (z[i * 2].mask[i] + mu * (Q / 4)) % Q;
        z[i * 2 + 1].mask[i] = (z[i * 2 + 1].mask[i] + mu * (Q / 16)) % Q;
    }
    z[(N + 1) * ELL as usize - 2].body = (z[(N + 1) * ELL as usize - 2].body + mu * (Q / 4)) % Q;
    z[(N + 1) * ELL as usize - 1].body = (z[(N + 1) * ELL as usize - 1].body + mu * (Q / 16)) % Q;

    GswCiphertext { z_m_gt: z }
}

fn apply_g_inverse(ct: LweCiphertext) -> [i8; (N + 1) * ELL as usize] {
    let mut res = [0i8; (N + 1) * ELL as usize];
    for i in 0..N {
        let (nu_1, nu_2) = decomposition_lut(ct.mask[i]);
        res[2 * i] = nu_1;
        res[2 * i + 1] = nu_2;
    }
    let (nu_1, nu_2) = decomposition_lut(ct.body);
    res[(N + 1) * ELL as usize - 2] = nu_1;
    res[(N + 1) * ELL as usize - 1] = nu_2;
    res
}

fn decomposition_lut(val: u8) -> (i8, i8) {
    match val % P {
        0 => (0, 0),
        1 => (0, 1),
        2 => (1, -2),
        3 => (1, -1),
        4 => (1, 0),
        5 => (1, 1),
        6 => (-2, -2),
        7 => (-2, -1),
        8 => (-2, 0),
        9 => (-2, 1),
        10 => (-1, -2),
        11 => (-1, -1),
        12 => (-1, 0),
        13 => (-1, 1),
        14 => (0, -2),
        15 => (0, -1),
        _ => panic!("bad value to decompose {val}"),
    }
}

#[test]
fn test_keygen_enc_dec() {
    let sk = crate::keygen();
    let msg1 = 3;
    let msg2 = 3;
    let c1 = encrypt(msg1, sk);
    let c2 = crate::lwe::encrypt(msg2, sk);
    let c3 = c1.external_product(c2);
    let pt = crate::decode(c3.decrypt(sk));
    println!("pt: {pt}");
}
