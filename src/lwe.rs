use crate::{decode, encode, keygen};
use crate::{N, P, Q, SIGMA};
use rand::Rng;
use rand_distr::{Distribution, Normal};

#[derive(Clone, Copy)]
pub struct LweCiphertext {
    pub mask: [u8; N],
    pub body: u8,
}

impl LweCiphertext {
    pub fn decrypt(&self, sk: [u8; N]) -> u8 {
        let mut dot_prod = 0u16;
        for j in 0..N {
            dot_prod = (dot_prod + self.mask[j] as u16 * (sk[j] & 1) as u16) % Q as u16;
        }

        println!("during decryption, dot_prod: {dot_prod}");

        let mu_star = self.body.wrapping_sub(dot_prod as u8) % Q;
        mu_star
    }

    pub fn add(&self, ct: LweCiphertext) -> LweCiphertext {
        let mut a_3 = [0u8; N];
        for i in 0..N {
            a_3[i] = (self.mask[i] + ct.mask[i]) % Q;
        }

        LweCiphertext {
            mask: a_3,
            body: (self.body + ct.body) % Q,
        }
    }
}

impl Default for LweCiphertext {
    fn default() -> Self {
        LweCiphertext {
            mask: [0u8; N],
            body: 0u8,
        }
    }
}

pub fn encrypt(mu: u8, sk: [u8; N]) -> LweCiphertext {
    // initializing normal distribution
    let sigma2 = f64::powf(SIGMA, 2.0);
    let normal = Normal::new(0.0, sigma2).unwrap();

    // sample error from discretized normal distribution over Z_q
    let e = (normal.sample(&mut rand::thread_rng()) * Q as f64).round() as i8;

    let mu_star = (((mu as i8) + e) % (Q as i8)) as u8;

    // mask
    let mut rng = rand::thread_rng();
    let mut a = [0u8; N];
    for a_i in &mut a {
        // sample `n` values from Z_q uniformly at random
        *a_i = rng.gen_range(0..Q);
    }

    // body
    let mut dot_prod = 0u8;
    for j in 0..N {
        dot_prod = (dot_prod + a[j] * (sk[j] & 1)) % Q;
    }

    let b = dot_prod + mu_star % Q;

    LweCiphertext { mask: a, body: b }
}

#[test]
fn test_keygen_enc_dec() {
    let sk = keygen();
    let msg = 2;
    for i in 0..1000 {
        let ct = encrypt(encode(msg), sk);
        let pt = decode(ct.decrypt(sk));
        assert!(pt == msg);
    }
}
