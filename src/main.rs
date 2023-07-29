use rand::Rng;
use rand_distr::{Distribution, Normal};
const N: usize = 1024;
const P: u8 = 16;
const Q: u8 = 64;
const SIGMA: f64 = 0.000000049029381729;

fn main() {
    let sk = keygen();
    let c1 = encrypt(2, sk);
    let c2 = encrypt(15, sk);
    let c3 = add(c1.0, c1.1, c2.0, c2.1);
    let pt = decrypt(c3.0, c3.1, sk);
    println!("{pt}");
}

fn keygen() -> [u8; N] {
    let mut sk = [0u8; N];
    rand::thread_rng().fill(&mut sk);
    sk
}

fn encode(msg: u8) -> u8 {
    assert!(msg < P, "message out of plaintext space");
    msg * (Q / P)
}

fn decode(mu: u8) -> u8 {
    assert!(mu < Q, "invalid encoding");
    ((mu as u16 * P as u16) / Q as u16) as u8
}

// Message mu should be in the plaintext space Z_p
fn encrypt(mu: u8, sk: [u8; N]) -> ([u8; N], u8) {
    // initializing normal distribution
    let sigma2 = f64::powf(SIGMA, 2.0);
    let normal = Normal::new(0.0, sigma2).unwrap();

    // sample error from discretized normal distribution over Z_q
    let e = (normal.sample(&mut rand::thread_rng()) * Q as f64).round() as i8;

    let mu_star = (((mu as i8) + e) % (P as i8)) as u8;

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

    (a, b)
}

fn decrypt(a: [u8; N], b: u8, sk: [u8; N]) -> u8 {
    let mut dot_prod = 0u8;
    for j in 0..N {
        dot_prod = (dot_prod + a[j] * (sk[j] & 1)) % Q;
    }

    let mu_star = b.wrapping_sub(dot_prod) % Q;
    mu_star % P
}

fn add(a_1: [u8; N], b_1: u8, a_2: [u8; N], b_2: u8) -> ([u8; N], u8) {
    let mut a_3 = [0u8; N];
    for i in 0..N {
        a_3[i] = (a_1[i] + a_2[i]) % Q;
    }

    (a_3, (b_1 + b_2) % Q)
}

#[test]
fn test_keygen_enc_dec() {
    let sk = keygen();
    let mu = 2;
    for i in 0..1000 {
        let ct = encrypt(mu, sk);
        let pt = decrypt(ct.0, ct.1, sk);
        assert!(pt == mu);
    }
}

#[test]
fn test_codec() {
    for i in 0..16 {
        assert!(i == decode(encode(i)));
    }
}
