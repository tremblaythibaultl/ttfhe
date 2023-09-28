pub mod ggsw;
pub mod glwe;
pub mod lwe;
pub mod poly;
pub mod utils;

// pub const B: usize = 256; // decomposition basis
pub const ELL: usize = 2; // number of decomposition layers
#[allow(non_upper_case_globals)]
pub const k: usize = 1; // GLWE dimension
pub const N: usize = 1024; // degree `N` of irreducible polynomial X^N + 1
pub const LWE_DIM: usize = N; // dimension `n` of LWE ciphertexts
pub const P: usize = 16; // plaintext modulus
