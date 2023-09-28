pub mod ggsw;
pub mod glwe;
pub mod lwe;
pub mod poly;
pub mod utils;

/// Decomposition basis. This value is used implicitely.
// pub const B: usize = 256;

/// Ciphertext modulus. This value is used implicitely.
// pub const Q: usize = 2^64;

/// Plaintext modulus
pub const P: usize = 16;

/// Number of decomposition layers
pub const ELL: usize = 2;

/// GLWE dimension
#[allow(non_upper_case_globals)]
pub const k: usize = 1;

/// Degree `N` of irreducible polynomial X^N + 1
pub const N: usize = 1024;

/// Dimension `n` of LWE ciphertexts
pub const LWE_DIM: usize = N;
