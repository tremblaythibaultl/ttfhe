pub mod ggsw;
pub mod glwe;
pub mod poly;

pub const ELL: usize = 2; // number of decomposition layers
#[allow(non_upper_case_globals)]
pub const k: usize = 1; // GLWE dimension
                        // The external product currently only works with k = 1
pub const N: usize = 1024; // degree N of irreducible polynomial X^N + 1
