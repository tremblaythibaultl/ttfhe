use std::fmt::Debug;

use crate::N;
#[cfg(test)]
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

// Represents an element of Z_{2^q}[X]/(X^N + 1) with implicit q = 2^64.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ResiduePoly {
    //TODO: use Vec
    #[serde(with = "BigArray")]
    pub coefs: [u64; N],
}

impl Debug for ResiduePoly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResiduePoly")
            .field("coefs", &self.coefs)
            .finish()
    }
}

impl ResiduePoly {
    pub fn add(&self, rhs: &ResiduePoly) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            res.coefs[i] = self.coefs[i].wrapping_add(rhs.coefs[i]); // addition over Z_{2^q}
        }
        res
    }

    pub fn add_assign(&mut self, rhs: &ResiduePoly) {
        for i in 0..N {
            self.coefs[i] = self.coefs[i].wrapping_add(rhs.coefs[i]);
        }
    }

    pub fn add_constant(&self, constant: u64) -> Self {
        let mut res = self.clone();
        res.coefs[0] = res.coefs[0].wrapping_add(constant);
        res
    }

    pub fn add_constant_assign(&mut self, constant: u64) {
        self.coefs[0] = self.coefs[0].wrapping_add(constant);
    }

    pub fn sub(&self, rhs: &ResiduePoly) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            res.coefs[i] = self.coefs[i].wrapping_sub(rhs.coefs[i]); // subtraction over Z_{2^q}
        }
        res
    }

    // TODO: use NTT for better performances
    pub fn mul(self, rhs: &ResiduePoly) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            let mut coef = 0u64;
            for j in 0..i + 1 {
                coef = coef.wrapping_add(self.coefs[j].wrapping_mul(rhs.coefs[i - j]));
            }
            for j in i + 1..N {
                coef = coef.wrapping_sub(self.coefs[j].wrapping_mul(rhs.coefs[N - j + i]));
            }
            res.coefs[i] = coef;
        }
        res
    }

    /// Multiplies the residue polynomial by X^{exponent} = X^{2N + exponent}.
    /// `exponent` is assumed to be reduced modulo 2N.
    pub fn multiply_by_monomial(self, exponent: usize) -> Self {
        let mut rotated_coefs = [0u64; N];

        let reverse = exponent >= N;
        let exponent = exponent % N;

        for i in 0..N {
            rotated_coefs[i] = if i < exponent {
                if reverse {
                    self.coefs[i + N - exponent]
                } else {
                    self.coefs[i + N - exponent].wrapping_neg()
                }
            } else {
                if reverse {
                    self.coefs[i - exponent].wrapping_neg()
                } else {
                    self.coefs[i - exponent]
                }
            }
        }

        ResiduePoly {
            coefs: rotated_coefs,
        }
    }
}

impl Default for ResiduePoly {
    fn default() -> Self {
        ResiduePoly { coefs: [0u64; N] }
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use crate::{poly::ResiduePoly, N};

    #[test]
    /// Tests that the monomial multiplication is coherent with monomial multiplication.
    fn test_monomial_mult() {
        for _ in 0..1000 {
            let mut monomial_coefs = [0u64; N];
            let monomial_non_null_term = thread_rng().gen_range(0..2 * N);

            if monomial_non_null_term < 1024 {
                monomial_coefs[monomial_non_null_term] = 1;
            } else {
                monomial_coefs[monomial_non_null_term % 1024] = 1u64.wrapping_neg();
            }

            let monomial = ResiduePoly {
                coefs: monomial_coefs,
            };

            let mut poly_coefs = [0u64; N];
            for i in 0..N {
                poly_coefs[i] = rand::random::<u64>();
            }
            let polynomial = ResiduePoly { coefs: poly_coefs };

            let res_mul = polynomial.mul(&monomial);
            let res_monomial_mul = polynomial.multiply_by_monomial(monomial_non_null_term);

            assert_eq!(res_mul.coefs, res_monomial_mul.coefs);
        }
    }
}
