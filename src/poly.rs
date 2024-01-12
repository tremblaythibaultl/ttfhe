use crate::N;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

/// Represents an element of Z_{q}\[X\]/(X^N + 1) with implicit q = 2^32.
#[derive(Clone, Serialize, Deserialize)]
pub struct ResiduePoly {
    pub coefs: Vec<u32>,
}

impl ResiduePoly {
    pub fn new() -> Self {
        ResiduePoly {
            coefs: Vec::<u32>::with_capacity(N),
        }
    }

    pub fn add(&self, rhs: &ResiduePoly) -> Self {
        let coefs = self
            .coefs
            .iter()
            .zip(rhs.coefs.iter())
            .map(|(l_i, r_i)| l_i.wrapping_add(*r_i))
            .collect();

        ResiduePoly { coefs }
    }

    pub fn add_assign(&mut self, rhs: &ResiduePoly) -> &mut Self {
        self.coefs = self
            .coefs
            .iter_mut()
            .zip(rhs.coefs.iter())
            .map(|(l_i, r_i)| l_i.wrapping_add(*r_i))
            .collect();

        self
    }

    pub fn add_constant(&self, constant: u32) -> Self {
        let mut res: ResiduePoly = self.clone();
        res.coefs[0] = res.coefs[0].wrapping_add(constant);
        res
    }

    pub fn add_constant_assign(&mut self, constant: u32) {
        self.coefs[0] = self.coefs[0].wrapping_add(constant);
    }

    pub fn sub(&self, rhs: &ResiduePoly) -> Self {
        let coefs = self
            .coefs
            .iter()
            .zip(rhs.coefs.iter())
            .map(|(l_i, r_i)| l_i.wrapping_sub(*r_i))
            .collect();

        ResiduePoly { coefs }
    }

    pub fn mul(&self, rhs: &ResiduePoly) -> Self {
        let mut res = ResiduePoly::default();

        polynomial_karatsuba_wrapping_mul(&mut res.coefs, &self.coefs, &rhs.coefs);

        res
    }

    /// Generates a residue polynomial with random coefficients in \[0..2^32)
    pub fn get_random() -> Self {
        let coefs = (0..N).map(|_| rand::random::<u32>()).collect();

        Self { coefs }
    }

    /// Generates a residue polynomial with random coefficients in \[0..1\]
    pub fn get_random_bin() -> Self {
        let coefs = (0..N).map(|_| thread_rng().gen_range(0..=1)).collect();

        Self { coefs }
    }

    /// Multiplies the residue polynomial by X^{exponent} = X^{2N + exponent}.
    /// `exponent` is assumed to be reduced modulo 2N.
    pub fn multiply_by_monomial(&self, exponent: usize) -> Self {
        let mut rotated_coefs = Vec::<u32>::with_capacity(N);

        let reverse = exponent >= N;
        let exponent = exponent % N;

        for i in 0..N {
            rotated_coefs.push({
                if i < exponent {
                    if reverse {
                        self.coefs[i + N - exponent]
                    } else {
                        self.coefs[i + N - exponent].wrapping_neg()
                    }
                } else if reverse {
                    self.coefs[i - exponent].wrapping_neg()
                } else {
                    self.coefs[i - exponent]
                }
            })
        }

        ResiduePoly {
            coefs: rotated_coefs,
        }
    }
}

impl Default for ResiduePoly {
    fn default() -> Self {
        ResiduePoly {
            coefs: vec![0u32; N],
        }
    }
}

/// This algorithm is taken from the [TFHE-rs](https://github.com/zama-ai/tfhe-rs/blob/7c50216f7ad1d2dcb06803d3d665409ab731bd45/tfhe/src/core_crypto/algorithms/polynomial_algorithms.rs#L683) codebase.
/// It performs a mulitplication of two elements of Z_{q}\[X\]/(X^N + 1) with q = 2^32, N = 1024 in time O(N^1.58).
pub fn polynomial_karatsuba_wrapping_mul(output: &mut [u32], p: &[u32], q: &[u32]) {
    let poly_size = output.len();

    // check dimensions are a power of 2
    assert!(poly_size.is_power_of_two());

    // allocate slices for recursion
    let mut a0 = vec![0u32; poly_size];
    let mut a1 = vec![0u32; poly_size];
    let mut a2 = vec![0u32; poly_size];
    let mut input_a2_p = vec![0u32; poly_size / 2];
    let mut input_a2_q = vec![0u32; poly_size / 2];

    // prepare for splitting
    let bottom = 0..(poly_size / 2);
    let top = (poly_size / 2)..poly_size;

    // induction
    induction_karatsuba(&mut a0, &p[bottom.clone()], &q[bottom.clone()]);
    induction_karatsuba(&mut a1, &p[top.clone()], &q[top.clone()]);
    slice_wrapping_add(&mut input_a2_p, &p[bottom.clone()], &p[top.clone()]);
    slice_wrapping_add(&mut input_a2_q, &q[bottom.clone()], &q[top.clone()]);
    induction_karatsuba(&mut a2, &input_a2_p, &input_a2_q);

    // rebuild the result
    let output: &mut [u32] = output.as_mut();
    slice_wrapping_sub(output, &a0, &a1);
    slice_wrapping_sub_assign(&mut output[bottom.clone()], &a2[top.clone()]);
    slice_wrapping_add_assign(&mut output[bottom.clone()], &a0[top.clone()]);
    slice_wrapping_add_assign(&mut output[bottom.clone()], &a1[top.clone()]);
    slice_wrapping_add_assign(&mut output[top.clone()], &a2[bottom.clone()]);
    slice_wrapping_sub_assign(&mut output[top.clone()], &a0[bottom.clone()]);
    slice_wrapping_sub_assign(&mut output[top], &a1[bottom]);
}

/// Compute the recursion for the karatsuba algorithm.
fn induction_karatsuba(res: &mut [u32], p: &[u32], q: &[u32]) {
    // stop the recursion when polynomials have KARATUSBA_STOP elements
    if p.len() <= 64 {
        // schoolbook algorithm
        for (lhs_degree, &lhs_elt) in p.iter().enumerate() {
            let res = &mut res[lhs_degree..];
            for (&rhs_elt, res) in q.iter().zip(res) {
                *res = (*res).wrapping_add(lhs_elt.wrapping_mul(rhs_elt));
            }
        }
    } else {
        let poly_size = res.len();

        // allocate slices for the rec
        let mut a0 = vec![0u32; poly_size / 2];
        let mut a1 = vec![0u32; poly_size / 2];
        let mut a2 = vec![0u32; poly_size / 2];
        let mut input_a2_p = vec![0u32; poly_size / 4];
        let mut input_a2_q = vec![0u32; poly_size / 4];

        // prepare for splitting
        let bottom = 0..(poly_size / 4);
        let top = (poly_size / 4)..(poly_size / 2);

        // rec
        induction_karatsuba(&mut a0, &p[bottom.clone()], &q[bottom.clone()]);
        induction_karatsuba(&mut a1, &p[top.clone()], &q[top.clone()]);
        slice_wrapping_add(&mut input_a2_p, &p[bottom.clone()], &p[top.clone()]);
        slice_wrapping_add(&mut input_a2_q, &q[bottom], &q[top]);
        induction_karatsuba(&mut a2, &input_a2_p, &input_a2_q);

        // rebuild the result
        slice_wrapping_sub(&mut res[(poly_size / 4)..(3 * poly_size / 4)], &a2, &a0);
        slice_wrapping_sub_assign(&mut res[(poly_size / 4)..(3 * poly_size / 4)], &a1);
        slice_wrapping_add_assign(&mut res[0..(poly_size / 2)], &a0);
        slice_wrapping_add_assign(&mut res[(poly_size / 2)..poly_size], &a1);
    }
}

pub fn slice_wrapping_add(output: &mut [u32], lhs: &[u32], rhs: &[u32]) {
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );
    assert!(
        output.len() == lhs.len(),
        "output (len: {}) and rhs (len: {}) must have the same length",
        output.len(),
        lhs.len()
    );

    output
        .iter_mut()
        .zip(lhs.iter().zip(rhs.iter()))
        .for_each(|(out, (&lhs, &rhs))| *out = lhs.wrapping_add(rhs));
}

pub fn slice_wrapping_add_assign(lhs: &mut [u32], rhs: &[u32]) {
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );

    lhs.iter_mut()
        .zip(rhs.iter())
        .for_each(|(lhs, &rhs)| *lhs = (*lhs).wrapping_add(rhs));
}

pub fn slice_wrapping_sub(output: &mut [u32], lhs: &[u32], rhs: &[u32]) {
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );
    assert!(
        output.len() == lhs.len(),
        "output (len: {}) and rhs (len: {}) must have the same length",
        output.len(),
        lhs.len()
    );

    output
        .iter_mut()
        .zip(lhs.iter().zip(rhs.iter()))
        .for_each(|(out, (&lhs, &rhs))| *out = lhs.wrapping_sub(rhs));
}

pub fn slice_wrapping_sub_assign(lhs: &mut [u32], rhs: &[u32]) {
    assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );

    lhs.iter_mut()
        .zip(rhs.iter())
        .for_each(|(lhs, &rhs)| *lhs = (*lhs).wrapping_sub(rhs));
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use crate::{poly::ResiduePoly, N};

    #[test]
    /// Tests that the monomial multiplication is coherent with monomial multiplication.
    fn test_monomial_mult() {
        for _ in 0..1000 {
            let mut monomial_coefs = vec![0u32; N];
            let monomial_non_null_term = thread_rng().gen_range(0..2 * N);

            if monomial_non_null_term < 1024 {
                monomial_coefs[monomial_non_null_term] = 1;
            } else {
                monomial_coefs[monomial_non_null_term % 1024] = 1u32.wrapping_neg();
            }

            let monomial = ResiduePoly {
                coefs: monomial_coefs,
            };

            let polynomial = ResiduePoly::get_random();

            let res_mul = polynomial.mul(&monomial);
            let res_monomial_mul = polynomial.multiply_by_monomial(monomial_non_null_term);

            assert_eq!(res_mul.coefs, res_monomial_mul.coefs);
        }
    }
}
