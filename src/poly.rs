use crate::N;

// Represents an element of Z_{q}[X]/(X^N + 1) with implicit q = 2^64.
#[derive(Copy, Clone)]
pub struct ResiduePoly {
    pub coefs: [u64; N],
}

impl ResiduePoly {
    pub fn add(&self, rhs: &ResiduePoly) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            res.coefs[i] = self.coefs[i].wrapping_add(rhs.coefs[i]); // addition over Z_q
        }
        res
    }

    pub fn add_assign(&mut self, rhs: &ResiduePoly) {
        for i in 0..N {
            self.coefs[i] = self.coefs[i].wrapping_add(rhs.coefs[i]);
        }
    }

    pub fn add_constant(&self, constant: u64) -> Self {
        let mut res = Self::default();
        res.coefs[0] = self.coefs[0].wrapping_add(constant);
        res
    }

    pub fn add_constant_assign(&mut self, constant: u64) {
        self.coefs[0] = self.coefs[0].wrapping_add(constant);
    }

    pub fn sub(&self, rhs: &ResiduePoly) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            res.coefs[i] = self.coefs[i].wrapping_sub(rhs.coefs[i]); // subtraction over Z_q
        }
        res
    }

    // TODO: use NTT for quasilinear time instread of quadratic
    pub fn mul(self, rhs: &ResiduePoly) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            let mut coef = 0u64;
            for j in 0..i + 1 {
                coef += self.coefs[j].wrapping_mul(rhs.coefs[i - j])
            }
            for j in i + 1..N {
                coef -= self.coefs[j].wrapping_sub(rhs.coefs[N - j + i])
            }
            res.coefs[i] = coef;
        }
        res
    }
}

impl Default for ResiduePoly {
    fn default() -> Self {
        ResiduePoly { coefs: [0u64; N] }
    }
}

#[test]
fn test_mul() {
    let a = ResiduePoly::default();
    let b = ResiduePoly::default();
    let c = a.mul(&b);
    println!("{:?}", c.coefs);
}
