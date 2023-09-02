use crate::N;
use serde::Serialize;

// Represents an element of Z_{2^q}[X]/(X^N + 1) with implicit q = 2^64.
#[derive(Copy, Clone, Serialize)]
pub struct ResiduePoly {
    //TODO: use Vec
    #[serde(serialize_with = "<[_]>::serialize")]
    pub coefs: [u64; N],
}

impl ResiduePoly {
    pub fn add(&self, rhs: ResiduePoly) -> Self {
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
}

impl Default for ResiduePoly {
    fn default() -> Self {
        ResiduePoly { coefs: [0u64; N] }
    }
}
