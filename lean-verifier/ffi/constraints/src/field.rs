//! Goldilocks field GF(p) and cubic extension GF(p^3) arithmetic.
//!
//! Base field: p = 2^64 - 2^32 + 1
//! Extension: GF(p^3) = GF(p)[x] / (x^3 - x - 1)
//!
//! Copied from poseidon2-lean (base field) with FF3 extension added.

pub const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001;

// ============================================================================
// Base field GF(p)
// ============================================================================

#[inline]
pub fn reduce(x: u128) -> u64 {
    let rl = x as u64;
    let rh = (x >> 64) as u64;
    let rhh = rh >> 32;
    let rhl = rh & 0xFFFFFFFF;

    let (aux1, borrow) = rl.overflowing_sub(rhh);
    let aux1 = if borrow {
        aux1.wrapping_sub(0xFFFFFFFF)
    } else {
        aux1
    };

    let aux = 0xFFFFFFFF_u64.wrapping_mul(rhl);

    let (result, carry) = aux1.overflowing_add(aux);
    let result = if carry {
        result.wrapping_add(0xFFFFFFFF)
    } else {
        result
    };

    if result >= GOLDILOCKS_PRIME {
        result - GOLDILOCKS_PRIME
    } else {
        result
    }
}

#[inline]
pub fn add(a: u64, b: u64) -> u64 {
    let (sum, overflow) = a.overflowing_add(b);
    if overflow || sum >= GOLDILOCKS_PRIME {
        sum.wrapping_sub(GOLDILOCKS_PRIME)
    } else {
        sum
    }
}

#[inline]
pub fn sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        a.wrapping_sub(b).wrapping_add(GOLDILOCKS_PRIME)
    }
}

#[inline]
pub fn mul(a: u64, b: u64) -> u64 {
    reduce((a as u128) * (b as u128))
}

#[inline]
pub fn inv(a: u64) -> u64 {
    pow(a, GOLDILOCKS_PRIME - 2)
}

pub fn pow(mut base: u64, mut exp: u64) -> u64 {
    let mut result = 1u64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exp >>= 1;
    }
    result
}

// ============================================================================
// Cubic extension GF(p^3) = GF(p)[x] / (x^3 - x - 1)
// ============================================================================

/// FF3 element: c0 + c1*x + c2*x^2
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FF3 {
    pub c0: u64,
    pub c1: u64,
    pub c2: u64,
}

impl FF3 {
    pub const ZERO: FF3 = FF3 { c0: 0, c1: 0, c2: 0 };
    pub const ONE: FF3 = FF3 { c0: 1, c1: 0, c2: 0 };

    #[inline]
    pub fn new(c0: u64, c1: u64, c2: u64) -> Self {
        FF3 { c0, c1, c2 }
    }

    /// Read from interleaved buffer at index (3 consecutive u64s).
    #[inline]
    pub fn from_interleaved(buf: &[u64], idx: usize) -> Self {
        FF3 {
            c0: buf[idx],
            c1: buf[idx + 1],
            c2: buf[idx + 2],
        }
    }

    #[inline]
    pub fn add(self, other: FF3) -> FF3 {
        FF3 {
            c0: add(self.c0, other.c0),
            c1: add(self.c1, other.c1),
            c2: add(self.c2, other.c2),
        }
    }

    #[inline]
    pub fn sub(self, other: FF3) -> FF3 {
        FF3 {
            c0: sub(self.c0, other.c0),
            c1: sub(self.c1, other.c1),
            c2: sub(self.c2, other.c2),
        }
    }

    /// Multiply in GF(p^3) with reduction by x^3 = x + 1.
    ///
    /// x^3 -> x + 1
    /// x^4 -> x^2 + x
    #[inline]
    pub fn mul(self, other: FF3) -> FF3 {
        let a0b0 = mul(self.c0, other.c0);
        let a0b1 = mul(self.c0, other.c1);
        let a0b2 = mul(self.c0, other.c2);
        let a1b0 = mul(self.c1, other.c0);
        let a1b1 = mul(self.c1, other.c1);
        let a1b2 = mul(self.c1, other.c2);
        let a2b0 = mul(self.c2, other.c0);
        let a2b1 = mul(self.c2, other.c1);
        let a2b2 = mul(self.c2, other.c2);

        // cross = a1*b2 + a2*b1 (x^3 coefficient)
        let cross = add(a1b2, a2b1);
        // top = a2*b2 (x^4 coefficient)
        let top = a2b2;

        FF3 {
            c0: add(a0b0, cross),                         // +cross from x^3 -> +1
            c1: add(add(a0b1, a1b0), add(cross, top)),   // +cross from x^3 -> x, +top from x^4 -> x
            c2: add(add(a0b2, a1b1), add(a2b0, top)),    // +top from x^4 -> x^2
        }
    }

    /// Embed a base field element into FF3.
    #[inline]
    pub fn from_base(val: u64) -> FF3 {
        FF3 { c0: val, c1: 0, c2: 0 }
    }

    /// Exponentiation by repeated squaring.
    pub fn pow(self, mut exp: u64) -> FF3 {
        let mut result = FF3::ONE;
        let mut base = self;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        result
    }

    /// Inverse via norm-based tower inversion.
    pub fn inv(self) -> FF3 {
        // For x^3 - x - 1 over GF(p):
        // norm(a) = a * a^p * a^(p^2) is in GF(p)
        // Use Frobenius: a^p computed via p-th power
        // For the spec, use brute force: a^(p^3 - 2)
        // p^3 - 2 is huge, but we can use the factored approach:
        // a^(-1) = a^(p-1) * a^(p*(p-1)) / norm(a)
        // Simpler: just compute via extended field norm
        let norm = self.norm();
        let norm_inv = inv(norm);
        // a^(-1) = conjugates_product * norm_inv
        let conj = self.conjugates_product();
        FF3 {
            c0: mul(conj.c0, norm_inv),
            c1: mul(conj.c1, norm_inv),
            c2: mul(conj.c2, norm_inv),
        }
    }

    /// Compute norm: N(a) = a * a^p * a^(p^2) in GF(p).
    fn norm(self) -> u64 {
        let ap = self.frobenius();
        let ap2 = ap.frobenius();
        let product = self.mul(ap).mul(ap2);
        // Result should be in GF(p) (c1=c2=0)
        product.c0
    }

    /// Product of conjugates: a^p * a^(p^2).
    fn conjugates_product(self) -> FF3 {
        let ap = self.frobenius();
        let ap2 = ap.frobenius();
        ap.mul(ap2)
    }

    /// Frobenius endomorphism: a^p.
    /// For x^3 - x - 1 over GF(p), this maps (c0, c1, c2) to specific combinations.
    fn frobenius(self) -> FF3 {
        // x^p mod (x^3 - x - 1) and x^(2p) mod (x^3 - x - 1) are constants
        // that depend on p. We compute them once.
        // For Goldilocks p = 2^64 - 2^32 + 1:
        // Use the fact that a^p = c0 + c1 * x^p + c2 * x^(2p)
        // where x^p and x^(2p) are precomputed mod (x^3 - x - 1)
        //
        // x^p mod (x^3 - x - 1): computed as pow(x, p)
        // For the spec, just use full exponentiation
        self.pow(GOLDILOCKS_PRIME)
    }
}
