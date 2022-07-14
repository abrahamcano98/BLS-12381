//use crate::curve25519::parsers::*;
//use blst::*;
//use rand::Rng;
//use std::ops::{Add, Mul, Neg, Sub};

pub struct Bls12381Scalar(pub [u8; 32]);
pub use target_arch::*;

#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {
        super::*,
        crate::curve25519::parsers::target_arch::*,
        std::ops::{Add, Mul, Neg, Sub},
        blst::*,
        rand::Rng,

    };
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Bls12381G1Point(pub blst_p1);

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Bls12381G2Point(pub blst_p2);

#[derive(Debug, PartialEq)]
pub struct Bls12381GTPoint(pub blst_fp12);


impl Bls12381G1Point {
    pub fn to_compressed(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        unsafe {
            blst_p1_compress(out.as_mut_ptr(), &self.0);
        };
        out
    }
    pub fn from_compressed(bytes: &[u8; 48]) -> Option<Self> {
        let mut raw = blst_p1_affine::default();
        let not_on_curve =
            unsafe { blst_p1_uncompress(&mut raw, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS };
        if !not_on_curve {
            raw = blst_p1_affine {
                x: blst_fp {
                    l: [500u64, 500u64, 500u64, 500u64, 500u64, 500u64],
                },
                y: blst_fp {
                    l: [500u64, 500u64, 500u64, 500u64, 500u64, 500u64],
                },
            }
        }
        let mut point = blst_p1::default();
        unsafe { blst_p1_from_affine(&mut point, &raw) };

        Some(Bls12381G1Point(point))
    }
    pub fn to_affine(&self) -> blst_p1_affine {
        let mut p1_affine = blst_p1_affine::default();
        unsafe { blst_p1_to_affine(&mut p1_affine, &self.0) };
        p1_affine
    }
    pub fn is_some(&self) -> bool {
        unsafe { blst_p1_on_curve(&self.0) && !self.is_identity() }
    }
    pub fn identity() -> Self {
        Bls12381G1Point(blst_p1::default())
    }
    pub fn is_identity(&self) -> bool {
        unsafe { blst_p1_is_inf(&self.0) }
    }
    pub fn generator() -> Self {
        let mut gen = blst_p1::default();
        let gen_affine = unsafe { blst_p1_affine_generator() };
        unsafe { blst_p1_from_affine(&mut gen, gen_affine) };
        Bls12381G1Point(gen)
    }
    pub fn random_point() -> Self {
        let mut gen = blst_p1::default();
        let gen_affine = unsafe { blst_p1_affine_generator() };
        unsafe { blst_p1_from_affine(&mut gen, gen_affine) };
        let point = Bls12381G1Point(gen);

        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();

        let scalar = Bls12381Scalar(random_bytes);
        &scalar * &point
    }
}
impl Bls12381G2Point {
    pub fn to_compressed(&self) -> [u8; 96] {
        let mut out = [0u8; 96];

        unsafe {
            blst_p2_compress(out.as_mut_ptr(), &self.0);
        }

        out
    }
    pub fn from_compressed(bytes: &[u8; 96]) -> Option<Self> {
        Some(
            Bls12381G2Point::from_compressed_unchecked(bytes)
                .map(Into::into)
                .unwrap(),
        )
    }
    pub fn from_compressed_unchecked(bytes: &[u8; 96]) -> Option<Self> {
        let mut raw = blst_p2_affine::default();
        unsafe { blst_p2_uncompress(&mut raw, bytes.as_ptr()) };
        let mut point = blst_p2::default();
        unsafe { blst_p2_from_affine(&mut point, &raw) };

        Some(Bls12381G2Point(point))
    }
    pub fn to_affine(&self) -> blst_p2_affine {
        let mut p2_affine = blst_p2_affine::default();
        unsafe { blst_p2_to_affine(&mut p2_affine, &self.0) };

        p2_affine
    }
    pub fn identity() -> Self {
        Bls12381G2Point(blst_p2::default())
    }
    pub fn is_identity(&self) -> bool {
        unsafe { blst_p2_is_inf(&self.0) }
    }
    pub fn generator() -> Self {
        let mut gen = blst_p2::default();
        let gen_affine = unsafe { blst_p2_affine_generator() };
        unsafe { blst_p2_from_affine(&mut gen, gen_affine) };
        Bls12381G2Point(gen)
    }
    pub fn random_point() -> Self {
        let mut gen = blst_p2::default();
        let gen_affine = unsafe { blst_p2_affine_generator() };
        unsafe { blst_p2_from_affine(&mut gen, gen_affine) };
        let point = Bls12381G2Point(gen);

        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        let scalar = Bls12381Scalar(random_bytes);

        &scalar * &point
    }
}

impl Bls12381GTPoint {
    pub fn to_compressed(&self) -> [u8; 576] {
        self.0.to_bendian()
    }
    pub fn from_compressed(&bytes: &[u8; 576]) -> Option<Self> {
        Some(Bls12381GTPoint(read_fp_blst(&bytes)))
    }
}
impl Neg for Bls12381G1Point {
    type Output = Bls12381G1Point;

    fn neg(mut self) -> Bls12381G1Point {
        // Missing for affine in blst
        unsafe {
            blst_p1_cneg(&mut self.0, false);
        }
        self
    }
}

impl Neg for Bls12381G2Point {
    type Output = Bls12381G2Point;

    fn neg(mut self) -> Bls12381G2Point {
        // Missing for affine in blst
        unsafe {
            blst_p2_cneg(&mut self.0, false);
        }
        self
    }
}
impl Neg for Bls12381GTPoint {
    type Output = Bls12381GTPoint;

    #[inline]
    fn neg(mut self) -> Bls12381GTPoint {
        unsafe {
            blst_fp2_cneg(&mut self.0.fp6[0].fp2[0], &self.0.fp6[0].fp2[0], false);
            blst_fp2_cneg(&mut self.0.fp6[0].fp2[1], &self.0.fp6[0].fp2[1], false);
            blst_fp2_cneg(&mut self.0.fp6[0].fp2[2], &self.0.fp6[0].fp2[2], false);
            blst_fp2_cneg(&mut self.0.fp6[1].fp2[0], &self.0.fp6[1].fp2[0], false);
            blst_fp2_cneg(&mut self.0.fp6[1].fp2[1], &self.0.fp6[1].fp2[1], false);
            blst_fp2_cneg(&mut self.0.fp6[1].fp2[2], &self.0.fp6[1].fp2[2], false);
        }
        self
    }
}

impl Add<&Bls12381G1Point> for &Bls12381G1Point {
    type Output = Bls12381G1Point;
    fn add(self, v: &Bls12381G1Point) -> Bls12381G1Point {
        let mut out_add = blst_p1::default();

        unsafe { blst_p1_add(&mut out_add, &self.0, &v.0) };
        Bls12381G1Point(out_add)
    }
}

impl Add<&Bls12381G2Point> for &Bls12381G2Point {
    type Output = Bls12381G2Point;
    fn add(self, v: &Bls12381G2Point) -> Bls12381G2Point {
        let mut out_add = blst_p2::default();

        unsafe { blst_p2_add(&mut out_add, &self.0, &v.0) };
        Bls12381G2Point(out_add)
    }
}

impl Sub<&Bls12381G1Point> for &Bls12381G1Point {
    type Output = Bls12381G1Point;
    fn sub(self, v: &Bls12381G1Point) -> Bls12381G1Point {
        let mut out_sub = blst_p1::default();
        let v_neg = -(*v);

        unsafe { blst_p1_add(&mut out_sub, &self.0, &v_neg.0) };
        Bls12381G1Point(out_sub)
    }
}

impl Sub<&Bls12381G2Point> for &Bls12381G2Point {
    type Output = Bls12381G2Point;
    fn sub(self, v: &Bls12381G2Point) -> Bls12381G2Point {
        let mut out_sub = blst_p2::default();
        let v_neg = -(*v);

        unsafe { blst_p2_add(&mut out_sub, &self.0, &v_neg.0) };
        Bls12381G2Point(out_sub)
    }
}

impl Mul<&Bls12381G1Point> for &Bls12381Scalar {
    type Output = Bls12381G1Point;

    fn mul(self, v: &Bls12381G1Point) -> Bls12381G1Point {
        let mut out_mul = blst_p1::default();
        unsafe { blst_p1_mult(&mut out_mul, &v.0, self.0.as_ptr(), 255usize) };
        Bls12381G1Point(out_mul)
    }
}
impl Mul<&Bls12381Scalar> for &Bls12381G1Point {
    type Output = Bls12381G1Point;

    fn mul(self, v: &Bls12381Scalar) -> Bls12381G1Point {
        let mut out_mul = blst_p1::default();
        unsafe { blst_p1_mult(&mut out_mul, &self.0, v.0.as_ptr(), 255usize) };
        Bls12381G1Point(out_mul)
    }
}

impl Mul<&Bls12381G2Point> for &Bls12381Scalar {
    type Output = Bls12381G2Point;

    fn mul(self, v: &Bls12381G2Point) -> Bls12381G2Point {
        let mut out_mul = blst_p2::default();
        unsafe { blst_p2_mult(&mut out_mul, &v.0, self.0.as_ptr(), 255usize) };
        Bls12381G2Point(out_mul)
    }
}
impl Mul<&Bls12381Scalar> for &Bls12381G2Point {
    type Output = Bls12381G2Point;

    fn mul(self, v: &Bls12381Scalar) -> Bls12381G2Point {
        let mut out_mul = blst_p2::default();
        unsafe { blst_p2_mult(&mut out_mul, &self.0, v.0.as_ptr(), 255usize) };
        Bls12381G2Point(out_mul)
    }
}
}