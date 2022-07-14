/*
use bls12381support::bls12381::*;
use bls12381support::traits::{GroupOperations, Pairing, PointValidation};
use bls12381support::errors::*;
use std::ops::Neg;
*/
use bytemuck::{Pod, Zeroable};
pub use target_arch::*;




#[derive(Debug, Copy, Clone, PartialEq,Pod,Zeroable)]
#[repr(transparent)]
pub struct PodBls12381G1Point(pub [u8; 48]);
#[derive(Debug, Copy, Clone, PartialEq,Pod,Zeroable)]
#[repr(transparent)]
pub struct PodBls12381G2Point(pub [u8; 96]);

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PodBls12381GTPoint(pub [u8; 576]);



#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {
        super::*,
        std::ops::Neg,
        crate::curve25519::{
            curve_syscall_traits::{GroupOperations, Pairing, PointValidation},
            errors::*,
            bls12381lib::*,
            bls12381lib::Bls12381Scalar,
        },
        blst::*,
    };

    pub fn validate_bls12381(point: &PodBls12381G1Point) -> bool {
        point.validate_point()
    }

    pub fn add_bls12381(
        left_point: &PodBls12381G1Point,
        right_point: &PodBls12381G1Point,
    ) -> Option<PodBls12381G1Point> {
        PodBls12381G1Point::add(left_point, right_point)
    }

    pub fn subtract_bls12381(
        left_point: &PodBls12381G1Point,
        right_point: &PodBls12381G1Point,
    ) -> Option<PodBls12381G1Point> {
        PodBls12381G1Point::subtract(left_point, right_point)
    }

    pub fn multiply_bls12381(
        scalar: &Bls12381Scalar,
        point: &PodBls12381G1Point,
    ) -> Option<PodBls12381G1Point> {
        PodBls12381G1Point::multiply(scalar, point)
    }
    impl From<&Bls12381G1Point> for PodBls12381G1Point {
        fn from(point: &Bls12381G1Point) -> Self {
            Self(point.to_compressed())
        }
    }
    impl TryFrom<&PodBls12381G1Point> for Bls12381G1Point {
        type Error = BLS12381Error;

        fn try_from(pod: &PodBls12381G1Point) -> Result<Self, Self::Error> {
            Bls12381G1Point::from_compressed(&pod.0).ok_or(BLS12381Error::PodConversion)
        }
    }

    impl From<&Bls12381G2Point> for PodBls12381G2Point {
        fn from(point: &Bls12381G2Point) -> Self {
            Self(point.to_compressed())
        }
    }
    impl TryFrom<&PodBls12381G2Point> for Bls12381G2Point {
        type Error = BLS12381Error;

        fn try_from(pod: &PodBls12381G2Point) -> Result<Self, Self::Error> {
            Bls12381G2Point::from_compressed(&pod.0).ok_or(BLS12381Error::PodConversion)
        }
    }

    impl From<&Bls12381GTPoint> for PodBls12381GTPoint {
        fn from(point: &Bls12381GTPoint) -> Self {
            Self(point.to_compressed())
        }
    }
    impl TryFrom<&PodBls12381GTPoint> for Bls12381GTPoint {
        type Error = BLS12381Error;

        fn try_from(pod: &PodBls12381GTPoint) -> Result<Self, Self::Error> {
            Bls12381GTPoint::from_compressed(&pod.0).ok_or(BLS12381Error::PodConversion)
        }
    }
    impl Neg for PodBls12381G1Point {
        type Output = Option<Self>;

        fn neg(self) -> Option<Self> {
            let point: Bls12381G1Point = (&self).try_into().ok()?;
            let point_neg = -point;
            Some((&point_neg).into())
        }
    }
    impl Neg for PodBls12381G2Point {
        type Output = Option<Self>;

        fn neg(self) -> Option<Self> {
            let point: Bls12381G2Point = (&self).try_into().ok()?;
            let point_neg = -point;
            Some((&point_neg).into())
        }
    }
    impl Neg for PodBls12381GTPoint {
        type Output = Option<Self>;

        fn neg(self) -> Option<Self> {
            let point: Bls12381GTPoint = (&self).try_into().ok()?;
            let point_neg = -point;
            Some((&point_neg).into())
        }
    }
    impl PointValidation for PodBls12381G1Point {
        type Point = Self;

        fn validate_point(&self) -> bool {
            let point: Bls12381G1Point = self.try_into().unwrap();
            unsafe { blst_p1_on_curve(&point.0) }
        }
    }
    impl GroupOperations for PodBls12381G1Point {
        type Scalar = Bls12381Scalar;
        type Point = Self;

        fn add(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: Bls12381G1Point = left_point.try_into().ok()?;
            let right_point: Bls12381G1Point = right_point.try_into().ok()?;

            let result = &left_point + &right_point;
            Some((&result).into())
        }

        fn subtract(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: Bls12381G1Point = left_point.try_into().ok()?;
            let right_point: Bls12381G1Point = right_point.try_into().ok()?;

            let result = &left_point - &right_point;
            Some((&result).into())
        }

        fn multiply(scalar: &Bls12381Scalar, point: &PodBls12381G1Point) -> Option<Self> {
            let point: Bls12381G1Point = point.try_into().ok()?;

            let result = scalar * &point;
            Some((&result).into())
        }
    }
    impl Pairing for PodBls12381GTPoint {
        type G1Point = PodBls12381G1Point;
        type G2Point = PodBls12381G2Point;
        type GTPoint = Self;
        fn pairing_map(pairing_vec: &[(Self::G1Point, Self::G2Point)]) -> Option<PodBls12381GTPoint> {
            let dst = [0u8; 3];
            let mut pairing_blst = blst::Pairing::new(true, &dst);
            for (g1, g2) in pairing_vec {
                let left_point: Bls12381G2Point = g2.try_into().ok()?;
                let right_point: Bls12381G1Point = g1.try_into().ok()?;

                pairing_blst.raw_aggregate(&left_point.to_affine(), &right_point.to_affine());
            }
            pairing_blst.commit();
            let result = Bls12381GTPoint(pairing_blst.as_fp12().final_exp());
            
            Some((&result).into())
        }
    }
}

#[cfg(target_os = "solana")]
mod target_arch {
    use {
        super::*,
        crate::curve25519::{
            bls12381lib::*,
            curve_syscall_traits::{ADD,MUL, SUB,CURVEBLS12381},}

    };

    pub fn validate_bls12381(point: &PodBls12381G1Point) -> bool {
        let mut validate_result = 0u8;
        let result = unsafe {
            solana_program::syscalls::sol_curve_validate_point(
                CURVEBLS12381,
                &point.0 as *const u8,
                &mut validate_result,
            )
        };
        result == 0
    }

    pub fn add_bls12381(
        left_point: &PodBls12381G1Point,
        right_point: &PodBls12381G1Point,
    ) -> Option<PodBls12381G1Point> {
        let mut result_point = PodBls12381G1Point::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_group_op(
                CURVEBLS12381,
                ADD,
                &left_point.0 as *const u8,
                &right_point.0 as *const u8,
                &mut result_point.0 as *mut u8,
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }

    pub fn subtract_bls12381(
        left_point: &PodBls12381G1Point,
        right_point: &PodBls12381G1Point,
    ) -> Option<PodBls12381G1Point> {
        let mut result_point = PodBls12381G1Point::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_group_op(
                CURVEBLS12381,
                SUB,
                &left_point.0 as *const u8,
                &right_point.0 as *const u8,
                &mut result_point.0 as *mut u8,
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }

    pub fn multiply_bls12381(
        scalar: &Bls12381Scalar,
        point: &PodBls12381G1Point,
    ) -> Option<PodBls12381G1Point> {
        let mut result_point = PodBls12381G1Point::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_group_op(
                CURVEBLS12381,
                MUL,
                &scalar.0 as *const u8,
                &point.0 as *const u8,
                &mut result_point.0 as *mut u8,
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }
}
#[cfg(test)]
mod tests {
    use {super::*, 
        rand::Rng,
        crate::curve25519::{
            curve_syscall_traits::{GroupOperations, Pairing, PointValidation,CURVEBLS12381},
            errors::*,
            bls12381lib::*,
            bls12381::*,

        },
        blst::*,

    };

    #[test]
    fn test_validate_bls12381() {
        let pod = PodBls12381G1Point([
            178, 32, 230, 171, 124, 17, 181, 87, 224, 40, 117, 148, 219, 170, 36, 126, 91, 2, 212,
            199, 126, 223, 232, 59, 64, 70, 12, 82, 14, 143, 227, 150, 235, 159, 97, 59, 8, 215,
            231, 41, 143, 62, 209, 89, 206, 183, 216, 205,
        ]);

        assert!(pod.validate_point());

        let invalid_bytes = PodBls12381G1Point([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 199, 15, 204, 88, 160, 204, 186,
            218, 193, 138, 187, 64, 38, 116, 190, 158, 221, 176, 137, 107, 98, 131, 121, 162, 139,
            52, 252, 232, 169, 181,
        ]);

        assert!(!invalid_bytes.validate_point());
    }
    #[test]
    fn test_bls12381_add_subtract() {
        //Identity
        let identity: PodBls12381G1Point = (&Bls12381G1Point::identity()).try_into().unwrap();

        let point = PodBls12381G1Point([
            178, 32, 230, 171, 124, 17, 181, 87, 224, 40, 117, 148, 219, 170, 36, 126, 91, 2, 212,
            199, 126, 223, 232, 59, 64, 70, 12, 82, 14, 143, 227, 150, 235, 159, 97, 59, 8, 215,
            231, 41, 143, 62, 209, 89, 206, 183, 216, 205,
        ]);

        assert_eq!(add_bls12381(&point, &identity).unwrap(), point);
        assert_eq!(subtract_bls12381(&point, &identity).unwrap(), point);
        println!("add:{:?}",add_bls12381(&point, &identity).unwrap());

        //Associativity
        let point_a = PodBls12381G1Point([
            164, 48, 56, 2, 220, 9, 101, 127, 139, 111, 81, 167, 53, 185, 177, 166, 162, 30, 111,
            80, 116, 5, 115, 0, 223, 8, 0, 177, 208, 118, 232, 198, 83, 117, 73, 229, 206, 27, 122,
            254, 24, 192, 28, 56, 25, 234, 204, 95,
        ]);
        let point_b = PodBls12381G1Point([
            145, 13, 140, 214, 63, 166, 31, 172, 216, 154, 83, 115, 209, 24, 14, 125, 213, 17, 129,
            25, 178, 1, 138, 159, 239, 149, 140, 240, 18, 48, 8, 222, 137, 235, 24, 210, 255, 241,
            241, 199, 207, 201, 135, 171, 190, 15, 74, 238,
        ]);
        let point_c = PodBls12381G1Point([
            166, 91, 27, 36, 154, 178, 34, 74, 164, 131, 177, 229, 62, 254, 199, 51, 152, 118, 190,
            242, 115, 200, 187, 159, 216, 105, 216, 45, 245, 180, 132, 130, 241, 19, 231, 83, 105,
            196, 102, 20, 228, 134, 251, 168, 165, 101, 191, 224,
        ]);

        assert_eq!(
            add_bls12381(&add_bls12381(&point_a, &point_b).unwrap(), &point_c),
            add_bls12381(&point_a, &add_bls12381(&point_b, &point_c).unwrap()),
        );

        assert_eq!(
            subtract_bls12381(&subtract_bls12381(&point_a, &point_b).unwrap(), &point_c),
            subtract_bls12381(&point_a, &add_bls12381(&point_b, &point_c).unwrap()),
        );

        // commutativity
        assert_eq!(
            add_bls12381(&point_a, &point_b).unwrap(),
            add_bls12381(&point_b, &point_a).unwrap(),
        );
        //substraction
        let point: PodBls12381G1Point = (&Bls12381G1Point::generator()).try_into().unwrap();
        let point_negated: PodBls12381G1Point =
            (&-(Bls12381G1Point::generator())).try_into().unwrap();
        assert_eq!(point_negated, subtract_bls12381(&identity, &point).unwrap());
    }
    #[test]
    fn test_bls12381_add_subtract_iter() {
        //Identity
        let identity: PodBls12381G1Point = (&Bls12381G1Point::identity()).try_into().unwrap();

        for _ in 0..1000 {
            let point: PodBls12381G1Point = (&Bls12381G1Point::random_point()).try_into().unwrap();

            assert_eq!(add_bls12381(&point, &identity).unwrap(), point);
            assert_eq!(subtract_bls12381(&point, &identity).unwrap(), point);

            //Associativity
            let point_a: PodBls12381G1Point =
                (&Bls12381G1Point::random_point()).try_into().unwrap();
            let point_b: PodBls12381G1Point =
                (&Bls12381G1Point::random_point()).try_into().unwrap();
            let point_c: PodBls12381G1Point =
                (&Bls12381G1Point::random_point()).try_into().unwrap();

            assert_eq!(
                add_bls12381(&add_bls12381(&point_a, &point_b).unwrap(), &point_c),
                add_bls12381(&point_a, &add_bls12381(&point_b, &point_c).unwrap()),
            );

            assert_eq!(
                subtract_bls12381(&subtract_bls12381(&point_a, &point_b).unwrap(), &point_c),
                subtract_bls12381(&point_a, &add_bls12381(&point_b, &point_c).unwrap()),
            );

            // commutativity
            assert_eq!(
                add_bls12381(&point_a, &point_b).unwrap(),
                add_bls12381(&point_b, &point_a).unwrap(),
            );
            //substraction
            let point: PodBls12381G1Point = (&Bls12381G1Point::random_point()).try_into().unwrap();
            let point_negated: PodBls12381G1Point = (&-(point.clone())).clone().unwrap();
            assert_eq!(point_negated, subtract_bls12381(&identity, &point).unwrap());
        }
    }
    #[test]
    fn test_bls12381_mul() {
        let scalar_a = Bls12381Scalar([
            195, 203, 68, 90, 223, 109, 162, 61, 15, 21, 31, 234, 232, 4, 247, 40, 68, 44, 26, 240,
            165, 166, 40, 63, 201, 94, 249, 39, 103, 172, 126, 34,
        ]);
        let point_x = PodBls12381G1Point([
            183, 206, 137, 76, 44, 34, 178, 189, 201, 165, 89, 60, 17, 77, 117, 136, 85, 138, 32,
            233, 240, 131, 84, 196, 1, 126, 227, 224, 231, 236, 33, 11, 233, 55, 104, 214, 73, 149,
            229, 98, 126, 66, 212, 162, 183, 43, 115, 102,
        ]);

        let point_y = PodBls12381G1Point([
            161, 120, 188, 175, 196, 48, 174, 238, 151, 88, 236, 60, 188, 162, 132, 21, 10, 254,
            219, 128, 163, 232, 223, 202, 223, 43, 191, 64, 23, 99, 40, 219, 244, 243, 50, 223,
            199, 52, 84, 158, 227, 120, 56, 107, 107, 129, 37, 210,
        ]);

        let ax = multiply_bls12381(&scalar_a, &point_x).unwrap();
        let bx = multiply_bls12381(&scalar_a, &point_y).unwrap();

        assert_eq!(
            add_bls12381(&ax, &bx),
            multiply_bls12381(&scalar_a, &add_bls12381(&point_x, &point_y).unwrap()),
        );
    }

    #[test]
    fn test_bls12381_mul_iter() {
        for _ in 0..1000 {
            let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
            let scalar_a = Bls12381Scalar(random_bytes);

            let point_x: PodBls12381G1Point =
                (&Bls12381G1Point::random_point()).try_into().unwrap();

            let point_y: PodBls12381G1Point =
                (&Bls12381G1Point::random_point()).try_into().unwrap();

            let ax = multiply_bls12381(&scalar_a, &point_x).unwrap();
            let bx = multiply_bls12381(&scalar_a, &point_y).unwrap();

            assert_eq!(
                add_bls12381(&ax, &bx),
                multiply_bls12381(&scalar_a, &add_bls12381(&point_x, &point_y).unwrap()),
            );
        }
    }
    #[test]
    fn test_bls12381_pairing() {
        let point_a_g1 = PodBls12381G1Point([
            166, 49, 33, 40, 240, 188, 20, 150, 58, 114, 27, 230, 39, 186, 111, 67, 78, 59, 39, 40,
            159, 78, 55, 64, 197, 195, 219, 251, 30, 22, 32, 207, 241, 83, 191, 75, 196, 51, 135,
            20, 54, 34, 156, 182, 164, 244, 253, 3,
        ]);
        let point_b_g1 = PodBls12381G1Point([
            143, 242, 220, 139, 133, 230, 13, 10, 129, 177, 153, 12, 224, 186, 207, 34, 55, 115,
            74, 147, 108, 27, 115, 142, 80, 228, 32, 72, 70, 91, 107, 159, 170, 171, 25, 239, 199,
            30, 130, 1, 37, 17, 17, 145, 66, 25, 240, 243,
        ]);
        let point_c_g1 = PodBls12381G1Point([
            131, 141, 28, 118, 120, 216, 218, 179, 194, 92, 27, 85, 39, 14, 15, 6, 87, 132, 203,
            100, 182, 179, 134, 1, 254, 1, 184, 238, 209, 28, 15, 67, 246, 227, 37, 105, 85, 175,
            168, 233, 73, 185, 65, 25, 14, 194, 110, 117,
        ]);

        let point_a_g2 = PodBls12381G2Point([
            139, 175, 59, 181, 119, 128, 235, 5, 111, 215, 60, 177, 132, 243, 250, 87, 81, 226,
            124, 6, 182, 15, 125, 226, 208, 235, 239, 209, 130, 27, 149, 81, 197, 173, 127, 53,
            126, 48, 79, 140, 143, 70, 33, 188, 163, 212, 149, 248, 2, 116, 246, 168, 68, 124, 13,
            104, 241, 210, 73, 146, 95, 231, 207, 30, 10, 145, 22, 90, 108, 105, 253, 125, 216,
            148, 30, 12, 207, 179, 234, 53, 166, 101, 247, 11, 64, 139, 242, 166, 231, 164, 227,
            249, 4, 166, 90, 254,
        ]);
        let point_b_g2 = PodBls12381G2Point([
            129, 154, 209, 246, 163, 42, 199, 144, 71, 153, 175, 174, 192, 205, 162, 157, 233, 76,
            61, 224, 68, 9, 246, 87, 32, 79, 197, 111, 2, 127, 92, 128, 170, 60, 34, 227, 31, 166,
            41, 207, 131, 205, 36, 130, 99, 191, 83, 45, 20, 229, 79, 200, 2, 205, 209, 67, 68,
            226, 48, 230, 222, 51, 41, 31, 192, 14, 176, 227, 13, 61, 122, 125, 62, 198, 154, 130,
            236, 46, 14, 203, 201, 253, 235, 195, 237, 50, 105, 23, 181, 42, 126, 2, 239, 135, 101,
            77,
        ]);
        let point_c_g2 = PodBls12381G2Point([
            176, 248, 226, 178, 206, 137, 7, 181, 151, 204, 251, 129, 167, 214, 167, 118, 173, 18,
            87, 141, 29, 76, 65, 29, 224, 75, 132, 109, 20, 71, 230, 110, 109, 240, 6, 236, 128,
            154, 231, 166, 108, 121, 225, 130, 220, 212, 190, 189, 3, 202, 126, 13, 101, 31, 103,
            75, 43, 24, 120, 19, 72, 236, 77, 82, 191, 98, 212, 111, 65, 228, 130, 223, 244, 173,
            152, 114, 121, 176, 192, 2, 162, 136, 29, 8, 62, 158, 165, 174, 202, 25, 171, 56, 30,
            88, 29, 239,
        ]);

        let vec_pairing = vec![
            (point_a_g1, point_a_g2),
            (point_b_g1, point_b_g2),
            (point_c_g1, point_c_g2),
        ];
        let result = PodBls12381GTPoint([
            22, 51, 239, 123, 211, 207, 203, 104, 63, 25, 120, 245, 26, 70, 19, 139, 2, 104, 24,
            229, 116, 7, 1, 9, 65, 239, 44, 246, 202, 113, 177, 13, 116, 4, 0, 10, 105, 154, 129,
            146, 157, 165, 124, 171, 201, 40, 252, 76, 1, 254, 168, 135, 60, 209, 225, 60, 198,
            231, 76, 70, 174, 177, 105, 13, 41, 155, 174, 144, 248, 190, 47, 135, 36, 95, 80, 6,
            137, 68, 144, 247, 116, 169, 50, 137, 108, 183, 221, 147, 244, 30, 63, 51, 227, 240,
            84, 54, 12, 56, 213, 17, 191, 178, 3, 218, 140, 193, 92, 88, 22, 182, 217, 22, 157, 5,
            209, 212, 143, 223, 186, 248, 200, 219, 1, 228, 210, 79, 116, 97, 173, 25, 189, 2, 111,
            138, 189, 115, 31, 90, 42, 53, 202, 229, 146, 50, 6, 252, 0, 232, 183, 23, 44, 209, 90,
            114, 174, 208, 127, 30, 183, 56, 62, 54, 171, 135, 199, 181, 228, 174, 67, 227, 167,
            224, 130, 122, 199, 185, 65, 227, 92, 67, 180, 220, 211, 164, 38, 99, 126, 79, 48, 91,
            54, 235, 0, 159, 175, 71, 237, 47, 51, 220, 81, 142, 212, 208, 190, 90, 205, 215, 160,
            255, 1, 154, 32, 57, 195, 12, 53, 22, 175, 108, 114, 2, 31, 1, 70, 246, 84, 173, 107,
            186, 153, 4, 99, 155, 179, 161, 109, 198, 53, 45, 4, 234, 217, 57, 132, 181, 163, 200,
            137, 78, 20, 87, 152, 154, 65, 152, 160, 131, 20, 57, 30, 204, 138, 118, 50, 143, 11,
            40, 118, 245, 206, 251, 87, 20, 3, 73, 177, 178, 94, 249, 205, 182, 157, 109, 69, 66,
            37, 115, 14, 178, 80, 104, 179, 230, 221, 206, 145, 255, 231, 1, 156, 89, 117, 147,
            221, 15, 36, 31, 235, 126, 123, 200, 137, 114, 131, 221, 199, 28, 220, 90, 181, 219,
            204, 80, 221, 67, 212, 217, 161, 58, 158, 125, 95, 10, 24, 179, 9, 160, 203, 16, 177,
            250, 95, 104, 184, 137, 116, 76, 110, 85, 77, 216, 240, 192, 32, 200, 35, 242, 236,
            118, 203, 177, 117, 106, 68, 197, 253, 196, 214, 170, 236, 128, 252, 254, 79, 128, 194,
            239, 25, 113, 4, 234, 8, 79, 4, 106, 115, 106, 83, 101, 220, 51, 206, 165, 79, 202,
            206, 41, 190, 135, 19, 3, 97, 211, 35, 123, 46, 109, 171, 122, 79, 146, 231, 21, 249,
            209, 250, 120, 25, 44, 102, 100, 230, 57, 10, 179, 171, 31, 100, 195, 83, 237, 22, 16,
            126, 75, 15, 246, 74, 23, 95, 78, 25, 169, 1, 220, 217, 200, 105, 119, 106, 198, 251,
            38, 142, 226, 198, 224, 231, 227, 245, 43, 180, 212, 205, 237, 105, 178, 160, 73, 112,
            31, 99, 174, 98, 179, 60, 32, 17, 90, 24, 53, 55, 14, 129, 16, 86, 247, 138, 24, 71,
            99, 10, 231, 229, 74, 171, 40, 254, 176, 67, 126, 148, 98, 121, 190, 88, 81, 8, 217,
            186, 232, 68, 249, 126, 108, 247, 110, 248, 82, 143, 166, 148, 25, 201, 171, 136, 134,
            4, 93, 217, 155, 220, 81, 250, 164, 224, 159, 94, 92, 67, 190, 70, 220, 87, 42, 188,
            159, 156, 255, 0, 200, 151, 190, 238, 183, 232, 236, 139, 100, 233, 153, 18, 208, 100,
            187, 184, 8, 239, 54, 211, 142, 99, 231, 49, 79,
        ]);
        let pairing_out = PodBls12381GTPoint::pairing_map(&vec_pairing).unwrap();
        //println!("pairing_out:{:?}",pairing_out);
        assert_eq!(pairing_out, result);
    }
    #[test]
    fn test_bls12381_pairing_iter() {
        for _ in 1..1000 {
            let point_x: PodBls12381G1Point =
                (&Bls12381G1Point::random_point()).try_into().unwrap();

            let point_y: PodBls12381G2Point =
                (&Bls12381G2Point::random_point()).try_into().unwrap();

            let point_x_neg = (-point_x).unwrap();

            let point_y_neg = (-point_y).unwrap();

            let vec_pairing = vec![(point_x, point_y)];
            let vec_pairing_y_neg = vec![(point_x, point_y_neg)];
            let vec_pairing_x_neg = vec![(point_x_neg, point_y)];

            let p = (-PodBls12381GTPoint::pairing_map(&vec_pairing).unwrap()).unwrap();
            let q = PodBls12381GTPoint::pairing_map(&vec_pairing_y_neg).unwrap();
            let r = PodBls12381GTPoint::pairing_map(&vec_pairing_x_neg).unwrap();


            assert_eq!(p, q);
            assert_eq!(q, r);
        }
    }
}